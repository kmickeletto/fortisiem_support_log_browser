import tkinter as tk
from tkinter import ttk
import os
import time
import threading
import queue
import paramiko
from scp import SCPClient
import textwrap
import re
import shutil
import hashlib

class SSHClient(tk.Frame):
    def __init__(self, parent, hostname, username, password=None, key_filename=None, days=1, on_complete=None, theme="dark", logger=None):
        super().__init__(parent)
        self.on_complete = on_complete
        self.parent = parent
        self.hostname = hostname
        self.username = username
        self.password = password
        self.key_filename = os.path.normpath(key_filename) if key_filename else None
        self.days = days
        self.client = None
        self.scp = None
        self.connected = False
        self.command_successful = False
        self.result_queue = queue.Queue()
        self.transfer_rates = []
        self.logger = logger if logger else DummyLogger()
        self.start_time = None
        self.chunk_size_mb = 100
        self.operation_completed = False
        self.temp_dir = None

        self.parent.configure(background='black')
        self.parent.protocol("WM_DELETE_WINDOW", self.on_close)
        self.parent.title("SSH Client")

        self.progress_bar = ttk.Progressbar(self.parent, orient='horizontal', length=400, mode='determinate')
        self.status_label = tk.Label(self.parent, text="", foreground='white', background='black')
        self.eta_label = tk.Label(self.parent, text="", foreground='white', background='black')
        self.output_text = tk.Text(self.parent, height=20, width=80, bg='black', fg='white', insertbackground='white', padx=5, pady=5, state='disabled')
        self.output_text.pack()
        self.output_text.tag_configure('normal', foreground='white')
        self.output_text.tag_configure('info', foreground='cyan')
        self.output_text.tag_configure('warn', foreground='yellow')
        self.output_text.tag_configure('error', foreground='red')

        # Pack but hide progress-related widgets initially
        self.progress_bar.pack(pady=10)
        self.status_label.pack(pady=5)
        self.eta_label.pack(pady=5)

        # Apply the theme
        self.apply_theme(theme)

    def apply_theme(self, theme):
        if theme == "dark":
            self.output_text.config(bg='black', fg='white', insertbackground='white')
            self.status_label.config(fg='white', bg='black')
            self.eta_label.config(fg='white', bg='black')
        else:
            self.output_text.config(bg='white', fg='black', insertbackground='black')
            self.status_label.config(fg='black', bg='white')
            self.eta_label.config(fg='black', bg='white')

    def start_operations(self, command, download_path, result_queue):
        thread = threading.Thread(target=self.execute_ssh_operations, args=(command, download_path, result_queue), daemon=True)
        thread.start()

    def execute_ssh_operations(self, command, download_path, result_queue):
        self.connect()
        if self.connected:
            if not self.is_root_user():
                run_command = f"sudo su -c 'source /opt/phoenix/bin/.bashrc && {command} {self.days}'"
                self.print_text(f"User is not root, escalating privileges to root\n", 'warn')
                self.logger.warning("User is not root, escalating privileges to root")
            else:
                run_command = f"{command} {self.days}"
            self.handle_command(run_command, download_path, result_queue)

    def is_root_user(self):
        stdin, stdout, stderr = self.client.exec_command("id -u")
        user_id = stdout.read().strip()
        return user_id == b'0'

    def connect(self):
        try:
            self.print_text(f"Connecting to {self.hostname}\n", 'info')
            self.logger.info(f"Connecting to {self.hostname}")
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            pkey = None
            if self.key_filename:
                self.logger.info(f"Using key file: {self.key_filename}")
                with open(self.key_filename, 'r') as key_file:
                    key_data = key_file.read()
                    pkey = paramiko.RSAKey.from_private_key_file(self.key_filename)

            self.client.connect(
                self.hostname,
                username=self.username,
                password=self.password,
                pkey=pkey,
                look_for_keys=False,
                compress=True,
                allow_agent=False,
                timeout=10,
                banner_timeout=200
            )

            transport = self.client.get_transport()
            transport.default_window_size = 2147483647
            transport.local_cipher = 'arcfour'

            # Create a new session to read the banner message
            session = transport.open_session()
            session.get_pty()
            session.invoke_shell()

            banner_message = ""
            while True:
                line = session.recv(1024).decode('utf-8')
                if line.endswith("$ ") or line.endswith("# "):  # Typical shell prompt endings
                    break
                banner_message += line
            self.print_text(banner_message + "\n", 'info')
            self.logger.info(banner_message.strip())

            # Close the session after reading the banner message
            session.close()

            self.scp = SCPClient(transport, progress=self.progress)
            self.connected = True
        except Exception as e:
            self.print_text(f"Connection failed: {e}\n", "error")
            self.logger.error(f"Connection failed: {e}")
            self.connected = False

    def handle_command(self, command, download_path, result_queue):
        self.logger.info(f"Executing command: {command}")
        if not self.is_alive():
            return
        try:
            stdin, stdout, stderr = self.client.exec_command(command)
            stdout_output, stderr_output, file_name = self.process_command_output(stdout, stderr)
            if file_name:
                self.create_temp_dir()
                self.split_file(file_name, self.chunk_size_mb)
                remote_file_size, sha256_hash = self.get_remote_file_info(file_name)
                self.logger.info(f"{file_name} detected, size {remote_file_size} bytes")
                self.logger.debug(f"{file_name} hash is {sha256_hash}")
                self.print_text(f"{file_name} detected, size {(remote_file_size / 1024 / 1024):.1f} MB\n", 'info')
                self.download_chunks(file_name, download_path, result_queue, remote_file_size, sha256_hash)
                self.cleanup_remote_files(file_name)
            else:
                self.command_successful = False
                self.logger.error("No file detected")
        except Exception as e:
            self.print_text(f"Failed to execute command: {e}\n", "error")
            self.logger.error(f"Failed to execute command: {e}")
            self.command_successful = False
            self.cleanup_remote_files(file_name)

    def process_command_output(self, stdout, stderr):
        stdout_output = []
        stderr_output = []
        file_name = None
        regex = re.compile(r'^(\/(?:[^\/\s]+\/)*[^\/\s]+\.\S{3})\s+created,')

        while True:
            if not self.is_alive():
                break
            line = stdout.readline()
            if line:
                self.logger.info(line.strip())
                match = regex.search(line)
                if match:
                    file_name = match.group(1)
                    self.logger.info(f"Detected file creation: {file_name}")
                elif line.startswith("Warning:"):
                    continue
                else:
                    self.print_text(line, 'normal')
                    stdout_output.append(line)

            error_line = stderr.readline()
            if error_line:
                if error_line.startswith('find:') or error_line.startswith('gzip:'):
                    self.logger.warning(error_line.strip())
                else:
                    self.logger.error(error_line.strip())
                stderr_output.append(error_line)

            if stdout.channel.exit_status_ready() and not line:
                break

        exit_status = stdout.channel.recv_exit_status()
        if exit_status != 0:
            self.command_successful = False
            self.logger.error(f"Command failed with exit status {exit_status}")
            if stderr_output:
                error_message = ''.join(stderr_output)
                self.print_text(f"Command failed with exit status {exit_status}: {error_message}\n", "error")
                self.logger.error(f"Command failed with exit status {exit_status}: {error_message}")
            else:
                self.print_text(f"Command failed with exit status {exit_status}\n", "error")
                self.logger.error(f"Command failed with exit status {exit_status}")
        else:
            self.command_successful = True

        return stdout_output, stderr_output, file_name

    def create_temp_dir(self):
        self.temp_dir = f"/tmp/temp_split_dir_{int(time.time())}"
        self.logger.info(f"Creating temporary directory: {self.temp_dir}")
        stdin, stdout, stderr = self.client.exec_command(f"mkdir -p {self.temp_dir}")
        stdout.channel.recv_exit_status()
        for line in stderr:
            self.logger.error(line.strip())

    def split_file(self, remote_path, chunk_size):
        temp_file_path = f"{self.temp_dir}/{os.path.basename(remote_path)}"
        split_command = f"split -b {chunk_size}M {remote_path} {temp_file_path}.part"
        self.logger.info(f"Splitting file with command: {split_command}")
        stdin, stdout, stderr = self.client.exec_command(split_command)
        stdout.channel.recv_exit_status()
        for line in stderr:
            self.logger.error(line.strip())

    def get_remote_file_info(self, remote_path):
        file_size_command = f"stat -c%s {remote_path}"
        stdin, stdout, stderr = self.client.exec_command(file_size_command)
        remote_file_size = int(stdout.read().strip())

        sha256_command = f"sha256sum {remote_path} | awk '{{print $1}}'"
        stdin, stdout, stderr = self.client.exec_command(sha256_command)
        sha256_hash = stdout.read().strip().decode()

        return remote_file_size, sha256_hash

    def download_chunks(self, remote_path, local_path, result_queue, remote_file_size, sha256_hash):
        sftp = self.client.open_sftp()
        parts = sftp.listdir(path=self.temp_dir)
        part_files = sorted([file for file in parts if file.startswith(os.path.basename(remote_path) + ".part")])

        num_chunks = len(part_files)
        if num_chunks > 1:
            self.print_text(f"File is split into {num_chunks} chunks\n", 'info')
        self.logger.info(f"File is split into {num_chunks} chunks")

        all_parts_downloaded = True

        for part in part_files:
            remote_part_path = f"{self.temp_dir}/{part}"
            local_part_path = f"{local_path}.{part.split('.')[-1]}"

            success, result = self.download_file_with_retries(remote_part_path, local_part_path, max_retries=3)
            if success:
                self.logger.info(f"Downloaded chunk: {result}")
                self.delete_remote_file(remote_part_path)
            else:
                self.logger.error(f"Failed to download chunk: {result}")
                all_parts_downloaded = False
                break

        if all_parts_downloaded:
            self.merge_files(local_path, part_files)
            local_file_size = os.path.getsize(local_path)
            self.logger.info(f"Local file size: {local_file_size} bytes")
            if local_file_size == remote_file_size:
                local_sha256_hash = self.calculate_sha256(local_path)
                if local_sha256_hash == sha256_hash:
                    self.delete_remote_file(remote_path)
                    self.parent.after(0, lambda: result_queue.put(local_path))
                    if self.on_complete and not self.operation_completed:
                        self.operation_completed = True
                        self.parent.after(0, self.on_complete)
                else:
                    self.print_text("SHA256 hash does not match after download.", 'error')
                    self.logger.error("SHA256 hash does not match after download.")
            else:
                self.print_text("Downloaded file size does not match the remote file size.", 'error')
                self.logger.error("Downloaded file size does not match the remote file size.")
        self.cleanup_remote_files(remote_path)

    def merge_files(self, local_path, part_files):
        self.logger.info("Merging downloaded chunks into the final file.")
        with open(local_path, 'wb') as merged_file:
            for part in part_files:
                local_part_path = f"{local_path}.{part.split('.')[-1]}"
                self.logger.info(f"Merging {local_part_path} into {local_path}")
                try:
                    with open(local_part_path, 'rb') as part_file:
                        shutil.copyfileobj(part_file, merged_file)
                    os.remove(local_part_path)
                    self.logger.info(f"Deleted part file: {local_part_path}")
                except Exception as e:
                    self.print_text(f"Failed to merge or delete part file {local_part_path}: {e}", 'error')
                    self.logger.error(f"Failed to merge or delete part file {local_part_path}: {e}")

    def delete_remote_file(self, remote_path):
        try:
            stdin, stdout, stderr = self.client.exec_command(f"sudo rm -f {remote_path}")
            exit_status = stdout.channel.recv_exit_status()
            if exit_status == 0:
                self.print_text(f"Deleted remote file: {remote_path}\n", 'info')
                self.logger.info(f"Deleted remote file: {remote_path}")
            else:
                error_message = stderr.read().decode()
                self.print_text(f"Failed to delete remote file: {error_message}\n", 'error')
                self.logger.error(f"Failed to delete remote file: {error_message}")
        except Exception as e:
            self.print_text(f"Failed to delete remote file: {e}\n", 'error')
            self.logger.error(f"Failed to delete remote file: {e}")

    def cleanup_remote_files(self, remote_path):
        try:
            self.logger.info(f"Cleaning up remote files in {self.temp_dir}")
            cleanup_command = f"sudo rm -rf {self.temp_dir} {remote_path}"
            stdin, stdout, stderr = self.client.exec_command(cleanup_command)
            exit_status = stdout.channel.recv_exit_status()
            if exit_status == 0:
                self.print_text(f"Cleaned up remote files in {self.temp_dir}\n", 'info')
                self.logger.info(f"Cleaned up remote files in {self.temp_dir}")
            else:
                error_message = stderr.read().decode()
                self.print_text(f"Failed to clean up remote files: {error_message}\n", 'error')
                self.logger.error(f"Failed to clean up remote files: {error_message}")
        except Exception as e:
            self.print_text(f"Failed to clean up remote files: {e}\n", 'error')
            self.logger.error(f"Failed to clean up remote files: {e}")

    def download_file_with_retries(self, remote_path, local_path, max_retries):
        retries = 0
        while retries < max_retries:
            success, result = self.download_file(remote_path, local_path)
            if success:
                return True, result
            retries += 1
            self.logger.warning(f"Retrying download of {remote_path}, attempt {retries}/{max_retries}")
            time.sleep(1)
        return False, remote_path

    def download_file(self, remote_path, local_path):
        self.remote_path = remote_path
        self.start_time = time.time()
        self.logger.info(f"Starting download of {remote_path} to {local_path}")

        try:
            scp_client = SCPClient(self.client.get_transport(), progress=self.progress)
            scp_client.get(remote_path, local_path, preserve_times=False)
            self.logger.info(f"Successfully downloaded {remote_path} to {local_path}")
            return True, local_path
        except Exception as e:
            self.print_text(f"\nFailed to download file {remote_path}: {e}\n", "error")
            self.logger.error(f"Failed to download file {remote_path}: {e}")
            return False, local_path

    def progress(self, filename, size, sent):
        if not self.is_alive():
            return

        current_time = time.time()
        elapsed_time = current_time - self.start_time
        size_mb = size / (1024 * 1024)
        sent_mb = sent / (1024 * 1024)
        progress = (sent_mb / size_mb) * 100 if size_mb > 0 else 0

        transfer_rate = (sent * 8) / (1024 * 1024 * elapsed_time) if elapsed_time > 0 else 0
        eta = ((size - sent) / transfer_rate) / 100000 if transfer_rate > 0 else 0

        eta_str = self.format_eta(eta)

        if int(current_time - self.start_time) % 1 == 0:
            self.parent.after(0, lambda: self.update_progress_bar(progress, size_mb, transfer_rate, eta_str))

    def update_progress_bar(self, progress, size_mb, transfer_rate, eta_str):
        try:
            if not self.progress_bar.winfo_exists():
                return
            self.progress_bar['value'] = progress
            self.status_label['text'] = (f"Downloading: {self.remote_path} - {size_mb:.1f} MB ({int(progress)}% complete) / "
                                         f"{transfer_rate:.2f} Mbps")
            self.eta_label['text'] = f"Time Remaining: {eta_str}"
            self.parent.update_idletasks()
        except tk.TclError:
            pass

    def format_eta(self, eta_seconds):
        eta_seconds = round(eta_seconds)
        hours, remainder = divmod(eta_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        if hours > 0:
            return f"{hours}h {minutes}m {seconds}s"
        elif minutes > 0:
            return f"{minutes}m {seconds}s"
        else:
            return f"{seconds}s"

    def calculate_sha256(self, file_path):
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def is_alive(self):
        try:
            return self.parent.winfo_exists()
        except RuntimeError:
            return False

    def print_text(self, text, tag=None):
        if self.is_alive():
            fixed_width = 80
            wrapped_text = textwrap.fill(text, width=fixed_width)
            self.output_text.config(state='normal')
            self.output_text.insert(tk.END, wrapped_text + '\n', tag)
            self.output_text.config(state='disabled')
            self.output_text.see(tk.END)
            self.output_text.update_idletasks()

    def on_close(self):
        self.close()
        try:
            self.parent.destroy()
        except tk.TclError:
            pass

    def close(self):
        if self.client:
            self.client.close()
        if self.scp:
            self.scp.close()
        self.connected = False

class DummyLogger:
    def __getattr__(self, name):
        return lambda *args, **kwargs: None
