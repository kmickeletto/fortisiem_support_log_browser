import subprocess
import sys

# Packages required for the script, mapping package names to their import names
pip_packages = {
    'ttkthemes': 'ttkthemes',
    'Pillow': 'PIL',
    'paramiko': 'paramiko',
    'scp': 'scp',
    'sv_ttk': 'sv_ttk',
    'pyyaml': 'yaml'
}

standard_modules = [
    'tkinter', 'argparse', 'datetime', 'time', 're', 'glob', 'os',
    'ctypes', 'platform', 'base64', 'io', 'tempfile', 'uuid', 'tarfile',
    'gzip', 'shutil', 'threading', 'winreg', 'queue', 'textwrap', 'fnmatch',
    'itertools', 'collections', 'functools', 'gc', 'json', 'xml.etree.ElementTree', 'xml.dom'
]

# Function to install packages using pip
def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

# Flag to track if any installation happened
installed_any = False

# Check pip-installable packages
for package, import_name in pip_packages.items():
    try:
        __import__(import_name)
    except ImportError:
        install(package)
        installed_any = True

# Check standard library modules
for module in standard_modules:
    try:
        __import__(module)
    except ImportError:
        print(f"Error: {module} is a standard library module and should be available in the Python installation.")
        sys.exit(1)

# Restart the script if any installation happened
if installed_any:
    subprocess.call([sys.executable, *sys.argv])
    sys.exit()

from recursive_extractor import RecursiveExtractor
from log_module import get_logger_instance, DummyLogger
from updater import AutoUpdater
import logging
import tkinter as tk
from tkinter import ttk, messagebox, font, PhotoImage, scrolledtext, filedialog
import tkinter.font as tkFont
from ttkthemes import ThemedTk
# import argparse
from datetime import datetime, timedelta
import time
import re
import glob
import os
from PIL import Image, ImageTk
import ctypes
import platform
import tempfile
import uuid
import sys
import tarfile, zipfile, lzma
import gzip
import shutil
import threading
import paramiko
from scp import SCPClient
import queue
from PyQt6 import QtWidgets, QtCore, QtGui
import textwrap
import yaml
from itertools import cycle, count
from collections import defaultdict
import functools
import gc
import sv_ttk
import fnmatch
import json
import copy
import xml.etree.ElementTree as ET
from xml.dom import minidom

class Spinner(tk.Label):
    def __init__(self, parent, script_dir, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.frames = None
        self.delay = 100
        self.idx = 0
        self.cancel = None
        self.running = False
        self.script_dir = script_dir

    def load(self, im_path, width=None, height=None):
        im_path = os.path.join(self.script_dir, im_path)
        im = Image.open(im_path)
        frames = []

        try:
            for i in count(1):
                frame = im.copy()
                if width and height:
                    frame = frame.resize((width, height), Image.LANCZOS)
                # Set the background color of each frame
                frame = self.set_background_color(frame)
                frames.append(ImageTk.PhotoImage(frame.convert("RGBA")))
                im.seek(i)
        except EOFError:
            pass

        self.frames = cycle(frames)

        try:
            self.delay = im.info['duration']
        except KeyError:
            self.delay = 100

        if len(frames) == 1:
            self.config(image=next(self.frames))
        else:
            self.next_frame()

    def set_background_color(self, frame):
        # Get the parent background color
        parent_bg = self.master.cget("background")
        # Convert the color name to hex value
        rgb_color = self.master.winfo_rgb(parent_bg)
        hex_color = "#{:02x}{:02x}{:02x}".format(rgb_color[0] // 256, rgb_color[1] // 256, rgb_color[2] // 256)

        frame = frame.convert("RGBA")
        data = frame.getdata()
        new_data = []
        for item in data:
            if item[:3] == (0, 0, 0):  # Check for black pixels (assuming spinner's original background is black)
                new_data.append((*tuple(int(hex_color[i:i+2], 16) for i in (1, 3, 5)), item[3]))
            else:
                new_data.append(item)
        frame.putdata(new_data)
        return frame

    def next_frame(self):
        if self.frames and self.running:
            self.config(image=next(self.frames))
            self.cancel = self.after(self.delay, self.next_frame)

    def start(self):
        self.running = True
        if self.frames:
            self.next_frame()
        self.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        self.lift()

    def stop(self):
        self.running = False
        if self.cancel:
            self.after_cancel(self.cancel)
            self.config(image='')
        self.place_forget()

class SSHClient(tk.Frame):
    def __init__(self, parent, hostname, username, password=None, key_filename=None, days=1, on_complete=None, theme="dark"):
        super().__init__(parent)
        self.on_complete = on_complete
        self.parent = parent
        self.hostname = hostname
        self.username = username
        self.password = password
        self.key_filename = key_filename
        self.days = days
        self.client = None
        self.scp = None
        self.connected = False
        self.command_successful = False
        self.result_queue = queue.Queue()
        self.transfer_rates = []
        self.parent.after(1000, self.check_queue)
        self.start_time = None

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

    def check_queue(self):
        try:
            result_path = self.result_queue.get_nowait()
            self.launch_extractor(result_path)
            self.parent.after(1000, self.check_queue)
        except queue.Empty:
            self.parent.after(1000, self.check_queue)
        except Exception as e:
            print(f"Error in check_queue: {e}")
            self.parent.after(1000, self.check_queue)
        
    def start_operations(self, command, download_path, result_queue):
        thread = threading.Thread(target=self.execute_ssh_operations, args=(command, download_path, result_queue), daemon=True)
        thread.start()

    def execute_ssh_operations(self, command, download_path, result_queue):
        self.connect()
        if self.connected:
            if not self.is_root_user():
                run_command = f"sudo su -c 'source /opt/phoenix/bin/.bashrc && {command} {self.days}'"
                self.print_text(f"User is not root, escalating privileges to root\n", 'warn')
            else:
                run_command = f"{command} {self.days}"
            self.extract_and_download(run_command, download_path, result_queue)

    def is_root_user(self):
        stdin, stdout, stderr = self.client.exec_command("id -u")
        user_id = stdout.read().strip()
        return user_id == b'0'

    def connect(self):
        try:
            self.print_text(f"Connecting to {self.hostname}\n", 'info')
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            pkey = None
            if self.key_filename:
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

            # Close the session after reading the banner message
            session.close()

            self.scp = SCPClient(transport, progress=self.progress)
            self.connected = True
        except Exception as e:
            self.print_text(f"Connection failed: {e}\n", "error")
            self.connected = False
            
    def extract_and_download(self, command, download_path, result_queue):
        if not self.is_alive():
            return  # Abort
        try:
            stdin, stdout, stderr = self.client.exec_command(command)
            stdout_output = []
            stderr_output = []
            file_name = None
            regex = re.compile(r'^(\/(?:[^\/\s]+\/)*[^\/\s]+\.\S{3})\s+created,')
    
            while True:
                if not self.is_alive():
                    break
                line = stdout.readline()
                if line:
                    match = regex.search(line)
                    if match:
                        file_name = match.group(1)
                        self.print_text(f"Detected file creation: {file_name}\n", 'info')
                    elif line.startswith("Warning:"):
                        continue  # Skip warning lines
                    else:
                        self.print_text(line, 'normal')
                        stdout_output.append(line)
    
                error_line = stderr.readline()
                # No need for error output
                #if error_line:
                #    self.print_text(error_line, 'error')
                #    stderr_output.append(error_line)
    
                if stdout.channel.exit_status_ready() and not line:
                    break
    
            exit_status = stdout.channel.recv_exit_status()
            if exit_status == 0:
                self.command_successful = True
                if file_name:
                    local_path = self.download_file(file_name, download_path)
                    if local_path:
                        self.delete_remote_file(file_name)
                        self.parent.after(0, lambda: result_queue.put(local_path))
                        if self.on_complete:
                            self.parent.after(0, self.on_complete)
            else:
                self.command_successful = False
                if stderr_output:
                    error_message = ''.join(stderr_output)
                    self.print_text(f"Command failed with exit status {exit_status}: {error_message}\n", "error")
                else:
                    self.print_text(f"Command failed with exit status {exit_status}\n", "error")
        except Exception as e:
            self.print_text(f"Failed to execute command: {e}\n", "error")
            self.command_successful = False
        
    def download_file(self, remote_path, local_path):
        self.remote_path = remote_path
        self.start_time = time.time()
    
        try:
            self.scp.get(remote_path, local_path, preserve_times=False)  # Set preserve_times to False
            return local_path
        except Exception as e:
            self.print_text(f"\nFailed to download file: {e}\n", "error")
            return False

    def delete_remote_file(self, remote_path):
        try:
            # Use sudo to delete the file to handle permission issues
            stdin, stdout, stderr = self.client.exec_command(f"sudo rm -f {remote_path}")
            stdout.channel.recv_exit_status()  # Block until command finishes
            if stdout.channel.recv_exit_status() == 0:
                self.print_text(f"Deleted remote file: {remote_path}\n", 'info')
            else:
                error_message = stderr.read().decode()
                self.print_text(f"Failed to delete remote file: {error_message}\n", 'error')
        except Exception as e:
            self.print_text(f"Failed to delete remote file: {e}\n", 'error')

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
    
        # Limit updates to once per second
        if int(current_time - self.start_time) % 1 == 0:
            self.parent.after(0, lambda: self.update_progress_bar(progress, size_mb, transfer_rate, eta_str))

    def update_progress_bar(self, progress, size_mb, transfer_rate, eta_str):
        try:
            if not self.progress_bar.winfo_exists():
                return
            self.progress_bar['value'] = progress
            self.status_label['text'] = (f"Downloading: {self.remote_path} - {size_mb:.2f} MB ({int(progress)}% complete) / "
                                        f"{transfer_rate:.2f} Mbps")
            self.eta_label['text'] = f"ETA: {eta_str}"
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

    def is_alive(self):
        try:
            return self.parent.winfo_exists()
        except RuntimeError:
            return False

    def print_text(self, text, tag=None):
        if self.is_alive():
            fixed_width = 80
            wrapped_text = textwrap.fill(text, width=fixed_width)
            self.output_text.config(state='normal')  # Enable writing
            self.output_text.insert(tk.END, wrapped_text + '\n', tag)
            self.output_text.config(state='disabled')  # Set back to read-only
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

class SSHCredentialsForm(tk.Frame):
    def __init__(self, parent, callback, initial_credentials=None, theme="light"):
        super().__init__(parent)
        self.parent = parent
        self.callback = callback
        self.theme = theme
        self.parent.geometry('600x250')
        self.parent.title("Enter the host and credentials")
        self.pack(padx=10, pady=10)
        self.apply_theme()
        self.init_ui()
        self.load_initial_credentials(initial_credentials)

    def apply_theme(self):
        sv_ttk.use_dark_theme() if self.theme == "dark" else sv_ttk.use_light_theme()

    def load_initial_credentials(self, initial_credentials):
        self.hostname_entry.insert(0, initial_credentials.get('hostname', ''))
        self.username_entry.insert(0, initial_credentials.get('username', ''))
        if 'keyfile' in initial_credentials and initial_credentials['keyfile']:
            self.key_entry.insert(0, initial_credentials.get('keyfile', ''))
            self.auth_var.set('key')
            self.toggle_auth_method()
        elif 'password' in initial_credentials:
            self.password_entry.insert(0, initial_credentials.get('password', ''))
            self.auth_var.set('password')
            self.toggle_auth_method()
        self.validate_inputs()

    def init_ui(self):
        self.auth_var = tk.StringVar(value='password')

        ttk.Label(self, text="Hostname/IP:").grid(row=0, column=0, sticky="w")
        self.hostname_entry = ttk.Entry(self)
        self.hostname_entry.grid(row=0, column=1, columnspan=4, padx=5)
        self.hostname_entry.focus_set()

        ttk.Label(self, text="Username:").grid(row=1, column=0, sticky="w")
        self.username_entry = ttk.Entry(self)
        self.username_entry.grid(row=1, column=1, columnspan=4, padx=5)

        auth_frame = ttk.LabelFrame(self, text="Authentication Method", padding=5)
        auth_frame.grid(row=0, column=5, padx=50)
        rb1 = ttk.Radiobutton(auth_frame, text="Password", variable=self.auth_var, value='password', command=self.toggle_auth_method)
        rb1.grid(row=0, column=0, sticky="w")
        rb2 = ttk.Radiobutton(auth_frame, text="Private Key", variable=self.auth_var, value='key', command=self.toggle_auth_method)
        rb2.grid(row=1, column=0, sticky="w")

        self.auth_label = ttk.Label(self, text="Password:")
        self.auth_label.grid(row=2, column=0, pady=3, sticky="w")

        self.password_entry = ttk.Entry(self, show="*")
        self.password_entry.grid(row=2, column=1, columnspan=4, pady=3, padx=5)
        self.key_entry = ttk.Entry(self)
        self.key_entry.grid(row=2, column=1, columnspan=4, pady=3)
        self.key_entry.grid_remove()
        self.browse_button = ttk.Button(self, text="Browse", command=self.browse_keyfile)
        self.browse_button.grid(row=2, column=5)
        self.browse_button.grid_remove()

        ttk.Label(self, text="Days:").grid(row=4, column=0, sticky="w")
        self.days_value = tk.StringVar()
        self.days_entry = ttk.Scale(self, from_=1, to=7, orient='horizontal', length=150, command=self.update_days_label)
        self.days_entry.grid(row=4, column=1, pady=10)
        self.days_label = ttk.Label(self, textvariable=self.days_value)
        self.days_label.grid(row=4, column=2, sticky="w", padx=5)
        self.days_value.set("1")

        action_frame = ttk.LabelFrame(self, relief="flat")
        action_frame.grid(row=5, column=5)

        self.submit_button = ttk.Button(action_frame, text="Submit", command=self.submit_credentials, state="disabled")
        self.submit_button.grid(row=0, column=1, padx=5)

        cancel_button = ttk.Button(action_frame, text="Cancel", command=self.cancel)
        cancel_button.grid(row=0, column=0, padx=5)

        for widget in [self.hostname_entry, self.username_entry, self.password_entry, self.submit_button, cancel_button]:
            widget.lift()

        self.parent.bind("<Return>", lambda event: self.submit_credentials())
        self.hostname_entry.bind("<KeyRelease>", self.validate_inputs)
        self.username_entry.bind("<KeyRelease>", self.validate_inputs)
        self.password_entry.bind("<KeyRelease>", self.validate_inputs)
        self.key_entry.bind("<KeyRelease>", self.validate_inputs)

    def update_days_label(self, value):
        self.days_value.set(str(int(float(value))))

    def validate_inputs(self, event=None):
        if self.auth_var.get() == 'password':
            if self.hostname_entry.get().strip() and self.username_entry.get().strip() and self.password_entry.get().strip():
                self.submit_button['state'] = 'normal'
            else:
                self.submit_button['state'] = 'disabled'
        else:
            if self.hostname_entry.get().strip() and self.username_entry.get().strip() and self.key_entry.get().strip():
                self.submit_button['state'] = 'normal'
            else:
                self.submit_button['state'] = 'disabled'

    def toggle_auth_method(self):
        if self.auth_var.get() == 'password':
            self.auth_label.config(text="Password:")
            self.password_entry.grid()
            self.key_entry.grid_remove()
            self.browse_button.grid_remove()
        else:
            self.auth_label.config(text="Private Key:")
            self.password_entry.grid_remove()
            self.key_entry.grid()
            self.browse_button.grid()
        self.validate_inputs()

    def browse_keyfile(self):
        default_dir = os.path.expanduser('~/.ssh')

        if not os.path.isdir(default_dir):
            default_dir = os.getcwd()

        file_types = [("Private Key Files", "*.pem *.key"), ("All Files", "*.*")]
        if os.path.isfile(os.path.join(default_dir, 'id_rsa')) and not any(fname.endswith('.pem') for fname in os.listdir(default_dir)):
            file_types = [("All Files", "*.*")]

        self.parent.attributes('-topmost', 0)
        filename = filedialog.askopenfilename(
            parent=self.parent,
            initialdir=default_dir,
            title="Select Key File",
            filetypes=file_types
        )

        if filename:
            self.key_entry.delete(0, tk.END)
            self.key_entry.insert(0, filename)

        self.parent.focus_force()
        self.validate_inputs()

    def close_form(self):
        if self.parent.winfo_exists():
            self.parent.destroy()

    def submit_credentials(self, event=None):
        hostname = self.hostname_entry.get().strip()
        username = self.username_entry.get().strip()
        days = int(float(self.days_entry.get()))
        if days == 0:
            days = 1
        password = None
        keyfile = None

        if hostname and username:
            if self.auth_var.get() == 'password':
                password = self.password_entry.get().strip()
            else:
                keyfile = self.key_entry.get().strip()

            credentials = {
                'hostname': hostname,
                'username': username,
                'password': password,
                'keyfile': keyfile,
                'days': days
            }

            if self.callback:
                self.callback(credentials)
            self.close_form()

    def cancel(self):
        self.parent.destroy()

class FSMLogsExtractorApp(tk.Toplevel):
    def __init__(self, parent, tarball, remove_parent, theme="light", on_extraction_complete=None):
        super().__init__(parent)
        self.theme = theme
        sv_ttk.set_theme(self.theme)
        self.withdraw()
        self.title("Extracting Logs")
        self.geometry('900x400')

        self.parent = parent
        self.on_extraction_complete = on_extraction_complete
        self.stop_event = threading.Event()

        self.attributes('-topmost', True)
        self.output_text = scrolledtext.ScrolledText(self, width=100, height=15)
        self.output_text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        progress_frame = ttk.Frame(self)
        progress_frame.pack(padx=10, pady=5, fill=tk.X, expand=False)

        self.progress_bar = ttk.Progressbar(progress_frame, orient='horizontal', mode='determinate', length=400)
        self.progress_bar.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.progress_label = ttk.Label(progress_frame, text="0%", width=10)
        self.progress_label.pack(side=tk.RIGHT, padx=5)

        self.protocol("WM_DELETE_WINDOW", self.on_close_extract)

        self.apply_theme(self.theme)

        self.tarball = os.path.normpath(tarball)
        self.remove_parent = remove_parent
        self.extracted_directory = None
        self.thread = threading.Thread(target=self.extract_tarball)
        self.thread.start()

        self.transient(self.parent)
        self.grab_set()
        self.withdraw()
        self.deiconify()

    def apply_theme(self, theme):
        sv_ttk.set_theme(theme)

    def set_initial_window_position(self, window):
        window.update_idletasks()
    
        parent_x = self.parent.winfo_rootx()
        parent_y = self.parent.winfo_rooty()
        parent_width = self.parent.winfo_width()
        parent_height = self.parent.winfo_height()
    
        window_width = window.winfo_width() or window.winfo_reqwidth()
        window_height = window.winfo_height() or window.winfo_reqheight()
    
        x = parent_x + (parent_width // 2) - (window_width // 2)
        y = parent_y + (parent_height // 2) - (window_height // 2)
    
        window.geometry(f'{window_width}x{window_height}+{x}+{y}')

    def prompt_overwrite(self, path):
        self.lower()
        
        overwrite_window = tk.Toplevel(self)
        sv_ttk.set_theme(self.theme)
        overwrite_window.title("Directory exists")
        overwrite_window.geometry("300x150")
        
        overwrite_window.transient(self)
        overwrite_window.grab_set()
        
        message_label = ttk.Label(overwrite_window, text=f"The directory {path} already exists. Do you want to overwrite it?", wraplength=280)
        message_label.pack(padx=20, pady=20)
        
        button_frame = ttk.Frame(overwrite_window)
        button_frame.pack(padx=20, pady=10)
        
        yes_button = ttk.Button(button_frame, text="Yes", command=lambda: self._overwrite_path(path, overwrite_window))
        no_button = ttk.Button(button_frame, text="No", command=overwrite_window.destroy)
        
        yes_button.grid(row=0, column=0, padx=5)
        no_button.grid(row=0, column=1, padx=5)
        
        self.set_initial_window_position(overwrite_window)

    def _overwrite_path(self, path, window):
        shutil.rmtree(path)
        self.extract_tarball()
        window.destroy()

    def update_gui(self, message):
        self.after(0, lambda: self._safe_update_gui(message))

    def update_progress(self, progress):
        self.after(0, lambda: self._safe_update_progress(progress))
        print(progress)

    def _safe_update_gui(self, message):
        self.output_text.insert(tk.END, message + '\n')
        self.output_text.see(tk.END)

    def _safe_update_progress(self, progress):
        if self.progress_bar.winfo_exists():
            self.progress_bar['value'] = progress
            self.progress_label['text'] = f"{int(progress)}%"

    def on_close_extract(self):
        if threading.active_count() > 1:
            response = messagebox.askyesno("Quit", "Extraction is running. Do you really want to quit?", parent=self)
            if response:
                self.stop_event.set()
                self.thread.join(timeout=1)
                self.attributes('-topmost', False)
                self.destroy()
        else:
            self.attributes('-topmost', False)
            self.destroy()

    def extract_tarball(self):
        extractor = RecursiveExtractor(self.update_gui)
        try:
            self.update_gui("Starting extraction...\n")
            self.extracted_directory = extractor.extract_top_level(self.tarball, self.remove_parent)
            if self.extracted_directory:
                self.update_gui(f"Extraction completed. Extracted to: {self.extracted_directory}\n")
                if hasattr(self, 'on_extraction_complete'):
                    self.on_extraction_complete(self.extracted_directory)
            else:
                self.update_gui("Extraction failed.\n")
        except Exception as e:
            self.update_gui(f"Extraction failed: {str(e)}\n")
        finally:
            self.after(100, self.destroy)

class Tooltip:
    def __init__(self, widget, delay=1000):
        self.widget = widget
        self.tipwindow = None
        self.id = None
        self.delay = delay
        self.lifetime = 5000
        self.enabled = True

    def showtip(self, text, x, y, height):
        if not self.enabled or not text or self.tipwindow:
            return
        if self.widget.winfo_toplevel().focus_get() != self.widget:
            return
        self.text = text
        if self.tipwindow or not text:
            return
        # Check if the widget's master window is active
        if self.widget.winfo_toplevel().focus_get() != self.widget:
            return  # Do not schedule if the widget's window is not active
        self.x = x + self.widget.winfo_rootx()
        self.y = y + height + self.widget.winfo_rooty()
        self.schedule()

    def schedule(self):
        self.unschedule()
        self.id = self.widget.after(self.delay, self.display)

    def display(self):
        # Check again in case focus changed during the delay
        if self.tipwindow or self.widget.winfo_toplevel().focus_get() != self.widget:
            return
        self.tipwindow = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry("+%d+%d" % (self.x, self.y))
        label = tk.Label(tw, text=self.text, justify='left',
                         background="lightyellow", relief='solid', borderwidth=1,
                         font=("tahoma", "8", "normal"))
        label.pack(ipadx=1)
        # Auto close after a set time
        self.widget.after(self.lifetime, self.hidetip)

    def unschedule(self):
        if self.id:
            self.widget.after_cancel(self.id)
        self.id = None

    def hidetip(self):
        if self.tipwindow:
            self.tipwindow.destroy()
            self.tipwindow = None

class LogManager:
    def __init__(self, root, config_manager, config):
        self.root = root
        self.config_manager = config_manager
        self.config = config
        self.all_sources = self.config.get("logs", [])
        self.user_sources = [source for source in self.all_sources if source["creation_type"] == "user"]

        self.window = tk.Toplevel(root)
        self.window.title("Source Manager")
        self.window.transient(root)  # Make the window a proper child of the parent window
        self.window.grab_set()  # Ensure all events are sent to this window until it is closed

        self.tree = ttk.Treeview(self.window, columns=("handle", "name", "path", "pattern", "type", "format", "creation_type"), show="headings")
        self.tree.heading("handle", text="")
        self.tree.heading("name", text="Name")
        self.tree.heading("path", text="Path")
        self.tree.heading("pattern", text="Pattern")
        self.tree.heading("type", text="Type")
        self.tree.heading("format", text="Format")
        self.tree.heading("creation_type", text="Creation Type")
        self.tree.column("handle", width=30, anchor="center")
        self.tree.pack(fill=tk.BOTH, expand=True)
        self.tree.bind("<Button-1>", self.on_click)
        self.tree.bind("<B1-Motion>", self.on_drag)
        self.tree.bind("<Double-1>", self.on_double_click)  # Bind double-click to edit

        self.add_button = ttk.Button(self.window, text="Add Source", command=self.add_source)
        self.add_button.pack(side=tk.LEFT, padx=5, pady=5)
        self.save_button = ttk.Button(self.window, text="Save", command=self.save_sources)
        self.save_button.pack(side=tk.RIGHT, padx=5, pady=5)

        self.load_sources()

        self.drag_data = {"item": None, "index": None}

    def load_sources(self):
        self.tree.delete(*self.tree.get_children())
        tab_order = self.config.get("tab_order", [])
        ordered_sources = sorted(self.all_sources, key=lambda x: tab_order.index(x["name"]) if x["name"] in tab_order else len(tab_order))
        for source in ordered_sources:
            self.tree.insert("", tk.END, values=("⠿", source["name"], source["path"], source["pattern"], source["type"], source.get("format", ""), source["creation_type"]))

    def on_click(self, event):
        item = self.tree.identify_row(event.y)
        column = self.tree.identify_column(event.x)
        if item and column == "#1":
            self.drag_data["item"] = item
            self.drag_data["index"] = self.tree.index(item)

    def on_drag(self, event):
        item = self.drag_data["item"]
        if item:
            y = event.y
            above_item = self.tree.identify_row(y - 1)
            below_item = self.tree.identify_row(y + 1)
            if above_item:
                self.tree.move(item, "", self.tree.index(above_item))
            elif below_item:
                self.tree.move(item, "", self.tree.index(below_item))
            self.update_tab_order()

    def update_tab_order(self):
        new_order = [self.tree.item(item, "values")[1] for item in self.tree.get_children()]
        self.config["tab_order"] = new_order

    def on_double_click(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            values = self.tree.item(item, "values")
            source_entry = {
                "name": values[1],
                "path": values[2],
                "pattern": values[3],
                "type": values[4],
                "format": values[5],
                "creation_type": values[6]
            }
            AddEditSourceWindow(self, source_entry, self.config)

    def add_source(self):
        AddEditSourceWindow(self, None, self.config)

    def save_sources(self):
        sources = [source for source in self.all_sources if source["creation_type"] == "system"] + self.user_sources
        self.config["logs"] = sources
        self.config_manager.save_config(self.config)
        self.window.destroy()

class ConfigManager:
    CONFIG_FILE_PATH = os.path.join(os.path.expanduser("~"), ".fortisiem_log_viewer.yaml")
    DEFAULT_CONFIG = {
        "logs": [
            {
                "id": 1,
                "name": "Aggregate Logs",
                "path": "",
                "pattern": "",
                "type": "aggregate",
                "creation_type": "system"
            },
            {
                "id": 2,
                "name": "phoenix_config",
                "path": "configCollection",
                "pattern": "phoenix_config*.txt",
                "type": "config",
                "format": "ini",
                "creation_type": "system"
            },
            {
                "id": 3,
                "name": "server",
                "path": "appsvr",
                "pattern": "server*",
                "type": "log",
                "creation_type": "system"
            },
            {
                "id": 4,
                "name": "clickhouse",
                "path": "system/clickhouse",
                "pattern": "clickhouse*",
                "type": "log",
                "creation_type": "system"
            },
            {
                "id": 5,
                "name": "archiver",
                "path": "backend",
                "pattern": "archiver.log",
                "type": "log",
                "creation_type": "system"
            },
            {
                "id": 6,
                "name": "svnlite",
                "path": "backend",
                "pattern": "svnlite*",
                "type": "log",
                "creation_type": "system"
            },
            {
                "id": 7,
                "name": "postgresql",
                "path": "postgres",
                "pattern": "postgresql*",
                "type": "log",
                "creation_type": "system"
            },
            {
                "id": 8,
                "name": "domain.xml",
                "path": "configCollection",
                "pattern": "domain*.xml",
                "type": "config",
                "format": "xml",
                "creation_type": "system"
            }
        ],
        "tab_order": [
            1,2,3,4,5,6,7,8
        ],
        "theme": "system",
        "ssh_credentials": {
            "hostname": "",
            "username": "",
            "password": "",
            "keyfile": "",
            "days": 1
        },
    }

    @staticmethod
    def load_config():
        try:
            if not os.path.exists(ConfigManager.CONFIG_FILE_PATH):
                ConfigManager.save_config(ConfigManager.DEFAULT_CONFIG)
                return ConfigManager.DEFAULT_CONFIG

            with open(ConfigManager.CONFIG_FILE_PATH, 'r') as config_file:
                saved_config = yaml.safe_load(config_file)

            if saved_config is None:
                saved_config = {}

            # Extract user-defined logs and tab order
            user_logs = saved_config.get("logs", [])
            user_tab_order = saved_config.get("tab_order", None)
            theme = saved_config.get("theme", "system")

            # Add creation_type to user logs if not already present
            for log in user_logs:
                if "creation_type" not in log:
                    log["creation_type"] = "user"

            # Merge user-defined logs with default logs, avoiding duplicates
            merged_logs = ConfigManager.DEFAULT_CONFIG["logs"] + [
                log for log in user_logs if log not in ConfigManager.DEFAULT_CONFIG["logs"]
            ]

            # Use the user-defined tab order if available
            if user_tab_order is None:
                merged_tab_order = ConfigManager.DEFAULT_CONFIG["tab_order"]
            else:
                merged_tab_order = user_tab_order

            ssh_credentials = saved_config.get("ssh_credentials", ConfigManager.DEFAULT_CONFIG["ssh_credentials"])

            merged_config = {
                "logs": merged_logs,
                "tab_order": merged_tab_order,
                "theme": theme,
                "ssh_credentials": ssh_credentials
            }
            return merged_config
        except yaml.YAMLError as e:
            root = tk.Tk()
            root.withdraw()  # Hide the root window
            error_msg = (
                f"Error loading config file: {e}\n"
                f"File: {ConfigManager.CONFIG_FILE_PATH}\n\n"
                f"Please correct the file or delete it for a new file to be generated"
            )
            messagebox.showerror("Error", error_msg)
            sys.exit(1)

    @staticmethod
    def save_config(config):
        try:
            user_logs = [log for log in config["logs"] if log["creation_type"] == "user"]
            user_tab_order = config["tab_order"]

            user_config = {
                "logs": user_logs,
                "tab_order": user_tab_order,
                "theme": config.get("theme", "system")
            }

            if "ssh_credentials" in config:
                user_config["ssh_credentials"] = {
                    "hostname": config["ssh_credentials"]["hostname"],
                    "username": config["ssh_credentials"]["username"]
                }
            if "keyfile" in config["ssh_credentials"]:
                user_config["ssh_credentials"]["keyfile"] = config["ssh_credentials"]["keyfile"]

            # Save the configuration to a YAML file
            with open(ConfigManager.CONFIG_FILE_PATH, 'w') as config_file:
                yaml.dump(user_config, config_file, default_flow_style=False, sort_keys=False)
        except Exception as e:
            print(f"Error saving config file: {e}")

    @staticmethod
    def load_default_config():
        return ConfigManager.DEFAULT_CONFIG

class ThemeManager:
    def __init__(self, app):
        self.app = app

    def apply_theme(self, theme_name):
        if theme_name == "system":
            actual_theme = self.detect_system_theme()
        else:
            actual_theme = theme_name
        sv_ttk.set_theme(actual_theme)
        self.app.initialize_spinner(actual_theme)
        self.app.apply_font_styles()
        self.app.config["theme"] = theme_name
        self.update_theme_menu(theme_name)

    def apply_saved_theme(self):
        saved_theme = self.app.config.get("theme", "system")
        self.apply_theme(saved_theme)

    def update_theme_menu(self, theme_name):
        bullet = "\u2022"
        self.app.theme_menu.entryconfig(0, label=f"{bullet} Light Theme" if theme_name == "light" else "  Light Theme")
        self.app.theme_menu.entryconfig(1, label=f"{bullet} Dark Theme" if theme_name == "dark" else "  Dark Theme")
        self.app.theme_menu.entryconfig(2, label=f"{bullet} Detect System Theme" if theme_name == "system" else "  Detect System Theme")

    def detect_system_theme(self):
        if platform.system() == "Windows":
            import winreg
            try:
                registry = winreg.ConnectRegistry(None, winreg.HKEY_CURRENT_USER)
                key = winreg.OpenKey(registry, r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize")
                value, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
                winreg.CloseKey(key)
                return "light" if value == 1 else "dark"
            except Exception as e:
                print(f"Error detecting Windows theme: {e}")
                return "light"
        elif platform.system() == "Darwin":
            try:
                from subprocess import check_output
                result = check_output(
                    ['defaults', 'read', '-g', 'AppleInterfaceStyle']
                ).strip().decode('utf-8')
                return "dark" if result == "Dark" else "light"
            except Exception as e:
                print(f"Error detecting macOS theme: {e}")
                return "light"
        else:
            return "light"

class SystemInfoManager:
    def __init__(self, app):
        self.app = app

    def update_system_info(self):
        if self.app.logbase:
            system_info_path = os.path.join(self.app.logbase, 'system', 'phshowVersion.txt')
            if os.path.exists(system_info_path):
                self.parse_system_info(system_info_path)
            
            top_path = os.path.join(self.app.logbase, 'system', 'top')
            if os.path.exists(top_path):
                self.parse_top_info(top_path)

            df_path = os.path.join(self.app.logbase, 'system', 'df')
            if os.path.exists(df_path):
                self.parse_df_info(df_path)

    def parse_system_info(self, file_path):
        with open(file_path, 'r', encoding='ISO-8859-1') as file:
            content = file.read()

        ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
        cleaned_content = ansi_escape.sub('', content)

        hostname_pattern = r'Hostname:\s+(\S+)'
        hostname_match = re.search(hostname_pattern, cleaned_content)
        if hostname_match:
            self.app.systeminfo['hostname'] = hostname_match.group(1)

        ip_pattern = re.compile(r'Intf-IP\[ifcfg-\S+\]:\s+(\S+)')
        self.app.networks = ip_pattern.findall(cleaned_content)

        role_pattern = r'FortiSIEM Role:\s+(\S+)'
        role_match = re.search(role_pattern, cleaned_content)
        if role_match:
            self.app.systeminfo['role'] = role_match.group(1)

        version_pattern = r'Binary Version:\s+(\S+)'
        version_match = re.search(version_pattern, cleaned_content)
        if version_match:
            self.app.systeminfo['version'] = version_match.group(1)

        if self.app.systeminfo.get('role') == 'Supervisor':
            config_dir = os.path.join(self.app.logbase, 'configCollection')
            if os.path.exists(config_dir):
                for file_name in os.listdir(config_dir):
                    if file_name.startswith('phoenix_config') and file_name.endswith('.txt'):
                        config_file_path = os.path.join(config_dir, file_name)
                        with open(config_file_path, 'r', encoding='ISO-8859-1') as config_file:
                            for line in config_file:
                                if line.startswith('superfollower='):
                                    superfollower_value = line.split('=')[1].strip().lower()
                                    if superfollower_value == 'true':
                                        self.app.systeminfo['role'] = 'Follower Supervisor'
                                    else:
                                        self.app.systeminfo['role'] = 'Leader Supervisor'
                                    break

        self.update_system_info_header()

    def parse_top_info(self, file_path):
        with open(file_path, 'r', encoding='ISO-8859-1') as file:
            lines = file.readlines()

        header_info = lines[0]
        tasks_info = lines[1]
        cpu_info = lines[2]
        mem_info = lines[3]
        swap_info = lines[4]

        self.app.systeminfo['top'] = {
            'header': header_info.strip(),
            'tasks': tasks_info.strip(),
            'cpu': cpu_info.strip(),
            'mem': mem_info.strip(),
            'swap': swap_info.strip(),
            'processes': []
        }

        for line in lines[7:]:
            if line.strip():
                process_info = line.split()
                if len(process_info) > 10:  # Ensure it's a process line
                    self.app.systeminfo['top']['processes'].append({
                        'pid': process_info[0],
                        'user': process_info[1],
                        'pr': process_info[2],
                        'ni': process_info[3],
                        'virt': process_info[4],
                        'res': process_info[5],
                        'shr': process_info[6],
                        's': process_info[7],
                        'cpu': process_info[8],
                        'mem': process_info[9],
                        'time': process_info[10],
                        'command': ' '.join(process_info[11:])
                    })

    def parse_df_info(self, file_path):
        with open(file_path, 'r', encoding='ISO-8859-1') as file:
            lines = file.readlines()

        self.app.systeminfo['df'] = []
        headers = lines[0].strip().split()
        for line in lines[1:]:
            if line.strip():
                filesystem_info = line.split()
                filesystem_dict = dict(zip(headers, filesystem_info))
                self.app.systeminfo['df'].append(filesystem_dict)

    def update_system_info_header(self):
        # Update the header labels with the extracted system information
        self.app.hostname_value.config(text=f"{self.app.systeminfo.get('hostname', '')}")
        self.app.ip_value.config(text=f"{', '.join(self.app.networks) if self.app.networks else ''}")
        self.app.role_value.config(text=f"{self.app.systeminfo.get('role', '')}")
        self.app.version_value.config(text=f"{self.app.systeminfo.get('version', '')}")

class AddLogWindow:
    def __init__(self, log_manager):
        self.log_manager = log_manager
        self.window = tk.Toplevel(log_manager.window)
        self.window.title("Add Log")

        self.name_label = ttk.Label(self.window, text="Name:")
        self.name_label.grid(row=0, column=0, padx=5, pady=5)
        self.name_entry = ttk.Entry(self.window)
        self.name_entry.grid(row=0, column=1, padx=5, pady=5)

        self.path_label = ttk.Label(self.window, text="Path:")
        self.path_label.grid(row=1, column=0, padx=5, pady=5)
        self.path_entry = ttk.Entry(self.window)
        self.path_entry.grid(row=1, column=1, padx=5, pady=5)

        self.pattern_label = ttk.Label(self.window, text="Pattern:")
        self.pattern_label.grid(row=2, column=0, padx=5, pady=5)
        self.pattern_entry = ttk.Entry(self.window)
        self.pattern_entry.grid(row=2, column=1, padx=5, pady=5)

        self.type_label = ttk.Label(self.window, text="Type:")
        self.type_label.grid(row=3, column=0, padx=5, pady=5)
        self.type_entry = ttk.Entry(self.window)
        self.type_entry.grid(row=3, column=1, padx=5, pady=5)

        self.add_button = ttk.Button(self.window, text="Add", command=self.add_log)
        self.add_button.grid(row=4, column=0, columnspan=2, padx=5, pady=5)

    def add_log(self):
        log = {
            "name": self.name_entry.get(),
            "path": self.path_entry.get(),
            "pattern": self.pattern_entry.get(),
            "type": self.type_entry.get()
        }
        self.log_manager.tree.insert("", tk.END, values=(log["name"], log["path"], log["pattern"], log["type"]))
        self.window.destroy()

class LogParser:
    SEVERITY_ORDER = {
        'DEBUG': 1, 'INFO': 2, 'WARN': 3, 'WARNING': 3,
        'ERROR': 4, 'CRIT': 5, 'CRITICAL': 5, 'SEVERE': 5
    }

    def is_error_or_warning(self, severity, threshold='ERROR'):
        if severity is None:
            return False
        severity = severity.replace('PHL_', '').upper()
        return self.SEVERITY_ORDER.get(severity, 0) >= self.SEVERITY_ORDER.get(threshold, 4)

    def is_error_or_warning(self, line):
        return 'PHL_ERROR' in line or 'PHL_WARNING' in line

    def parse_log(self, line, log_type):
        if log_type == "backend":
            pat = re.compile(r'^(\S+)\s+(\S+)\s+.*?\[([A-Z_]+)\]:\s*\[eventSeverity\]=([A-Z_]+),\[procName\]=(\S+),\[fileName\]=(\S+),\[lineNumber\]=(-?\d+),.*$')
            if not self.is_error_or_warning(line):
                return None
        elif log_type == "appserver":
            pat = re.compile(r'^(\S+\s+\S+)\s+\[.*?\]\s+[A-Z]+\s+(\S+)\s*-\s*\[(\S+)\]:(.*)')
            if not self.is_error_or_warning(line):
                return None
        else:
            raise ValueError("Unsupported log type")
    
        try:
            if log_type == "backend":
                ts, reporter, event, severity, process, file, line_number = pat.findall(line)[0]
                t = datetime.strptime(ts, '%Y-%m-%dT%H:%M:%S.%f%z')
                return t, reporter, event, severity, process, file, line_number
            elif log_type == "appserver":
                match = pat.match(line)
                try:
                    t, file, event, body = match.groups()
                    timestamp = datetime.strptime(t, '%Y-%m-%d %H:%M:%S,%f')
                except (ValueError, AttributeError):
                    return None
                    
                fields = {
                    'phCustId': None,
                    'eventSeverity': None,
                    'phEventCategory': None,
                    'methodName': None,
                    'className': None,
                    'procName': None,
                    'lineNumber': None
                }
                
                field_patterns = {
                    'phCustId': r'\[phCustId\]=(\d+),',
                    'eventSeverity': r'\[eventSeverity\]=([A-Z_]+),',
                    'phEventCategory': r'\[phEventCategory\]=(\d+),',
                    'methodName': r'\[methodName\]=(\S+?),',
                    'className': r'\[className\]=(\S+?),',
                    'procName': r'\[procName\]=(\S+?),',
                    'lineNumber': r'\[lineNumber\]=(-?\d+),'
                }
                
                for field, pattern in field_patterns.items():
                    match = re.search(pattern, body)
                    if match:
                        fields[field] = match.group(1)
                return timestamp, None, event, fields['eventSeverity'], fields['procName'], file, fields['lineNumber']
        except (IndexError, ValueError):
            return None

    def extract_date_range(self, file_path, log_type):
        """Extracts the date range from the log file."""
        date_pattern = re.compile(r'(\d{4}-\d{2}-\d{2})')
        start_date = None
        end_date = None
        with open(file_path, 'r', encoding='ISO-8859-1') as file:
            for line in file:
                date_match = date_pattern.search(line)
                if date_match:
                    date = datetime.strptime(date_match.group(1), '%Y-%m-%d')
                    if not start_date or date < start_date:
                        start_date = date
                    if not end_date or date > end_date:
                        end_date = date
        return start_date, end_date
    
    def parse_timestamp(self, log_entry, log_type):
        try:
            if log_type == "backend":
                timestamp_str = log_entry.split()[0]
                return datetime.strptime(timestamp_str, '%Y-%m-%dT%H:%M:%S.%f%z').date()
            elif log_type == "appserver":
                timestamp_str = log_entry.split()[0] + " " + log_entry.split()[1]
                return datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S,%f').date()
        except ValueError as e:
            print(f"Error parsing timestamp: {str(e)}")
            return None
            
    def filter_logs_by_date(self, file_path, log_type, target_date_str):
        """Filter logs from a file for the specified date."""
        date_pattern = re.compile(r'(\d{4}-\d{2}-\d{2})')
        logs_for_date = []
        
        with open(file_path, 'r', encoding='ISO-8859-1') as file:
            for line in file:
                if log_type == "backend":
                    date_match = date_pattern.search(line)
                elif log_type == "appserver":
                    date_match = date_pattern.search(line)
                
                if date_match and date_match.group(1) == target_date_str:
                    logs_for_date.append(line)
        
        return logs_for_date
    
class LogViewerApp:
    def __init__(self, root, current_version, logger=None):
        sv_ttk.set_theme("light")
        self.repo_name = 'kmickeletto/fortisiem_support_log_browser'
        self.current_commit_sha = current_version
        self.updater = AutoUpdater(self.repo_name, current_version, logger=logger)
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        self.root = root
        self.logger = logger.get_logger(self) if logger else DummyLogger()
        self.logger.info("LogViewerApp initialized")
        self.root.title("FortiSIEM Support Log Viewer")
        self.ssh_objects = []
        self.logbase = None
        self.date_to_logs = {}
        self.systeminfo = {}
        self.networks = []
        self.load_event = threading.Event()
        self.spinner = Spinner(self.root, self.script_dir)
        self.spinner.load(os.path.join(self.script_dir, 'spinner-dark.gif'), 48, 48)
        self.set_app_icon(os.path.join(self.script_dir, 'fortisiem.png'))
        self.root.geometry('1080x750')
        self.root.minsize(800, 600)
        self.config = ConfigManager.load_config()  
        self.theme_manager = ThemeManager(self)
        self.system_info_manager = SystemInfoManager(self)        
        self.initialize_font()
        self.initialize_widgets()
        self.initialize_gui()
        self.initialize_menu()
        self.apply_styles()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.theme_manager.apply_saved_theme()
        self.notebook.bind('<ButtonPress-1>', self.on_tab_drag_start)
        self.notebook.bind('<B1-Motion>', self.on_tab_drag_motion)
        self.notebook.bind('<ButtonRelease-1>', self.on_tab_drag_end)
        self.tab_drag_data = {'start_index': None, 'end_index': None}
        self.config_manager = ConfigManager()

    def log(self, level, message):
        if self.logger:
            if level == 'debug':
                self.logger.debug(message)
            elif level == 'info':
                self.logger.info(message)
            elif level == 'warning':
                self.logger.warning(message)
            elif level == 'error':
                self.logger.error(message)
            elif level == 'critical':
                self.logger.critical(message)
                
    def set_app_icon(self, image_path):
        system = platform.system()

        if system == 'Windows':
            app_id = u'fortinet.fortisiem.log'
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(app_id)
            image = Image.open(image_path)
            image = image.resize((64, 64), Image.Resampling.LANCZOS)
            self.photo = ImageTk.PhotoImage(image)
            self.root.iconphoto(True, self.photo)

        elif system == 'Linux':
            self.root.iconphoto(True, tk.PhotoImage(file=image_path))

        elif system == 'Darwin':  # macOS
            self.root.iconphoto(True, tk.PhotoImage(file=image_path))

    def initialize_font(self):
        self.font_family = "Arial"
        self.standard_font = tkFont.Font(family=self.font_family, size=10)
        self.bold_font = tkFont.Font(family=self.font_family, weight="bold")
        self.header_font = tkFont.Font(family=self.font_family, size=10, weight="bold")

    def initialize_widgets(self):
        self.output_text = tk.Text(self.root, height=20, width=80, padx=5, pady=5, font=self.standard_font)
        self.status_label = tk.Label(self.root, text="", font=self.standard_font)
        self.progress_bar = ttk.Progressbar(self.root, orient='horizontal', length=400, mode='determinate')

    def initialize_gui(self):
        style = ttk.Style()
        style.configure("NoBorder.TLabelframe")
        style.configure("NoBorder.TLabelframe.Label", borderwidth=0)
        style.configure("Custom.Treeview", borderwidth=0, highlightthickness=0)
        style.layout("Custom.Treeview", [('Treeview.treearea', {'sticky': 'nswe'})])

        self.header_frame = ttk.LabelFrame(self.root, text="System Information")
        self.header_frame.pack(fill='x', padx=10, pady=10)

        ttk.Label(self.header_frame, text="Hostname:", style="Header.TLabel").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.hostname_value = ttk.Label(self.header_frame, text="", style="HeaderValue.TLabel")
        self.hostname_value.grid(row=0, column=1, sticky='w', padx=5, pady=5)

        ttk.Label(self.header_frame, text="Role:", style="Header.TLabel").grid(row=1, column=0, sticky='w', padx=5, pady=5)
        self.role_value = ttk.Label(self.header_frame, text="", style="HeaderValue.TLabel")
        self.role_value.grid(row=1, column=1, sticky='w', padx=5, pady=5)

        ttk.Label(self.header_frame, text="IP Addresses:", style="Header.TLabel").grid(row=0, column=2, sticky='w', padx=5, pady=5)
        self.ip_value = ttk.Label(self.header_frame, text="", style="HeaderValue.TLabel")
        self.ip_value.grid(row=0, column=3, sticky='w', padx=5, pady=5)

        ttk.Label(self.header_frame, text="Version:", style="Header.TLabel").grid(row=1, column=2, sticky='w', padx=5, pady=5)
        self.version_value = ttk.Label(self.header_frame, text="", style="HeaderValue.TLabel")
        self.version_value.grid(row=1, column=3, sticky='w', padx=5, pady=5)

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=(0, 10))

        self.tab_logs = ttk.Frame(self.notebook)

        frame_top = ttk.LabelFrame(self.tab_logs, text="Date")
        frame_top.pack(fill='x', padx=10, pady=10)

        self.selected_date = tk.StringVar()
        ttk.Label(frame_top, style="Header.TLabel").pack(side='left', padx=5, pady=5)

        dates = sorted(self.date_to_logs.keys())
        self.dropdown = ttk.Combobox(frame_top, textvariable=self.selected_date, style='Custom.TCombobox', state='readonly', font=(self.standard_font, 11), values=dates)
        self.dropdown.pack(side='left', fill='x', expand=True, padx=5, pady=(0, 5))
        self.dropdown.bind("<<ComboboxSelected>>", self.load_logs)
        if dates:
            self.latest_date = dates[-1]
            self.dropdown.set(self.latest_date)

        frame_backend = ttk.LabelFrame(self.tab_logs, text="Backend Logs")
        frame_backend.pack(fill='both', expand=True, padx=10, pady=10)
        self.setup_treeview(frame_backend, 'backend')
        self.add_right_click_menu(self.tree_backend)

        frame_appsvr = ttk.LabelFrame(self.tab_logs, text="AppServer Logs")
        frame_appsvr.pack(fill='both', expand=True, padx=10, pady=10)
        self.setup_treeview(frame_appsvr, 'appsvr')
        self.add_right_click_menu(self.tree_appsvr)

        self.update_ui_elements('disabled')
        self.check_for_updates()
        self.initialize_default_tab()

    def initialize_menu(self):
        menu_bar = tk.Menu(self.root)
        self.root.config(menu=menu_bar)

        file_menu = tk.Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Open tar", command=self.open_file)
        file_menu.add_command(label="Open Existing Directory", command=self.open_existing)
        file_menu.add_command(label="Open via SSH", command=self.fetch_ssh_logs)
        file_menu.add_separator()
        file_menu.add_command(label="Close current log", command=lambda: self.cleanup(), state='disabled')
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_close, accelerator="Alt+F4")
        self.root.bind_all("<Alt-F4>", lambda event: self.on_close())
        self.file_menu = file_menu

        edit_menu = tk.Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="Edit", menu=edit_menu)
        edit_menu.add_command(label="Source Manager", command=self.open_log_manager)

        view_menu = tk.Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="View", menu=view_menu)

        self.theme_menu = tk.Menu(view_menu, tearoff=0)
        view_menu.add_cascade(label="Theme", menu=self.theme_menu)
        self.theme_menu.add_command(label="Light Theme", command=lambda: self.theme_manager.apply_theme("light"))
        self.theme_menu.add_command(label="Dark Theme", command=lambda: self.theme_manager.apply_theme("dark"))
        self.theme_menu.add_command(label="Detect System Theme", command=lambda: self.theme_manager.apply_theme("system"))

    def open_log_manager(self):
        LogManager(self.root, self.config_manager, self.config)

    def initialize_default_tab(self):
        ordered_tabs = self.config.get("tab_order", ConfigManager.DEFAULT_CONFIG["tab_order"])
        tab_dict = {}

        if self.logbase:
            for log_config in self.config['logs']:
                if self.has_valid_logs(log_config):
                    tab_dict[log_config['id']] = ttk.Frame(self.notebook)

        for tab_id in ordered_tabs:
            if tab_id in tab_dict:
                log_config = next((log for log in self.config['logs'] if log['id'] == tab_id), None)
                if log_config:
                    self.notebook.add(tab_dict[tab_id], text=log_config['name'])

        for log_config in self.config['logs']:
            if log_config['id'] in tab_dict:
                if log_config['type'] == 'config':
                    self.initialize_config_tab(log_config)
                elif log_config['type'] == 'log':
                    self.initialize_log_tab(log_config)

    def has_valid_logs(self, log_config):
        if not self.logbase:
            return False

        log_dir = os.path.join(self.logbase, log_config['path'])
        if log_config['type'] == 'log':
            return bool(glob.glob(os.path.join(log_dir, log_config['pattern'])))
        elif log_config['type'] == 'config':
            return os.path.exists(log_dir)
        return False

    def initialize_config_tab(self, log_config):
        tab_name = log_config['name']
        tab = self.get_tab_by_name(tab_name)
        if not tab or not self.logbase:
            return

        config_dir = os.path.join(self.logbase, log_config['path'])
        if os.path.exists(config_dir):
            hide_comments_var = tk.BooleanVar(value=False)
            hide_comments_toggle = ttk.Checkbutton(tab, text="Sanitize Contents", variable=hide_comments_var, command=lambda: self.load_config_file(log_config, hide_comments_var, config_text), style="Switch.TCheckbutton")
            hide_comments_toggle.pack(anchor='w', padx=10, pady=5)

            config_text = tk.Text(tab, wrap='word', state='disabled')
            config_text.pack(fill='both', expand=True, padx=10, pady=10)

            config_scrollbar = ttk.Scrollbar(config_text, orient='vertical', command=config_text.yview)
            config_scrollbar.pack(side='right', fill='y')
            config_text['yscrollcommand'] = config_scrollbar.set
            self.load_config_file(log_config, hide_comments_var, config_text)

    def initialize_log_tab(self, log_config):
        tab_name = log_config['name']
        tab = self.get_tab_by_name(tab_name)
        if not tab or not self.logbase:
            return

        log_dir = os.path.join(self.logbase, log_config['path'])
        if os.path.exists(log_dir):
            combobox_var = tk.StringVar()
            combobox = ttk.Combobox(tab, textvariable=combobox_var, state='readonly', style='Custom.TCombobox', font=(self.font_family, 11))
            combobox.pack(fill='x', padx=10, pady=10)
            combobox.bind("<<ComboboxSelected>>", lambda e, config=log_config: self.load_log_file(os.path.join(self.logbase, log_config['path'], combobox.get()), log_text))

            log_text = tk.Text(tab, wrap='word', state='disabled')
            log_text.pack(fill='both', expand=True, padx=10, pady=10)

            scrollbar = ttk.Scrollbar(log_text, orient='vertical', command=log_text.yview)
            scrollbar.pack(side='right', fill='y')
            log_text['yscrollcommand'] = scrollbar.set
            self.update_file_combobox(log_dir, log_config['pattern'], combobox, log_config['name'], log_text)

    def load_config_file(self, log_config, hide_comments_var, config_text):
        if not self.logbase:
            return

        config_dir = os.path.join(self.logbase, log_config['path'])
        if os.path.exists(config_dir):
            for file_name in os.listdir(config_dir):
                if fnmatch.fnmatch(file_name, log_config['pattern']):
                    config_file_path = os.path.join(config_dir, file_name)
                    with open(config_file_path, 'r', encoding='ISO-8859-1') as file:
                        content = file.read()

                    # Apply comment sanitization if needed
                    if hide_comments_var.get():
                        if log_config.get("format") == "ini":
                            content = self.clean_ini_content(content)
                        elif log_config.get("format") == "xml":
                            content = self.clean_xml_content(content)
                        elif log_config.get("format") == "json":
                            content = self.clean_json_content(content)
                        elif log_config.get("format") == "yaml":
                            content = self.clean_yaml_content(content)

                    config_text.config(state='normal')
                    config_text.delete('1.0', tk.END)
                    config_text.insert('1.0', content)
                    config_text.config(state='disabled')

                    # Apply syntax highlighting based on the format
                    if log_config.get("format") == "ini":
                        self.highlight_ini(config_text)
                    elif log_config.get("format") == "xml":
                        self.highlight_xml(config_text)
                    elif log_config.get("format") == "json":
                        self.highlight_json(config_text)
                    elif log_config.get("format") == "yaml":
                        self.highlight_yaml(config_text)
                    break

    def initialize_spinner(self, theme):
        spinner_file = 'spinner-dark.gif' if theme == 'dark' else 'spinner-light.gif'
        self.spinner.load(os.path.join(self.script_dir, spinner_file), 48, 48)
        
    def center_spinner(self):
        self.spinner.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        self.spinner.lift()

    def setup_treeview(self, parent, type):
        tree = ttk.Treeview(parent, columns=("Count", "First Seen", "Last Seen", "Event Type", "Process", "File", "Line"), show="headings", selectmode='extended', style="Custom.Treeview")

        for col in tree['columns']:
            tree.heading(col, text=col, command=functools.partial(self.treeview_sort_column, tree, False, col))
            if col in ["Count", "Line"]:
                tree.column(col, anchor='e', stretch=False, width=50)
            elif col in ["First Seen", "Last Seen"]:
                tree.column(col, anchor='center', width=50)
            else:
                tree.column(col, anchor='w', stretch=True)

        scroll_y = ttk.Scrollbar(parent, orient='vertical', command=tree.yview)
        scroll_y.pack(side='right', fill='y', padx=(1, 1), pady=(30, 5))
        tree.configure(yscrollcommand=scroll_y.set)
        tree.pack(fill='both', expand=True, padx=(4, 4), pady=(4, 4))
        tree.bind("<Double-1>", self.on_double_click)

        if type == 'backend':
            self.tree_backend = tree
        else:
            self.tree_appsvr = tree

    def apply_styles(self):
        style = ttk.Style(self.root)
        style.configure('.', font=self.standard_font)
        style.configure('TLabel', font=self.standard_font)
        style.configure('TButton', font=self.standard_font)
        style.configure('TEntry', font=self.standard_font)
        style.configure('TFrame', background='SystemButtonFace')

        style.configure("Header.TLabel", font=self.standard_font)
        style.configure("HeaderValue.TLabel", font=self.standard_font)
        style.configure("SubHeader.TLabel", font=self.header_font)

        style.configure("TCombobox", fieldbackground='SystemButtonFace', foreground='SystemWindowText')
        style.map('TCombobox', fieldbackground=[('readonly', 'SystemButtonFace'), ('!focus', 'SystemButtonFace'), ('readonly hover', 'SystemButtonFace'), ('readonly focus', 'SystemButtonFace')],
                  foreground=[('readonly', 'SystemWindowText'), ('!focus', 'SystemWindowText'), ('readonly hover', 'SystemWindowText'), ('readonly focus', 'SystemWindowText')])

        current_theme = sv_ttk.get_theme()
        if current_theme == 'dark':
            style.configure('.', background='black', foreground='white')
            style.configure('TLabel', background='black', foreground='white')
            style.configure('TFrame', background='black')
            style.configure('TCombobox', fieldbackground='black', foreground='white')
            style.map('TCombobox', fieldbackground=[('readonly', 'black'), ('!focus', 'black'), ('readonly hover', 'black'), ('readonly focus', 'black')],
                      foreground=[('readonly', 'white'), ('!focus', 'white'), ('readonly hover', 'white'), ('readonly focus', 'white')])
            self.output_text.config(bg='black', fg='white', insertbackground='white')
            self.status_label.config(foreground='white', background='black')
        else:
            style.configure('.', background='SystemButtonFace', foreground='SystemWindowText')
            style.configure('TLabel', background='SystemButtonFace', foreground='SystemWindowText')
            style.configure('TFrame', background='SystemButtonFace')
            style.configure('TCombobox', fieldbackground='SystemButtonFace', foreground='SystemWindowText')
            style.map('TCombobox', fieldbackground=[('readonly', 'SystemButtonFace'), ('!focus', 'SystemButtonFace'), ('readonly hover', 'SystemButtonFace'), ('readonly focus', 'SystemButtonFace')],
                      foreground=[('readonly', 'SystemWindowText'), ('!focus', 'SystemWindowText'), ('readonly hover', 'SystemWindowText'), ('readonly focus', 'SystemWindowText')])

        style.layout("Tab", [('Notebook.tab', {'sticky': 'nswe', 'children': [('Notebook.padding', {'side': 'top', 'sticky': 'nswe', 'children': [('Notebook.label', {'side': 'top', 'sticky': ''})], })], })])
        style.configure("Tab", focuscolor=style.configure(".")["background"])

    def apply_font_styles(self):
        # Reapply font styles to ensure consistency after theme change
        self.output_text.config(font=self.standard_font)
        self.status_label.config(font=self.standard_font)
        self.hostname_value.config(font=self.header_font)
        self.role_value.config(font=self.header_font)
        self.ip_value.config(font=self.header_font)
        self.version_value.config(font=self.header_font)
        self.dropdown.config(font=(self.font_family, 11))

    def on_close(self):
        ConfigManager.save_config(self.config)
        self.cleanup()
        self.root.destroy()

    def cleanup(self):
        temp_dir = tempfile.gettempdir()
        if self.logbase and os.path.commonpath([self.logbase, temp_dir]) == temp_dir:
            try:
                shutil.rmtree(self.logbase)
            except Exception as e:
                pass
        if hasattr(self, 'file_path') and self.file_path and os.path.commonpath([self.file_path, temp_dir]) == temp_dir:
            try:
                os.remove(self.file_path)
            except Exception as e:
                pass
        for tab_id in self.notebook.tabs():
            self.notebook.forget(tab_id)
        self.tree_backend.delete(*self.tree_backend.get_children())
        self.tree_appsvr.delete(*self.tree_appsvr.get_children())
        if hasattr(self, 'text_widget') and self.text_widget.winfo_exists():
            self.text_widget.destroy()
        self.logbase = None
        self.backend_logs = []
        self.appserver_logs = []
        self.systeminfo.clear()
        self.networks.clear()
        self.system_info_manager.update_system_info_header()
        self.date_to_logs.clear()
        self.update_datechooser()
        self.treeview_sort_column(self.tree_backend, False, None)
        self.treeview_sort_column(self.tree_appsvr, False, None)
        self.file_menu.entryconfig("Close current log", state=tk.DISABLED)
        self.update_ui_elements('disabled')
        gc.collect()

    def update_ui_elements(self, state):
        try:
            if self.root.winfo_exists() and self.dropdown.winfo_exists():
                self.dropdown.config(state=state)
        except tk.TclError:
            pass
        if state == 'readonly':
            for tree in [self.tree_backend, self.tree_appsvr]:
                for col in tree['columns']:
                    try:
                        tree.heading(col, command=functools.partial(self.treeview_sort_column, tree, False, col))
                    except tk.TclError:
                        pass
        else:
            for tree in [self.tree_backend, self.tree_appsvr]:
                for col in tree['columns']:
                    try:
                        tree.heading(col, command='')
                    except tk.TclError:
                        pass
                        
    def update_file_combobox(self, directory, pattern, combobox, default_file, text_widget):
        try:
            log_files = sorted(glob.glob(os.path.join(directory, pattern)), key=lambda x: os.path.basename(x))
            filenames = [os.path.basename(f) for f in log_files]
            
            def update_combobox():
                combobox['values'] = filenames
                if default_file in filenames:
                    combobox.set(default_file)
                elif filenames:
                    combobox.set(filenames[0])
                self.root.update_idletasks()  # Force update the UI
                combobox.update()  # Explicitly update the combobox
                combobox.event_generate("<<ComboboxSelected>>")  # Trigger the event to load the file
                self.load_log_file(os.path.join(directory, combobox.get()), text_widget)
    
            self.root.after(0, update_combobox)  # Ensure this runs in the UI thread
    
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load log files: {e}")

    def open_file(self):
        self.file_path = filedialog.askopenfilename(title="Open Log File", filetypes=[("TAR files", "*.tar"),("All files", "*.*")])
        if not self.file_path:
            return
        
        self.cleanup()

        self.update_ui_elements('disabled')
        self.launch_extractor()

    def open_existing(self):
        directory = filedialog.askdirectory(title='Select the directory containing the extracted logs')
        if not directory:
            return
        if os.path.exists(f'{directory}/AOLogs'):
            directory = f'{directory}/AOLogs'
        if not os.path.isdir(os.path.join(directory, 'backend')):
            messagebox.showerror("Error", "Selected directory does not appear to be a valid log directory")
            self.cleanup()
            return
        self.cleanup()
        self.logbase = directory
        # Create the text widget for displaying content
        self.text_widget = tk.Text(self.root, wrap='word')
        self.text_widget.pack(fill='both', expand=True)
        # Define tags for syntax highlighting
        self.text_widget.tag_configure("keyword", foreground="blue")
        self.text_widget.tag_configure("string", foreground="green")
        self.text_widget.tag_configure("comment", foreground="grey", font=("Arial", 8, "italic"))
        self.text_widget.tag_configure("number", foreground="purple")
        # Add the tab to the notebook for logs
        self.notebook.add(self.tab_logs, text='Aggregate Logs')
        self.load_system_info_and_logs()
        self.update_ui_elements('readonly')

    def launch_extractor(self):
        if not self.file_path or not os.path.exists(self.file_path):
            return
        try:
            with tarfile.open(self.file_path, 'r') as tar:
                members = tar.getnames()
                if not any(name.startswith('AOLogs/backend') for name in members):
                    messagebox.showerror("Error", "Tarball does not appear to be a valid support log tarball")
                    self.cleanup()
                    return
        except Exception as e:
            self.cleanup()
            messagebox.showerror("Error", f"Failed to read tarball: {e}")
            return
        tarball_dir = os.path.dirname(self.file_path)
        dir_name = os.path.splitext(os.path.basename(self.file_path))[0]
        output_path = os.path.join(tarball_dir, dir_name)
        if os.path.exists(output_path):
            response = messagebox.askyesno("Directory exists", f"The directory {os.path.normpath(output_path)} already exists.\n\nDo you want to overwrite it?")
            if response:
                shutil.rmtree(output_path)
                self.create_extractor_window()
            else:
                return
        else:
            self.create_extractor_window()

    def create_extractor_window(self):
        current_theme = sv_ttk.get_theme()
        extractor_app = FSMLogsExtractorApp(self.root, self.file_path, remove_parent=False, theme=current_theme, on_extraction_complete=self.handle_extraction_complete)
        self.set_initial_window_position(extractor_app)
        extractor_app.deiconify()

    def handle_extraction_complete(self, extracted_path):
        def on_extraction_window_close():
            time.sleep(5)
            self.logbase = extracted_path
            self.text_widget = tk.Text(self.root, wrap='word')
            self.text_widget.pack(fill='both', expand=True)
            self.text_widget.tag_configure("keyword", foreground="blue")
            self.text_widget.tag_configure("string", foreground="green")
            self.text_widget.tag_configure("comment", foreground="grey", font=("Arial", 8, "italic"))
            self.text_widget.tag_configure("number", foreground="purple")
            self.notebook.add(self.tab_logs, text='Aggregate Logs')
            if os.path.exists(f'{self.logbase}/AOLogs'):
                self.logbase = f'{self.logbase}/AOLogs'
            self.load_system_info_and_logs()
            self.update_ui_elements('readonly')

        # Set the callback for the extraction window to close before calling handle_extraction_complete
        self.root.after(0, on_extraction_window_close)

    def load_system_info_and_logs(self):
        def load():
            self.system_info_manager.update_system_info()
            self.organize_logs()
            self.root.after(0, self.update_datechooser)
            self.root.after(0, self.load_logs)
            self.root.after(0, self.initialize_default_tab)
            self.file_menu.entryconfig("Close current log", state=tk.NORMAL)
            self.root.after(0, self.spinner.stop)

        self.spinner.start()
        self.center_spinner()
        threading.Thread(target=load).start()
        
    def load_log_file(self, file_path, text_widget):
        try:
            if file_path and text_widget:
                with open(file_path, 'r', encoding='ISO-8859-1') as file:
                    content = file.read()
                text_widget.config(state='normal')
                text_widget.delete('1.0', tk.END)
                text_widget.insert(tk.END, content)
                text_widget.config(state='disabled')
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load log file: {e}")
        
    def get_logs_from_file(self, log_file_path, log_type, target_date, existing_logs=None):
        parser = LogParser()
        logs = existing_logs if existing_logs else {}
        first_timestamp = None
        line_number = 0
        logs_for_date = parser.filter_logs_by_date(log_file_path, log_type, target_date)
    
        for line in logs_for_date:
            line_number += 1
            try:
                parsed = parser.parse_log(line, log_type)
                if parsed:
                    timestamp, reporter, event, severity, process, file_name, line_num = parsed
                    key = (process, event, file_name, str(line_num))
                    if key not in logs:
                        logs[key] = {'count': 0, 'first_seen': timestamp, 'last_seen': timestamp}
                        if first_timestamp is None or timestamp < first_timestamp:
                            first_timestamp = timestamp
                    logs[key]['count'] += 1
                    logs[key]['first_seen'] = min(logs[key]['first_seen'], timestamp)
                    logs[key]['last_seen'] = max(logs[key]['last_seen'], timestamp)
            except Exception as parse_error:
                print(f"Error parsing line {line_number} in file {log_file_path}: {parse_error}")
                print(f"Line content: {line.strip()}")
    
        return logs
        
    def aggregate_logs_across_files(self, log_files, log_type, target_date):
        all_errors = {}
        for log_file_path in log_files:
            all_errors = self.get_logs_from_file(log_file_path, log_type, target_date, existing_logs=all_errors)
    
        results = []
        for (process, event, file_name, parsed_line_number), details in all_errors.items():
            results.append([
                details['count'],
                details['first_seen'].strftime('%I:%M %p'),
                details['last_seen'].strftime('%I:%M %p'),
                event, process, file_name, parsed_line_number
            ])
        return results

    def update_datechooser(self):
        dates = sorted(self.date_to_logs.keys())
        self.dropdown['values'] = dates
        if dates:
            self.latest_date = dates[-1]
            self.dropdown.set(self.latest_date)
            self.root.after(100, self.load_logs)
        else:
            self.dropdown.set('')
            
    def adjust_column_widths(self):
        def adjust_tree_columns(tree, min_widths, max_widths):
            tree.update_idletasks()
            tree_font = self.standard_font
    
            for index, col in enumerate(tree["columns"]):
                max_width = tree_font.measure(tree.heading(col)['text']) + 20
    
                for item in tree.get_children(''):
                    cell_value = str(tree.set(item, col))
                    cell_value = ' '.join(cell_value.split())
                    cell_width = tree_font.measure(cell_value)
                    max_width = max(max_width, cell_width)
    
                # Apply minimum and maximum width constraints
                final_width = min(max(min_widths[index], max_width), max_widths[index])
                tree.column(col, width=final_width)
    
        # Minimum and maximum widths for each column
        min_widths = [40, 50, 50, 175, 65, 50, 55]
        max_widths = [75, 50, 50, 400, 95, 300, 75]
    
        # Apply width adjustments to both Treeviews
        adjust_tree_columns(self.tree_backend, min_widths, max_widths)
        adjust_tree_columns(self.tree_appsvr, min_widths, max_widths)
        
    def create_text_widget_context_menu(self, text_widget):
        context_menu = tk.Menu(text_widget, tearoff=0)
        context_menu.add_command(label="Copy", command=lambda: text_widget.event_generate("<<Copy>>"))
        context_menu.add_separator()
        context_menu.add_command(label="Select All", command=lambda: text_widget.tag_add("sel", "1.0", "end"))

    def get_tab_by_name(self, tab_name):
        for tab_id in self.notebook.tabs():
            if self.notebook.tab(tab_id, 'text') == tab_name:
                return self.notebook.nametowidget(tab_id)
        return None
        
    def on_tab_reorder(self, event):
#        self.save_tab_order()
        pass
        
    def on_tab_drag_start(self, event):
        element = self.notebook.identify(event.x, event.y)
        if "label" in element:
            self.tab_drag_data['start_index'] = self.notebook.index(f"@{event.x},{event.y}")

    def on_tab_drag_motion(self, event):
        if self.tab_drag_data['start_index'] is None:
            return
        element = self.notebook.identify(event.x, event.y)
        if "label" in element:
            self.tab_drag_data['end_index'] = self.notebook.index(f"@{event.x},{event.y}")
            if self.tab_drag_data['start_index'] != self.tab_drag_data['end_index']:
                self.notebook.insert(self.tab_drag_data['end_index'], self.notebook.tabs()[self.tab_drag_data['start_index']])
                self.tab_drag_data['start_index'] = self.tab_drag_data['end_index']

    def on_tab_drag_end(self, event):
#        if self.tab_drag_data['start_index'] is not None and self.tab_drag_data['end_index'] is not None:
#            self.save_tab_order()
        self.tab_drag_data = {'start_index': None, 'end_index': None}

    def save_tab_order(self):
        current_tab_order = [next(log['id'] for log in self.config['logs'] if log['name'] == self.notebook.tab(tab_id, 'text')) for tab_id in self.notebook.tabs()]
        self.config["tab_order"] = current_tab_order
        ConfigManager.save_config(self.config)

    def treeview_sort_column(self, tv, reverse, col=None):
        for column in tv['columns']:
            if column != col:
                tv.heading(column, text=column)
        if not col:
            return
        data_type = {'Count': int, 'First Seen': datetime.strptime, 'Last Seen': datetime.strptime, 'Line': int}

        def convert(value):
            try:
                if col in data_type:
                    if 'Seen' in col:
                        return data_type[col](value, '%I:%M %p')
                    return data_type[col](value) if value is not None else 0
                else:
                    return value
            except ValueError:
                return 0 if col in ['Count', 'Line'] else value

        l = [(convert(tv.set(k, col)), k) for k in tv.get_children('')]
        l.sort(key=lambda x: x[0], reverse=reverse)

        for index, (val, k) in enumerate(l):
            tv.move(k, '', index)

        new_reverse = not reverse
        arrow = '↓' if reverse else '↑'
        current_heading = re.split(r' \↑| \↓', tv.heading(col, 'text'))[0]
        tv.heading(col, text=f"{current_heading} {arrow}", command=lambda: self.treeview_sort_column(tv, new_reverse, col))
        
    def load_logs(self, event=None):
        selected_date = self.selected_date.get()
        if selected_date in self.date_to_logs:
            self.display_logs_for_date(selected_date)
        else:
            messagebox.showinfo("Info", "No logs available for this date.")
    
    def display_logs_for_date(self, date):
        self.backend_logs = [log for log in self.date_to_logs[date] if 'backend' in log]
        self.appserver_logs = [log for log in self.date_to_logs[date] if 'appsvr' in log]
        self.tree_backend.delete(*self.tree_backend.get_children())
        self.tree_appsvr.delete(*self.tree_appsvr.get_children())
      
        # Aggregate logs across all files for the given date
        if self.backend_logs:
            backend_results = self.aggregate_logs_across_files(self.backend_logs, 'backend', date)
            for result in backend_results:
                cleaned_result = ["" if r is None or r == 'None' else r for r in result]
                self.tree_backend.insert("", "end", values=cleaned_result)
    
        if self.appserver_logs:
            appserver_results = self.aggregate_logs_across_files(self.appserver_logs, 'appserver', date)
            for result in appserver_results:
                cleaned_result = ["" if r is None or r == 'None' else r for r in result]
                self.tree_appsvr.insert("", "end", values=cleaned_result)
    
        self.treeview_sort_column(self.tree_backend, True, "Count")
        self.treeview_sort_column(self.tree_appsvr, True, "Count")
    
        self.adjust_column_widths()
        
    def display_logs(self, log_entries, title):
        top = tk.Toplevel(self.root)
        top.title(title)
        self.configure_window_size(top, 1500, 600)
        self.set_initial_window_position(top)
    
        # Determine colors based on the current theme
        current_theme = sv_ttk.get_theme()
        if current_theme == 'dark':
            text_bg = 'black'
            text_fg = 'white'
            even_row_bg = '#333333'
            odd_row_bg = 'black'
        else:
            text_bg = 'white'
            text_fg = 'black'
            even_row_bg = '#E8E8E8'
            odd_row_bg = '#FFFFFF'
    
        text = tk.Text(top, wrap='word', bg=text_bg, fg=text_fg)
        text.pack(side='left', fill='both', expand=True)
    
        scroll = tk.Scrollbar(top, command=text.yview)
        scroll.pack(side='right', fill='y')
        text.config(yscrollcommand=scroll.set)
    
        # Define tags for alternating row colors
        text.tag_configure('evenRow', background=even_row_bg)
        text.tag_configure('oddRow', background=odd_row_bg)
    
        log_entries = sorted(log_entries, key=lambda x: x[0])
    
        for index, (timestamp, entry) in enumerate(log_entries):
            text.insert('end', f"{entry}\n")
            line_index_start = f"{index + 1}.0"
            line_index_end = f"{index + 1}.end+1c"  # Extend the tag to the end of the line
            if index % 2 == 0:
                text.tag_add('evenRow', line_index_start, line_index_end)
            else:
                text.tag_add('oddRow', line_index_start, line_index_end)
    
        text.config(state='disabled')
        text.yview_moveto(0)
        
    def filter_log_entries(self, log_files, event_name, process_name, filename, line_number, log_type, target_date):
        log_entries = []
        parser = LogParser()
        
        for log_file_path in log_files:
            logs_for_date = parser.filter_logs_by_date(log_file_path, log_type, target_date)
            for line in logs_for_date:
                # Ensure that event name, process name, and filename are in the line
                if all(key in line for key in [event_name, process_name, filename]):
                    timestamp = self.parse_timestamp(line, log_type)
                    # Check if line_number is None, empty, or a non-string falsey value
                    if line_number in (None, '', 'None', 0, '0'):
                        line_number_condition = True  # No specific line number to match
                    else:
                        line_number_condition = f'[lineNumber]={line_number}' in line

                    # Combine timestamp validity check with line_number_condition
                    if timestamp and line_number_condition:
                        log_entries.append((timestamp, line.strip()))
        return sorted(log_entries, key=lambda x: x[0])
        
    def parse_timestamp(self, log_entry, log_type):
        try:
            if log_type == "backend":
                # Example backend log timestamp: 2024-04-18T14:15:23.346457-04:00
                timestamp_str = log_entry.split()[0]
                return datetime.strptime(timestamp_str, '%Y-%m-%dT%H:%M:%S.%f%z')
            elif log_type == "appserver":
                # Example appserver log timestamp: 2024-04-17 15:44:17,339
                timestamp_str = log_entry.split()[0] + " " + log_entry.split()[1]
                return datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S,%f')
        except ValueError as e:
            print(f"Error parsing timestamp: {str(e)}")
            return None
            
    def clean_ini_content(self, content):
        lines = content.splitlines()
        cleaned_lines = []
        section_open = False

        for line in lines:
            line = line.strip()
            if line.startswith('#'):
                continue  # Skip comment lines
            if line.startswith('[BEGIN '):
                section_open = True
                cleaned_lines.append(line)
            elif line.startswith('[END'):
                section_open = False
                cleaned_lines.append(line)
                cleaned_lines.append('')
            elif section_open and line:
                cleaned_lines.append(line)

        return "\n".join(cleaned_lines)

    def clean_xml_content(self, content):
        dom = minidom.parseString(content)
        pretty_xml = dom.toprettyxml(indent="  ")

        cleaned_lines = [line for line in pretty_xml.splitlines() if line.strip() and not line.strip().startswith("<!--")]
        return "\n".join(cleaned_lines)

    def clean_json_content(self, content):
        json_obj = json.loads(content)
        pretty_json = json.dumps(json_obj, indent=4)

        cleaned_lines = [line for line in pretty_json.splitlines() if line.strip() and not line.strip().startswith("//")]
        return "\n".join(cleaned_lines)

    def clean_yaml_content(self, content):
        yaml_obj = yaml.safe_load(content)
        pretty_yaml = yaml.dump(yaml_obj, default_flow_style=False, sort_keys=False)

        cleaned_lines = [line for line in pretty_yaml.splitlines() if line.strip() and not line.strip().startswith("#")]
        return "\n".join(cleaned_lines)
    
    def highlight_json(self, content):
        self.text_widget.tag_remove("keyword", "1.0", tk.END)
        self.text_widget.tag_remove("string", "1.0", tk.END)
        self.text_widget.tag_remove("number", "1.0", tk.END)
        self.text_widget.tag_remove("null", "1.0", tk.END)

        self.highlight_pattern(r'\btrue\b|\bfalse\b', "keyword", content)
        self.highlight_pattern(r'"[^"\\]*(?:\\.[^"\\]*)*"', "string", content)
        self.highlight_pattern(r'\b-?\d+(\.\d+)?([eE][+-]?\d+)?\b', "number", content)
        self.highlight_pattern(r'\bnull\b', "null", content)

    def highlight_xml(self, content):
        self.text_widget.tag_remove("keyword", "1.0", tk.END)
        self.text_widget.tag_remove("string", "1.0", tk.END)
        self.text_widget.tag_remove("comment", "1.0", tk.END)

        self.highlight_pattern(r'<!--.*?-->', "comment", content)
        self.highlight_pattern(r'</?[a-zA-Z0-9]+>', "keyword", content)
        self.highlight_pattern(r'".*?"', "string", content)

    def highlight_ini(self, text_widget):
        text_widget.tag_remove("keyword", "1.0", tk.END)
        text_widget.tag_remove("string", "1.0", tk.END)
        text_widget.tag_remove("comment", "1.0", tk.END)

        self.highlight_pattern(r'^\s*#.*', "comment", text_widget)
        self.highlight_pattern(r'^\s*;.*', "comment", text_widget)
        self.highlight_pattern(r'^\[.*?\]', "keyword", text_widget)
        self.highlight_pattern(r'".*?"', "string", text_widget)

    def highlight_pattern(self, pattern, tag, text_widget):
        start = "1.0"
        while True:
            start = text_widget.search(pattern, start, stopindex=tk.END, regexp=True)
            if not start:
                break
            end = text_widget.index(f"{start} lineend")
            text_widget.tag_add(tag, start, end)
            start = text_widget.index(f"{end} +1c")

    def on_double_click(self, event):
        tree = event.widget
        selected_items = tree.selection()
        if selected_items:
            item = selected_items[0]
            log_type = 'backend' if tree == self.tree_backend else 'appserver'
            details = tree.item(item, "values")
            event_name, process, filename, line_number = details[3], details[4], details[5], details[6]
            selected_date = self.selected_date.get()
            log_entries = self.filter_log_entries(self.backend_logs if tree == self.tree_backend else self.appserver_logs, event_name, process, filename, line_number, log_type, selected_date)
            title = f"Displaying logs for {event_name} on {selected_date}"
            self.display_logs(log_entries, title)
            
    def display_logs_for_date(self, date):
        self.backend_logs = [log for log in self.date_to_logs[date] if 'backend' in log]
        self.appserver_logs = [log for log in self.date_to_logs[date] if 'appsvr' in log]
        self.tree_backend.delete(*self.tree_backend.get_children())
        self.tree_appsvr.delete(*self.tree_appsvr.get_children())
      
        # Aggregate logs across all files for the given date
        if self.backend_logs:
            backend_results = self.aggregate_logs_across_files(self.backend_logs, 'backend', date)
            for result in backend_results:
                cleaned_result = ["" if r is None or r == 'None' else r for r in result]
                self.tree_backend.insert("", "end", values=cleaned_result)
    
        if self.appserver_logs:
            appserver_results = self.aggregate_logs_across_files(self.appserver_logs, 'appserver', date)
            for result in appserver_results:
                cleaned_result = ["" if r is None or r == 'None' else r for r in result]
                self.tree_appsvr.insert("", "end", values=cleaned_result)
    
        self.treeview_sort_column(self.tree_backend, True, "Count")
        self.treeview_sort_column(self.tree_appsvr, True, "Count")
    
        self.adjust_column_widths()
        
    def configure_window_size(self, top, width=1500, height=600):
        screen_width = top.winfo_screenwidth()
        screen_height = top.winfo_screenheight()
        window_width = min(width, screen_width)
        window_height = min(height, screen_height)
        if window_width < width or window_height < height:
            top.state('zoomed')  # maximize
        else:
            top.geometry(f'{window_width}x{window_height}')
            
    def set_initial_window_position(self, window):
        window.update_idletasks()
    
        # Get dimensions of the parent window
        parent_x = self.root.winfo_rootx()
        parent_y = self.root.winfo_rooty()
        parent_width = self.root.winfo_width()
        parent_height = self.root.winfo_height()
    
        # Get dimensions of the new window
        window_width = window.winfo_width() or window.winfo_reqwidth()
        window_height = window.winfo_height() or window.winfo_reqheight()
    
        # Calculate position to center the new window relative to the parent window
        x = parent_x + (parent_width // 2) - (window_width // 2)
        y = parent_y + (parent_height // 2) - (window_height // 2)
    
        window.geometry(f'{window_width}x{window_height}+{x}+{y}')

    def on_open_selected_logs(self, tree):
        selected_items = tree.selection()
        if not selected_items:
            messagebox.showinfo("Info", "No entries selected.")
            return

        log_entries = []
        event_names = set()  # Use a set to avoid duplicate event names
        log_type = 'backend' if tree == self.tree_backend else 'appserver'
        log_files = self.determine_logs(tree)
        selected_date = self.selected_date.get()
        
        for item in selected_items:
            details = tree.item(item, "values")
            event_name, process, filename, line_number = details[3], details[4], details[5], details[6]
            log_entries.extend(self.filter_log_entries(log_files, event_name, process, filename, line_number, log_type, selected_date))
            event_names.add(event_name)

        if len(event_names) > 1:
            sorted_names = sorted(event_names)
            title = f"Displaying logs for {', '.join(sorted_names[:-1])}, and {sorted_names[-1]} on {selected_date}"
        else:
            title = f"Displaying logs for {next(iter(event_names))} on {selected_date}"  # Safe as we check if event_names is not empty earlier

        self.display_logs(log_entries, title=title)
        
    def add_right_click_menu(self, tree):
        menu = tk.Menu(tree, tearoff=0)
        menu.add_command(label="Open Selected Logs", command=lambda: self.on_open_selected_logs(tree))
        tree.bind("<Button-3>", lambda event, t=tree: self.popup_menu(event, menu, t))
        
    def determine_logs(self, tree):
        return self.backend_logs if tree == self.tree_backend else self.appserver_logs
    
    def popup_menu(self, event, menu, tree):
        try:
            if tree.identify_row(event.y):
                menu.post(event.x_root, event.y_root)
        except tk.TclError:
            pass  # Do nothing if right-click is not on a row
        
    def fetch_ssh_logs(self):
        self.update_ui_elements('disabled')
        current_theme = sv_ttk.get_theme()  # Get the current theme
        top_level_window = tk.Toplevel(self.root)
        initial_credentials = self.config.get("ssh_credentials", {})
        form = SSHCredentialsForm(top_level_window, callback=self.handle_credentials, initial_credentials=initial_credentials, theme=current_theme)
        form.pack()
    
        top_level_window.transient(self.root)
        self.set_initial_window_position(top_level_window)
        top_level_window.grab_set()
        top_level_window.focus_set()
        self.root.wait_window(top_level_window)

    def on_ssh_complete(self):
        if os.path.exists(self.download_path):
            try:
                if self.ssh_window.winfo_exists():
                    self.ssh_window.destroy()
            except tk.TclError:
                pass
            self.handle_result(self.download_path)
        else:
            print("SSH operation failed or file does not exist")
        
    def handle_credentials(self, credentials):
        self.config['ssh_credentials'] = credentials
        ConfigManager.save_config(self.config)
        self.root.after(1500, lambda: self.start_ssh_client(credentials))

    def start_ssh_client(self, credentials):
        self.ssh_window = tk.Toplevel(self.root)
        self.result_queue = queue.Queue()
    
        temp_directory = tempfile.gettempdir()
        unique_filename = f"AOLogs-{uuid.uuid4()}.tar"
        self.download_path = os.path.join(temp_directory, unique_filename)
        
        self.ssh_client = SSHClient(
            self.ssh_window,
            credentials['hostname'],
            credentials['username'],
            password=credentials.get('password'),
            key_filename=credentials.get('keyfile'),
            days=credentials['days'],
            on_complete=self.on_ssh_complete,
            theme="dark"
        )
        
        self.ssh_window.withdraw()  # Hide the window until it's positioned
        self.set_initial_window_position(self.ssh_window)
        self.ssh_window.deiconify()  # Show the window after it's positioned
        
        self.ssh_window.transient(self.root)
        self.ssh_window.grab_set()
        self.ssh_window.focus_set()
        self.ssh_client.pack(fill='both', expand=True)  # Ensure the SSHClient frame is packed
    
        self.cleanup()
        self.ssh_client.start_operations('/opt/phoenix/phscripts/bin/phziplogs /tmp', self.download_path, self.result_queue)
        self.root.wait_window(self.ssh_window)

    def handle_result(self, download_path):
        if download_path:
            self.file_path = download_path
            self.launch_extractor()
            try:
                if self.root.winfo_exists() and self.dropdown.winfo_exists():
                    self.update_ui_elements('readonly')
            except tk.TclError:
                pass
        
    def organize_logs(self):
        self.date_to_logs = self.organize_logs_by_date()

    def organize_logs_by_date(self):
        date_to_logs = defaultdict(list)
        directories = ["backend", "appsvr"]
        parser = LogParser()
        oldest_backend_date = None

        for directory in directories:
            path = os.path.join(self.logbase, directory)
            if os.path.exists(path):
                for file_name in os.listdir(path):
                    if file_name.startswith('phoenix.log'):
                        file_path = os.path.join(path, file_name)
                        log_type = 'backend' if directory == 'backend' else 'appserver'
                        start_date, end_date = parser.extract_date_range(file_path, log_type)
                        self.logger.info(f"Start date: {start_date}, End date: {end_date}, File: {file_path}")
                        if start_date and end_date:
                            current_date = start_date
                            while current_date <= end_date:
                                date_str = current_date.strftime('%Y-%m-%d')
                                date_to_logs[date_str].append(file_path)
                                if log_type == 'backend':
                                    if oldest_backend_date is None or current_date < oldest_backend_date:
                                        oldest_backend_date = current_date
                                current_date += timedelta(days=1)

        self.logger.debug(f'Before filtering: {json.dumps(date_to_logs)}')
        self.logger.info(f'Oldest backend date: {oldest_backend_date}')

        # Filter by oldest_backend_date
        if oldest_backend_date:
            filtered_date_to_logs = {
                date: logs for date, logs in date_to_logs.items()
                if datetime.strptime(date, '%Y-%m-%d') >= oldest_backend_date
            }
            date_to_logs = filtered_date_to_logs

        self.logger.debug(f'After filtering: {json.dumps(date_to_logs)}')

        sorted_dates = sorted(date_to_logs.keys())
        self.logger.info(f'Sorted dates: {sorted_dates}')

        if sorted_dates:
            self.latest_date = sorted_dates[-1]
        else:
            self.latest_date = None

        return date_to_logs
    
    def check_for_updates(self):
        if self.updater.check_for_updates():
            if messagebox.askyesno('Update Available', 'A new version is available. Do you want to update?'):
                zip_path = self.updater.download_latest_version()
                self.updater.install_update(zip_path)
            else:
                self.logger.info('Update canceled.')

class LogManager:
    def __init__(self, root, config_manager, config):
        self.root = root
        self.config_manager = config_manager
        self.config = config
        self.modified_config = copy.deepcopy(self.config)  # Make a deep copy of config
        self.all_sources = self.modified_config.get("logs", [])
        self.user_sources = [source for source in self.all_sources if source["creation_type"] == "user"]
        self.tab_order = self.modified_config.get("tab_order", [])  # Initialize tab_order from modified_config

        self.assign_ids_to_user_sources()  # Ensure user sources have IDs

        self.window = tk.Toplevel(root)
        self.window.geometry('1080x400')
        self.window.title("Source Manager")
        self.set_initial_window_position(self.window)
        self.window.transient(root)
        self.window.grab_set()

        self.tree = ttk.Treeview(self.window, columns=("handle", "name", "path", "pattern", "type", "format", "creation_type"), show="headings")
        self.tree.heading("handle", text="")
        self.tree.heading("name", text="Name")
        self.tree.heading("path", text="Path")
        self.tree.heading("pattern", text="Pattern")
        self.tree.heading("type", text="Type")
        self.tree.heading("format", text="Format")
        self.tree.heading("creation_type", text="Creation Type")
        self.tree.column("handle", width=30, anchor="center")
        self.tree.pack(fill=tk.BOTH, expand=True)
        self.tree.bind("<Button-1>", self.on_click)
        self.tree.bind("<B1-Motion>", self.on_drag)
        self.tree.bind("<Double-1>", self.on_double_click)  # Bind double-click to edit

        # Create a frame to hold the buttons
        self.button_frame = ttk.Frame(self.window)
        self.button_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=5)

        self.save_button = ttk.Button(self.button_frame, text="Save", command=self.save_sources)
        self.save_button.pack(side=tk.RIGHT, padx=(0, 10))

        self.add_button = ttk.Button(self.button_frame, text="Add Source", command=self.add_source)
        self.add_button.pack(side=tk.RIGHT, padx=(0, 10))  # Add some space between buttons

        self.reset_button = ttk.Button(self.button_frame, text="Reset Defaults", command=self.reset_defaults)
        self.reset_button.pack(side=tk.RIGHT, padx=(0, 10))  # Add some space between buttons

        self.load_sources()
        self.auto_size_columns()

        self.drag_data = {"item": None, "index": None}

    def assign_ids_to_user_sources(self):
        next_id = 100
        existing_ids = {source["id"] for source in self.all_sources}
        for source in self.user_sources:
            if "id" not in source:
                while next_id in existing_ids:
                    next_id += 1
                source["id"] = next_id
                existing_ids.add(next_id)

    def set_initial_window_position(self, window):
        window.update_idletasks()

        # Get dimensions of the parent window
        parent_x = self.root.winfo_rootx()
        parent_y = self.root.winfo_rooty()
        parent_width = self.root.winfo_width()
        parent_height = self.root.winfo_height()

        # Get dimensions of the new window
        window_width = window.winfo_width() or window.winfo_reqwidth()
        window_height = window.winfo_height() or window.winfo_reqheight()

        # Calculate position to center the new window relative to the parent window
        x = parent_x + (parent_width // 2) - (window_width // 2)
        y = parent_y + (parent_height // 2) - (window_height // 2)

        window.geometry(f'{window_width}x{window_height}+{x}+{y}')

    def auto_size_columns(self):
        for col in self.tree["columns"]:
            max_width = max(len(str(self.tree.set(item, col))) for item in self.tree.get_children('')) * 15
            self.tree.column(col, width=max_width)

    def load_sources(self):
        self.tree.delete(*self.tree.get_children())
        ordered_sources = sorted(self.all_sources, key=lambda x: self.tab_order.index(x["id"]) if x["id"] in self.tab_order else len(self.tab_order))
        for source in ordered_sources:
            values = ("⠿", source["name"], source["path"], source["pattern"], source["type"], source.get("format", ""), source["creation_type"])
            self.tree.insert("", tk.END, values=values, iid=str(source["id"]))

    def on_click(self, event):
        item = self.tree.identify_row(event.y)
        column = self.tree.identify_column(event.x)
        if item and column == "#1":  # Handle column is now the first column
            self.drag_data["item"] = item
            self.drag_data["index"] = self.tree.index(item)

    def on_drag(self, event):
        item = self.drag_data["item"]
        if item:
            y = event.y
            above_item = self.tree.identify_row(y - 1)
            below_item = self.tree.identify_row(y + 1)
            if above_item:
                self.tree.move(item, "", self.tree.index(above_item))
            elif below_item:
                self.tree.move(item, "", self.tree.index(below_item))
            self.update_tab_order()

    def update_tab_order(self):
        self.tab_order = [int(item) for item in self.tree.get_children()]

    def on_double_click(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            source_entry = next(source for source in self.all_sources if source["id"] == int(item))
            AddEditSourceWindow(self, source_entry, self.modified_config)

    def add_source(self):
        AddEditSourceWindow(self, None, self.modified_config)

    def save_sources(self):
        # Update the all_sources and user_sources from the current treeview
        self.all_sources = [{"id": int(item),
                             "name": self.tree.item(item, "values")[1],
                             "path": self.tree.item(item, "values")[2],
                             "pattern": self.tree.item(item, "values")[3],
                             "type": self.tree.item(item, "values")[4],
                             "format": self.tree.item(item, "values")[5],
                             "creation_type": self.tree.item(item, "values")[6]}
                            for item in self.tree.get_children()]
        self.user_sources = [source for source in self.all_sources if source["creation_type"] == "user"]
        self.modified_config["logs"] = self.all_sources
        self.modified_config["tab_order"] = self.tab_order
        self.config.update(self.modified_config)  # Overwrite self.config with self.modified_config
        self.window.destroy()

    def reset_defaults(self):
        self.modified_config = self.config_manager.load_default_config()
        self.all_sources = self.modified_config.get("logs", [])
        self.user_sources = [source for source in self.all_sources if source["creation_type"] == "user"]
        self.assign_ids_to_user_sources()
        self.tab_order = self.modified_config.get("tab_order", [])
        self.load_sources()
        self.auto_size_columns()

class AddEditSourceWindow:
    def __init__(self, source_manager, source_entry, config):
        self.source_manager = source_manager
        self.source_entry = source_entry
        self.config = config
        self.window = tk.Toplevel(source_manager.window)

        if source_entry:
            self.window.title(f"Edit {source_entry['name']}")
        else:
            self.window.title("Add New Source")

        self.window.geometry('320x320')

        self.is_read_only = source_entry is not None and source_entry.get("creation_type") == "system"

        self.form_frame = ttk.Frame(self.window)
        self.form_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        self.name_label = ttk.Label(self.form_frame, text="Name:")
        self.name_label.grid(row=0, column=0, padx=5, pady=5, sticky=tk.E)
        self.name_entry = ttk.Entry(self.form_frame)
        self.name_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        self.name_entry.bind("<KeyRelease>", self.check_fields)

        self.path_label = ttk.Label(self.form_frame, text="Path:")
        self.path_label.grid(row=1, column=0, padx=5, pady=5, sticky=tk.E)
        self.path_entry = ttk.Entry(self.form_frame)
        self.path_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        self.path_entry.bind("<KeyRelease>", self.check_fields)

        self.pattern_label = ttk.Label(self.form_frame, text="Pattern:")
        self.pattern_label.grid(row=2, column=0, padx=5, pady=5, sticky=tk.E)
        self.pattern_entry = ttk.Entry(self.form_frame)
        self.pattern_entry.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)
        self.pattern_entry.bind("<KeyRelease>", self.check_fields)

        self.type_label = ttk.Label(self.form_frame, text="Type:")
        self.type_label.grid(row=3, column=0, padx=5, pady=5, sticky=tk.E)
        self.type_combobox = ttk.Combobox(self.form_frame, values=["log", "config"], state='readonly', width=15)
        self.type_combobox.grid(row=3, column=1, padx=5, pady=5, sticky=tk.W)
        self.type_combobox.set("log")
        self.type_combobox.bind("<<ComboboxSelected>>", self.on_type_selected)

        self.format_label = ttk.Label(self.form_frame, text="Format:")
        self.format_combobox = ttk.Combobox(self.form_frame, values=["ini", "xml", "json", "yaml", "other"], state='readonly', width=15)
        self.format_label.grid(row=4, column=0, padx=5, pady=5, sticky=tk.E)
        self.format_combobox.grid(row=4, column=1, padx=5, pady=5, sticky=tk.W)

        self.button_frame = ttk.Frame(self.window)
        self.button_frame.grid(row=1, column=0, columnspan=2, pady=(10), sticky="s")

        self.save_button = ttk.Button(self.button_frame, text="Save", command=self.save_source, state="disabled")
        self.save_button.grid(row=0, column=0, padx=5, pady=5)

        if source_entry and not self.is_read_only:
            self.delete_button = ttk.Button(self.button_frame, text="Delete", command=self.delete_source)
            self.delete_button.grid(row=0, column=1, padx=5, pady=5)

        if source_entry:
            self.name_entry.insert(0, source_entry["name"])
            self.path_entry.insert(0, source_entry["path"])
            self.pattern_entry.insert(0, source_entry["pattern"])
            self.type_combobox.set(source_entry["type"])
            if "format" in source_entry:
                self.format_combobox.set(source_entry["format"])

            if self.is_read_only:
                self.name_entry.config(state="disabled")
                self.path_entry.config(state="disabled")
                self.pattern_entry.config(state="disabled")
                self.type_combobox.config(state="disabled")
                self.format_combobox.config(state="disabled")
        else:
            self.type_combobox.set("log")

        self.on_type_selected()
        self.check_fields()

    def on_type_selected(self, event=None):
        if self.type_combobox.get() == "config":
            self.format_label.grid()
            self.format_combobox.grid()
            self.format_combobox.set("other")
        else:
            self.format_label.grid_remove()
            self.format_combobox.grid_remove()

    def check_fields(self, event=None):
        if not self.is_read_only and self.name_entry.get() and self.path_entry.get() and self.pattern_entry.get():
            self.save_button.config(state="normal")
        else:
            self.save_button.config(state="disabled")

    def save_source(self):
        next_id = max([src["id"] for src in self.source_manager.all_sources], default=99) + 1
        if next_id < 100:
            next_id = 100

        source = {
            "id": self.source_entry["id"] if self.source_entry else next_id,
            "name": self.name_entry.get(),
            "path": self.path_entry.get(),
            "pattern": self.pattern_entry.get(),
            "type": self.type_combobox.get(),
            "creation_type": "user" if self.source_entry is None else self.source_entry["creation_type"]
        }
        if self.type_combobox.get() == "config":
            source["format"] = self.format_combobox.get()

        if self.source_entry:
            # Update existing entry
            for idx, src in enumerate(self.source_manager.user_sources):
                if src["id"] == self.source_entry["id"]:
                    self.source_manager.user_sources[idx] = source
                    break
            for idx, src in enumerate(self.source_manager.all_sources):
                if src["id"] == self.source_entry["id"]:
                    self.source_manager.all_sources[idx] = source
                    break
        else:
            # Add new entry
            self.source_manager.user_sources.append(source)
            self.source_manager.all_sources.append(source)
            self.source_manager.tab_order.append(source["id"])

        self.source_manager.load_sources()
        self.window.destroy()

    def delete_source(self):
        if self.source_entry:
            self.source_manager.user_sources = [src for src in self.source_manager.user_sources if src["id"] != self.source_entry["id"]]
            self.source_manager.all_sources = [src for src in self.source_manager.all_sources if src["id"] != self.source_entry["id"]]
            self.source_manager.tab_order.remove(self.source_entry["id"])
        self.source_manager.load_sources()
        self.window.destroy()

def main():
    current_version = 'v1.1.0'
    if platform.system() == "Windows":
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    root = tk.Tk()
    logger_class = get_logger_instance()
    if logger_class is not DummyLogger:
        custom_logger = logger_class(
            logger_name="LogViewerAppLogger",
            destinations=[
                {
                    'type': 'file',
                    'destination': "log_viewer_app.log",
                    'level': logging.DEBUG,
                },
                {
                    'type': 'console',
                    'level': logging.INFO,
                }
            ]
        )
    else:
        custom_logger = DummyLogger()

    app = LogViewerApp(root, current_version, custom_logger)
    root.mainloop()

if __name__ == '__main__':
    main()


