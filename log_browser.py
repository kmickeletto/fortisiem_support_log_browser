import subprocess
import sys

pip_packages = {
    'ttkthemes': 'ttkthemes',
    'Pillow': 'PIL',
    'paramiko': 'paramiko',
    'scp': 'scp',
    'sv_ttk': 'sv_ttk'
}

# List of standard library modules
standard_modules = [
    'tkinter', 'argparse', 'datetime', 'time', 're', 'glob', 'os',
    'ctypes', 'platform', 'base64', 'io', 'tempfile', 'uuid', 'tarfile',
    'gzip', 'shutil', 'threading', 'winreg', 'queue', 'textwrap', 'json',
    'itertools', 'collections', 'functools', 'gc', 'configparser'
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
    
import tkinter as tk
from tkinter import ttk, messagebox, font, PhotoImage, scrolledtext, filedialog
import tkinter.font as tkFont
from ttkthemes import ThemedTk
import argparse
from datetime import datetime, timedelta
import time
import re
import glob
import os
from PIL import Image, ImageTk
import ctypes
import platform
import base64
import io
import tempfile
import uuid
import sys
import tarfile
import gzip
import shutil
import threading
import winreg
import paramiko
from scp import SCPClient
import queue
import textwrap
import json
from itertools import cycle, count
from collections import defaultdict
import functools
import gc
import sv_ttk
import configparser

class Spinner(tk.Label):
    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.frames = None
        self.delay = 100
        self.idx = 0
        self.cancel = None
        self.running = False

    def load(self, im_path, width=None, height=None):
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
    def __init__(self, parent, hostname, username, password=None, key_filename=None, days=1, on_complete=None):
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
        self.parent.after(1000, self.check_queue)
        self.start_time = None

        self.parent.configure(background='black')
        self.parent.protocol("WM_DELETE_WINDOW", self.on_close)

        self.progress_bar = ttk.Progressbar(self.parent, orient='horizontal', length=400, mode='determinate')
        self.status_label = tk.Label(self.parent, text="", foreground='white', background='black')
        self.output_text = tk.Text(self.parent, height=20, width=80, bg='black', fg='white', insertbackground='white', padx=5, pady=5)  # Reduced padding
        self.output_text.pack()  # Reduced outer padding
        self.output_text.tag_configure('info', foreground='cyan')
        self.output_text.tag_configure('error', foreground='red')

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
            run_command = f"{command} {self.days}"
            self.execute_command(run_command)
            if self.command_successful:
                local_path = self.download_file('/tmp/AOLogs.tar', download_path)
                if local_path:
                    self.parent.after(0, lambda: result_queue.put(local_path))
                    if self.on_complete:
                        self.parent.after(0, self.on_complete)

    def connect(self):
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            self.client.connect(
                self.hostname,
                username=self.username,
                password=self.password,
                key_filename=self.key_filename,
                look_for_keys=False,
                compress=True,
                allow_agent=False,
                timeout=10,
                banner_timeout=200
            )
            
            transport = self.client.get_transport()
            transport.default_window_size = 2147483647
            transport.local_cipher = 'arcfour'
    
            self.scp = SCPClient(transport, progress=self.progress)
            self.connected = True
        except Exception as e:
            self.parent.after(0, lambda: self.safe_insert(f"Connection failed: {e}\n", "error"))
            self.connected = False

    def execute_command(self, command):
        if not self.is_alive():
            return  # Abort operation if GUI is not alive
        self.parent.after(0, lambda: self.safe_insert(f"Connecting to {self.hostname}\n", 'info'))
        try:
            print(command)
            stdin, stdout, stderr = self.client.exec_command(command)
            stderr_output = []
            while True:
                if not self.is_alive():
                    break
                # Handle stdout
                line = stdout.readline()
                if line:
                    self.parent.after(0, lambda: self.safe_insert(line))
                # Handle stderr in a non-blocking way
                error_line = stderr.readline()
                if error_line:
                    stderr_output.append(error_line)
    
                # Exit the loop if the command has completed
                if stdout.channel.exit_status_ready():
                    break
            
            # Check exit status after command execution
            exit_status = stdout.channel.recv_exit_status()
            if exit_status == 0:
                self.command_successful = True
            else:
                self.command_successful = False
                if stderr_output:  # Check if there is any collected stderr output
                    error_message = ''.join(stderr_output)
                    self.parent.after(0, lambda: self.safe_insert(f"Command failed with exit status {exit_status}: {error_message}\n", "error"))
                else:
                    self.parent.after(0, lambda: self.safe_insert(f"Command failed with exit status {exit_status}\n", "error"))
        except Exception as e:
            self.parent.after(0, lambda: self.safe_insert(f"Failed to execute command: {e}\n", "error"))
            self.command_successful = False
        
    def download_file(self, remote_path, local_path):
        self.remote_path = remote_path
        self.start_time = time.time()
        self.progress_bar.pack(pady=20)
        self.status_label.pack(pady=10)

        try:
            self.scp.get(remote_path, local_path, preserve_times=True)
            return local_path
        except Exception as e:
            self.parent.after(0, lambda: self.safe_insert(f"\nFailed to download file: {e}\n", "error"))
            return False

    def progress(self, filename, size, sent):
        if not self.is_alive():
            return
            
        current_time = time.time()
        elapsed_time = current_time - self.start_time
        size_mb = size / (1024 * 1024)
        sent_mb = sent / (1024 * 1024)
        progress = (sent_mb / size_mb) * 100
        
        if elapsed_time > 0:
            transfer_rate = (sent * 8) / (1024 * 1024 * elapsed_time)
    
        self.parent.after(0, lambda: self.update_progress_bar(progress, size_mb, transfer_rate))
    
    def update_progress_bar(self, progress, size_mb, transfer_rate):
        self.progress_bar['value'] = progress
        self.status_label['text'] = f"Downloading: {self.remote_path} - {size_mb:.2f} MB ({int(progress)}% complete) / {transfer_rate:.2f} Mbps"
        if progress >= 100:
            self.status_label['text'] = f"{self.remote_path} downloaded successfully - {size_mb:.2f} MB transferred / {transfer_rate:.2f} Mbps"
        self.parent.update_idletasks()

    def is_alive(self):
        try:
            return self.parent.winfo_exists()
        except RuntimeError:
            return False

    def safe_insert(self, text, tag=None):
        if self.is_alive():
            fixed_width = 80
    
            wrapped_text = textwrap.fill(text, width=fixed_width)
            
            self.output_text.insert(tk.END, wrapped_text + '\n', tag)
            self.output_text.see(tk.END)
            self.output_text.update_idletasks()

    def on_close(self):
        self.close()
        self.parent.destroy()

    def close(self):
        if self.client:
            self.client.close()
        if self.scp:
            self.scp.close()
        self.connected = False
        
class SSHCredentialsForm(tk.Frame):
    def __init__(self, parent, callback=None, theme="light"):
        super().__init__(parent)
        self.parent = parent
        self.callback = callback
        self.theme = theme
        self.parent.geometry('600x250')
        self.parent.title("Enter the host and credentials")
        self.pack(padx=10, pady=10)
        self.apply_theme()  # Apply the Sun-Valley theme
        self.init_ui()
        self.load_credentials()
        
    def apply_theme(self):
        sv_ttk.use_dark_theme() if self.theme == "dark" else sv_ttk.use_light_theme()

    def load_credentials(self):
        creds_file = 'creds.json'
        if os.path.exists(creds_file):
            with open(creds_file, 'r') as file:
                creds = json.load(file)
                self.hostname_entry.insert(0, creds.get('hostname', ''))
                self.username_entry.insert(0, creds.get('username', ''))
                if 'password' in creds:
                    self.password_entry.insert(0, creds.get('password', ''))
                    self.auth_var.set('password')
                    self.toggle_auth_method()
                elif 'keyfile' in creds:
                    self.key_entry.insert(0, creds.get('keyfile', ''))
                    self.auth_var.set('key')
                    self.toggle_auth_method()
            self.validate_inputs()

    def init_ui(self):
        self.auth_var = tk.StringVar(value='password')

        # Use ttk widgets for Sun-Valley theme
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

    def update_days_label(self, value):
        self.days_value.set(str(int(float(value))))

    def validate_inputs(self, event=None):
        if self.hostname_entry.get().strip() and self.username_entry.get().strip():
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

    def browse_keyfile(self):
        default_dir = os.path.expanduser('~/.ssh')

        # Check if ~/.ssh directory exists
        if not os.path.isdir(default_dir):
            default_dir = os.getcwd()

        # Determine default file type
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

class FSMLogsExtractorApp(tk.Tk):
    def __init__(self, tarball, force, theme="light"):
        super().__init__()
        self.title("FSM Logs Extractor")
        self.geometry('900x400')

        self.theme = theme

        self.attributes('-topmost', True)
        self.output_text = scrolledtext.ScrolledText(self, width=100, height=15)
        self.output_text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        progress_frame = ttk.Frame(self)
        progress_frame.pack(padx=10, pady=5, fill=tk.X, expand=False)

        self.progress_bar = ttk.Progressbar(progress_frame, orient='horizontal', mode='determinate', length=400, style="Custom.Horizontal.TProgressbar")
        self.progress_bar.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.progress_label = ttk.Label(progress_frame, text="0%", width=10, style="Custom.TLabel")
        self.progress_label.pack(side=tk.RIGHT, padx=5)

        self.protocol("WM_DELETE_WINDOW", self.on_close_extract)

        self.apply_theme(theme)

        self.tarball = tarball
        self.force = force
        self.thread = threading.Thread(target=self.extract_tarball)
        self.thread.start()

    def apply_theme(self, theme):
        if theme == "dark":
            sv_ttk.use_dark_theme()
            self.output_text.configure(bg='#2e2e2e', fg='white', insertbackground='white')
        else:
            sv_ttk.use_light_theme()
            self.output_text.configure(bg='white', fg='black', insertbackground='black')

        style = ttk.Style()
        
        # Configure styles for dark and light themes
        if theme == "dark":
            style.configure("Custom.TLabel", background='#2e2e2e', foreground='white')
            style.configure("TFrame", background='#2e2e2e')
            style.configure("Custom.Horizontal.TProgressbar",
                            troughcolor='#404040',
                            background='#00BFFF',
                            thickness=20)
            self.configure(bg='#2e2e2e')
        else:
            style.configure("Custom.TLabel", background='white', foreground='black')
            style.configure("TFrame", background='white')
            style.configure("Custom.Horizontal.TProgressbar",
                            troughcolor='lightgray',
                            background='#0078D7',
                            thickness=20)
            self.configure(bg='white')

    def extract_tarball(self):
        tarball_dir = os.path.dirname(self.tarball)
        dir_name = os.path.splitext(os.path.basename(self.tarball))[0]
        output_path = os.path.join(tarball_dir, dir_name)

        if os.path.exists(output_path) and not self.force:
            self.prompt_overwrite(output_path)
        else:
            self.process_extraction(output_path)

    def prompt_overwrite(self, path):
        self.lower()

        overwrite_window = tk.Toplevel(self)
        overwrite_window.title("Directory exists")
        overwrite_window.geometry("300x150")
        overwrite_window.configure(bg='#2e2e2e' if self.theme == "dark" else 'white')

        message_label = tk.Label(overwrite_window, text=f"The directory {path} already exists. Do you want to overwrite it?",
                                 bg='#2e2e2e' if self.theme == "dark" else 'white',
                                 fg='white' if self.theme == "dark" else 'black', wraplength=280)
        message_label.pack(padx=20, pady=20)

        button_frame = tk.Frame(overwrite_window, bg='#2e2e2e' if self.theme == "dark" else 'white')
        button_frame.pack(padx=20, pady=10)

        yes_button = tk.Button(button_frame, text="Yes", command=lambda: self._overwrite_path(path, overwrite_window),
                               bg='#404040' if self.theme == "dark" else 'lightgray',
                               fg='white' if self.theme == "dark" else 'black')
        no_button = tk.Button(button_frame, text="No", command=overwrite_window.destroy,
                              bg='#404040' if self.theme == "dark" else 'lightgray',
                              fg='white' if self.theme == "dark" else 'black')

        yes_button.grid(row=0, column=0, padx=5)
        no_button.grid(row=0, column=1, padx=5)

    def _overwrite_path(self, path, window):
        shutil.rmtree(path)
        self.process_extraction(path)
        window.destroy()

    def process_extraction(self, output_path):
        processed_files = 0
        try:
            with tarfile.open(self.tarball, 'r') as tar:
                tar.extractall(path=output_path)
                self.update_gui(f"Extracting into: {output_path}")

            aologs_subdir = os.path.join(output_path, 'AOLogs')
            if os.path.exists(aologs_subdir):
                for item in os.listdir(aologs_subdir):
                    s = os.path.join(aologs_subdir, item)
                    d = os.path.join(output_path, item)
                    shutil.move(s, d)
                os.rmdir(aologs_subdir)

            total_files = sum(len(files) for _, _, files in os.walk(output_path))
            for root, dirs, files in os.walk(output_path):
                for file in files:
                    if file.endswith('.gz'):
                        gz_file_path = os.path.join(root, file)
                        extract_path, _ = os.path.splitext(gz_file_path)

                        dir_path, filename = os.path.split(extract_path)
                        if '.log' in filename:
                            filename = filename.replace('.log', '') + '.log'
                        if '_log' in filename:
                            filename = filename.replace('_log', '') + '.log'
                        if '.gz' in filename:
                            filename = filename.replace('.gz', '')
                        extract_path = os.path.join(dir_path, filename)
                        print(f"{gz_file_path} => {extract_path}")
                        with gzip.open(gz_file_path, 'rb') as f_in:
                            with open(extract_path, 'wb') as f_out:
                                shutil.copyfileobj(f_in, f_out)
                        os.remove(gz_file_path)
                        relative_path = os.path.relpath(extract_path, start=os.getcwd())
                        self.update_gui(f"Processed: {relative_path}")

                    processed_files += 1
                    self.update_progress(processed_files / total_files * 100)
            if hasattr(self, 'on_extraction_complete'):
                self.on_extraction_complete(output_path)

            self.after(100, self.destroy)  # Schedule the destroy method to be called safely

        except Exception as e:
            self.update_gui(f"An error occurred: {e}")

    def update_gui(self, message):
        self.after(0, lambda: self._safe_update_gui(message))

    def _safe_update_gui(self, message):
        self.output_text.insert(tk.END, message + '\n')
        self.output_text.yview(tk.END)

    def update_progress(self, progress):
        self.after(0, lambda: self._safe_update_progress(progress))

    def _safe_update_progress(self, progress):
        self.progress_bar['value'] = progress
        self.progress_label['text'] = f"{int(progress)}%"

    def on_close_extract(self):
        if threading.active_count() > 1:
            response = messagebox.askyesno("Quit", "Extraction is running. Do you really want to quit?")
            if response:
                self.attributes('-topmost', False)
                self.destroy()
        else:
            self.attributes('-topmost', False)
            self.destroy()
            
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
                if log_type == "backend":
                    date_match = date_pattern.search(line)
                elif log_type == "appserver":
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
    CONFIG_FILE_PATH = os.path.join(os.path.expanduser("~"), ".fortisiem_log_viewer.json")
    
    def __init__(self, root):
        self.root = root
        self.root.title("FortiSIEM Support Log Viewer")
        self.ssh_used = False
        self.ssh_objects = []
        self.logbase = None
        self.date_to_logs = {}
        self.systeminfo = {}
        self.networks = []
        self.load_event = threading.Event()
        self.spinner = Spinner(self.root)
        self.spinner.load('spinner-dark.gif', 48, 48)
        self.set_app_icon('fortisiem.png')
        self.root.geometry('1080x750')
        self.root.minsize(800, 600)
        self.initialize_font()
        self.initialize_widgets()
        self.initialize_gui()
        self.initialize_menu()
        self.apply_styles()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.apply_saved_theme()

    def save_theme_preference(self, theme_name):
        config_data = {"Theme": theme_name}
        try:
            with open(self.CONFIG_FILE_PATH, 'w') as config_file:
                json.dump(config_data, config_file)
        except Exception as e:
            print(f"Error saving theme to config file: {e}")

    def load_theme_preference(self):
        try:
            if not os.path.exists(self.CONFIG_FILE_PATH):
                # Create the config file with default theme if it doesn't exist
                self.save_theme_preference("light")
            
            with open(self.CONFIG_FILE_PATH, 'r') as config_file:
                config_data = json.load(config_file)
                theme_name = config_data.get("Theme")
                return theme_name
        except Exception as e:
            print(f"Error loading theme from config file: {e}")
            return "light"

    def apply_theme(self, theme_name):
        sv_ttk.set_theme(theme_name)
        self.update_spinner(theme_name)
        self.apply_font_styles()
        self.save_theme_preference(theme_name)
        self.update_theme_menu(theme_name)
    
    def apply_system_theme(self):
        theme = self.detect_system_theme()
        sv_ttk.set_theme(theme)
        self.update_spinner(theme)
        self.apply_font_styles()
        self.save_theme_preference("system")
        self.update_theme_menu("system")

    def apply_saved_theme(self):
        saved_theme = self.load_theme_preference()
        if saved_theme == "system":
            self.apply_system_theme()
        else:
            self.apply_theme(saved_theme)

    def update_theme_menu(self, theme_name):
        bullet = "\u2022"  # Unicode bullet character
        self.preferences_menu.entryconfig(0, label=f"{bullet} Light Theme" if theme_name == "light" else "  Light Theme")
        self.preferences_menu.entryconfig(1, label=f"{bullet} Dark Theme" if theme_name == "dark" else "  Dark Theme")
        self.preferences_menu.entryconfig(2, label=f"{bullet} System Theme" if theme_name == "system" else "  System Theme")

    def detect_system_theme(self):
        if platform.system() == "Windows":
            # Detect system theme on Windows
            import winreg
            try:
                registry = winreg.ConnectRegistry(None, winreg.HKEY_CURRENT_USER)
                key = winreg.OpenKey(registry, r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize")
                value, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
                winreg.CloseKey(key)
                return "light" if value == 1 else "dark"
            except Exception as e:
                print(f"Error detecting Windows theme: {e}")
                return "light"  # Default to light theme if detection fails
        elif platform.system() == "Darwin":
            # Detect system theme on macOS
            try:
                from subprocess import check_output
                result = check_output(
                    ['defaults', 'read', '-g', 'AppleInterfaceStyle']
                ).strip().decode('utf-8')
                return "dark" if result == "Dark" else "light"
            except Exception as e:
                print(f"Error detecting macOS theme: {e}")
                return "light"  # Default to light theme if detection fails
        else:
            # Default to light theme for other operating systems
            return "light"
            
    def center_spinner(self):
        self.spinner.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        self.spinner.lift()
        
    def update_spinner(self, theme_name):
        spinner_file = 'spinner-dark.gif' if theme_name == 'dark' else 'spinner-light.gif'
        self.spinner.load(spinner_file, 48, 48)
        self.center_spinner()
        
    def apply_font_styles(self):
        # Reapply font styles to ensure consistency after theme change
        self.output_text.config(font=self.standard_font)
        self.status_label.config(font=self.standard_font)
        self.hostname_value.config(font=self.header_font)
        self.role_value.config(font=self.header_font)
        self.ip_value.config(font=self.header_font)
        self.version_value.config(font=self.header_font)
        self.dropdown.config(font=(self.font_family, 11))

    def initialize_font(self):
        self.font_family = "Arial"
        self.standard_font = tkFont.Font(family=self.font_family, size=10)
        self.bold_font = tkFont.Font(family=self.font_family, weight="bold")
        self.header_font = tkFont.Font(family=self.font_family, size=10, weight="bold")

    def apply_styles(self):
        style = ttk.Style(self.root)
        style.configure('.', font=self.standard_font)
        style.configure('TLabel', font=self.standard_font)
        style.configure('TButton', font=self.standard_font)
        style.configure('TEntry', font=self.standard_font)
        style.configure('TFrame', background='SystemButtonFace')
        
        # Styling for headers
        style.configure("Header.TLabel", font=self.standard_font)
        style.configure("HeaderValue.TLabel", font=self.standard_font)
        style.configure("SubHeader.TLabel", font=self.header_font)
        
        # Ensure Combobox entry field is also styled using theme defaults
        style.configure("TCombobox", fieldbackground='SystemButtonFace', foreground='SystemWindowText')
        style.map('TCombobox', 
                fieldbackground=[('readonly', 'SystemButtonFace'), ('!focus', 'SystemButtonFace'), ('readonly hover', 'SystemButtonFace'), ('readonly focus', 'SystemButtonFace')],
                foreground=[('readonly', 'SystemWindowText'), ('!focus', 'SystemWindowText'), ('readonly hover', 'SystemWindowText'), ('readonly focus', 'SystemWindowText')])
        
        # Additional styling for dark theme
        current_theme = sv_ttk.get_theme()
        if current_theme == 'dark':
            style.configure('.', background='black', foreground='white')
            style.configure('TLabel', background='black', foreground='white')
            style.configure('TFrame', background='black')
            style.configure('TCombobox', fieldbackground='black', foreground='white')
            style.map('TCombobox', 
                    fieldbackground=[('readonly', 'black'), ('!focus', 'black'), ('readonly hover', 'black'), ('readonly focus', 'black')],
                    foreground=[('readonly', 'white'), ('!focus', 'white'), ('readonly hover', 'white'), ('readonly focus', 'white')])
            if hasattr(self, 'output_text'):
                self.output_text.config(bg='black', fg='white', insertbackground='white')
            if hasattr(self, 'status_label'):
                self.status_label.config(foreground='white', background='black')
        else:
            style.configure('.', background='SystemButtonFace', foreground='SystemWindowText')
            style.configure('TLabel', background='SystemButtonFace', foreground='SystemWindowText')
            style.configure('TFrame', background='SystemButtonFace')
            style.configure('TCombobox', fieldbackground='SystemButtonFace', foreground='SystemWindowText')
            style.map('TCombobox', 
                    fieldbackground=[('readonly', 'SystemButtonFace'), ('!focus', 'SystemButtonFace'), ('readonly hover', 'SystemButtonFace'), ('readonly focus', 'SystemButtonFace')],
                    foreground=[('readonly', 'SystemWindowText'), ('!focus', 'SystemWindowText'), ('readonly hover', 'SystemWindowText'), ('readonly focus', 'SystemWindowText')])
        
        # Use the Defined Style to remove the dashed line from Tabs
        style.layout("Tab", [('Notebook.tab', {'sticky': 'nswe', 'children':
        [('Notebook.padding', {'side': 'top', 'sticky': 'nswe', 'children':
            [('Notebook.label', {'side': 'top', 'sticky': ''})],
        })],
        })]
        )
        
        style.configure("Tab", focuscolor=style.configure(".")["background"])

    def initialize_widgets(self):
        # Initialize the widgets
        self.output_text = tk.Text(self.root, height=20, width=80, padx=5, pady=5, font=self.standard_font)
        self.status_label = tk.Label(self.root, text="", font=self.standard_font)
        self.progress_bar = ttk.Progressbar(self.root, orient='horizontal', length=400, mode='determinate')

    def initialize_gui(self):
        # Define the style for LabelFrame without a border
        style = ttk.Style()
        style.configure("NoBorder.TLabelframe")
        style.configure("NoBorder.TLabelframe.Label", borderwidth=0)
        style.configure("Custom.Treeview", 
                        borderwidth=0, 
                        highlightthickness=0)
    
        style.layout("Custom.Treeview", [('Treeview.treearea', {'sticky': 'nswe'})])
    
        # Create the system information section
        self.header_frame = ttk.LabelFrame(self.root, text="System Information")
        self.header_frame.pack(fill='x', padx=10, pady=10)
    
        # Creating the table structure using grid layout
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
    
        # Create a notebook widget (tabbed interface) below the system information
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=(0, 10))
    
        # Create the first tab for App/Backend Logs
        self.tab_logs = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_logs, text='App/Backend Logs')
    
        frame_top = ttk.LabelFrame(self.tab_logs, text="Date")
        frame_top.pack(fill='x', padx=10, pady=10)
    
        self.selected_date = tk.StringVar()
        ttk.Label(frame_top, style="Header.TLabel").pack(side='left', padx=5, pady=5)
    
        dates = sorted(self.date_to_logs.keys())
        self.dropdown = ttk.Combobox(frame_top, textvariable=self.selected_date, style='Custom.TCombobox', state='readonly', font=(self.standard_font, 11), values=dates)
        self.dropdown.pack(side='left', fill='x', expand=True, padx=5, pady=(0,5))
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
    
        self.initialize_conditional_tabs()
        
    def initialize_conditional_tabs(self):
        if self.logbase is None:
            return  # Ensure logbase is initialized

        # Ensure phoenix_config.txt tab is only created if it doesn't exist and the file is available
        if not hasattr(self, 'config_text') and os.path.exists(os.path.join(self.logbase, 'configCollection')):
            self.tab_config = ttk.Frame(self.notebook)
            self.notebook.add(self.tab_config, text='phoenix_config.txt')
    
            self.hide_comments_var = tk.BooleanVar(value=False)
            self.hide_comments_toggle = ttk.Checkbutton(self.tab_config, text="Remove comment and blank lines", variable=self.hide_comments_var, command=self.load_phoenix_config, style="Switch.TCheckbutton")
            self.hide_comments_toggle.pack(anchor='w', padx=10, pady=5)
    
            self.config_text = tk.Text(self.tab_config, wrap='word', state='disabled')
            self.config_text.pack(fill='both', expand=True, padx=10, pady=10)
    
            self.config_scrollbar = ttk.Scrollbar(self.config_text, orient='vertical', command=self.config_text.yview)
            self.config_scrollbar.pack(side='right', fill='y')
            self.config_text['yscrollcommand'] = self.config_scrollbar.set
    
        if os.path.exists(os.path.join(self.logbase, 'appsvr', 'server.log')):
            self.tab_server = ttk.Frame(self.notebook)
            self.notebook.add(self.tab_server, text='server.log')
    
            self.server_file_var = tk.StringVar()
            self.server_combobox = ttk.Combobox(self.tab_server, textvariable=self.server_file_var, state='readonly', style='Custom.TCombobox', font=(self.font_family, 11))
            self.server_combobox.pack(fill='x', padx=10, pady=10)
            self.server_combobox.bind("<<ComboboxSelected>>", lambda e: self.load_log_file(os.path.join(self.logbase, 'appsvr', self.server_combobox.get()), self.server_text))
    
            self.server_text = tk.Text(self.tab_server, wrap='word', state='disabled')
            self.server_text.pack(fill='both', expand=True, padx=10, pady=10)
            
            self.server_scrollbar = ttk.Scrollbar(self.server_text, orient='vertical', command=self.server_text.yview)
            self.server_scrollbar.pack(side='right', fill='y')
            self.server_text['yscrollcommand'] = self.server_scrollbar.set
    
        if os.path.exists(os.path.join(self.logbase, 'backend', 'archiver.log')):
            self.tab_archiver = ttk.Frame(self.notebook)
            self.notebook.add(self.tab_archiver, text='archiver.log')
    
            self.archiver_text = tk.Text(self.tab_archiver, wrap='word', state='disabled')
            self.archiver_text.pack(fill='both', expand=True, padx=10, pady=10)
            
            self.archiver_scrollbar = ttk.Scrollbar(self.archiver_text, orient='vertical', command=self.archiver_text.yview)
            self.archiver_scrollbar.pack(side='right', fill='y')
            self.archiver_text['yscrollcommand'] = self.archiver_scrollbar.set
    
        if os.path.exists(os.path.join(self.logbase, 'backend', 'svnlite.log')):
            self.tab_svnlite = ttk.Frame(self.notebook)
            self.notebook.add(self.tab_svnlite, text='svnlite.log')
    
            self.svnlite_file_var = tk.StringVar()
            self.svnlite_combobox = ttk.Combobox(self.tab_svnlite, textvariable=self.svnlite_file_var, state='readonly', style='Custom.TCombobox', font=(self.font_family, 11))
            self.svnlite_combobox.pack(fill='x', padx=10, pady=10)
            self.svnlite_combobox.bind("<<ComboboxSelected>>", lambda e: self.load_log_file(os.path.join(self.logbase, 'backend', self.svnlite_combobox.get()), self.svnlite_text))
    
            self.svnlite_text = tk.Text(self.tab_svnlite, wrap='word', state='disabled')
            self.svnlite_text.pack(fill='both', expand=True, padx=10, pady=10)
            
            self.svnlite_scrollbar = ttk.Scrollbar(self.svnlite_text, orient='vertical', command=self.svnlite_text.yview)
            self.svnlite_scrollbar.pack(side='right', fill='y')
            self.svnlite_text['yscrollcommand'] = self.svnlite_scrollbar.set
    
        if os.path.exists(os.path.join(self.logbase, 'postgres', 'postgresql.log')):
            self.tab_postgresql = ttk.Frame(self.notebook)
            self.notebook.add(self.tab_postgresql, text='postgresql.log')
    
            self.postgresql_file_var = tk.StringVar()
            self.postgresql_combobox = ttk.Combobox(self.tab_postgresql, textvariable=self.postgresql_file_var, state='readonly', style='Custom.TCombobox', font=(self.font_family, 11))
            self.postgresql_combobox.pack(fill='x', padx=10, pady=10)
            self.postgresql_combobox.bind("<<ComboboxSelected>>", lambda e: self.load_log_file(os.path.join(self.logbase, 'postgres', self.postgresql_combobox.get()), self.postgresql_text))
    
            self.postgresql_text = tk.Text(self.tab_postgresql, wrap='word', state='disabled')
            self.postgresql_text.pack(fill='both', expand=True, padx=10, pady=10)
            
            self.postgresql_scrollbar = ttk.Scrollbar(self.postgresql_text, orient='vertical', command=self.postgresql_text.yview)
            self.postgresql_scrollbar.pack(side='right', fill='y')
            self.postgresql_text['yscrollcommand'] = self.postgresql_scrollbar.set

    def toggle_comments(self):
        if not self.logbase:
            return
        
        config_dir = os.path.join(self.logbase, 'configCollection')
        if os.path.exists(config_dir):
            for file_name in os.listdir(config_dir):
                if file_name.startswith('phoenix_config') and file_name.endswith('.txt'):
                    config_file_path = os.path.join(config_dir, file_name)
                    with open(config_file_path, 'r', encoding='ISO-8859-1') as file:
                        content = file.readlines()
                    
                    if self.hide_comments_var.get():
                        content = [line for line in content if not line.strip().startswith("#")]
    
                    cleaned_content = self.clean_ini_content(''.join(content))
    
                    self.config_text.config(state='normal')
                    self.config_text.delete('1.0', tk.END)
                    self.config_text.insert(tk.END, cleaned_content)
                    self.config_text.config(state='disabled')
                    break

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

        cleaned_content = "\n".join(cleaned_lines)
        return cleaned_content

    def load_phoenix_config(self):
        if not self.logbase:
            return

        config_dir = os.path.join(self.logbase, 'configCollection')
        if os.path.exists(config_dir):
            for file_name in os.listdir(config_dir):
                if file_name.startswith('phoenix_config') and file_name.endswith('.txt'):
                    config_file_path = os.path.join(config_dir, file_name)
                    with open(config_file_path, 'r', encoding='ISO-8859-1') as file:
                        content = file.read()
                    
                    if self.hide_comments_var.get():
                        content = self.clean_ini_content(content)
                    
                    self.config_text.config(state='normal')
                    self.config_text.delete('1.0', tk.END)
                    self.config_text.insert(tk.END, content)
                    self.config_text.config(state='disabled')
                    break

    def load_system_info_and_logs(self):
        def load():
            self.update_system_info()  # Load system info
            self.organize_logs()       # Organize logs
            self.root.after(0, self.update_datechooser)  # Update the combobox with dates
            self.root.after(0, self.load_logs)        # Load logs for the selected date
            self.root.after(0, self.load_phoenix_config)  # Load the config file content
            self.root.after(0, self.update_file_combobox, os.path.join(self.logbase, 'appsvr'), 'server*.log', self.server_combobox, 'server.log', self.server_text)
            self.root.after(0, self.update_file_combobox, os.path.join(self.logbase, 'backend'), 'svnlite*.log', self.svnlite_combobox, 'svnlite.log', self.svnlite_text)
            self.root.after(0, self.load_log_file, os.path.join(self.logbase, 'backend', 'archiver.log'), self.archiver_text)
            self.file_menu.entryconfig("Close current log", state=tk.NORMAL)
            self.root.after(0, self.spinner.stop)
    
        # Start the spinner before loading logs
        self.spinner.start()
        self.center_spinner()
        
        # Run the load function in a separate thread
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

    def update_file_combobox(self, directory, pattern, combobox, default_file, text_widget):
        try:
            log_files = sorted(glob.glob(os.path.join(directory, pattern)), key=lambda x: os.path.basename(x))
            filenames = [os.path.basename(f) for f in log_files]
            combobox['values'] = filenames
            if default_file in filenames:
                combobox.set(default_file)
            else:
                combobox.set(filenames[0])
            self.load_log_file(os.path.join(directory, combobox.get()), text_widget)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load log files: {e}")

    def setup_treeview(self, parent, type):
        tree = ttk.Treeview(parent, columns=("Count", "First Seen", "Last Seen", "Event Type", "Process", "File", "Line"), 
                            show="headings", 
                            selectmode='extended', 
                            style="Custom.Treeview") 

        # Setting up columns with initial sort direction arrows
        for col in tree['columns']:
            # Initialize each column heading without arrows
            tree.heading(col, text=col, command=functools.partial(self.treeview_sort_column, tree, False, col))
            if col in ["Count", "Line"]:
                tree.column(col, anchor='e', stretch=False, width=50)
            elif col in ["First Seen", "Last Seen"]:
                tree.column(col, anchor='center', width=50)
            else:
                tree.column(col, anchor='w', stretch=True)

        scroll_y = ttk.Scrollbar(parent, orient='vertical', command=tree.yview)
        scroll_y.pack(side='right', fill='y', padx=(1,1), pady=(30,5))
        tree.configure(yscrollcommand=scroll_y.set)
        tree.pack(fill='both', expand=True, padx=(4,4), pady=(4,4))
        tree.bind("<Double-1>", self.on_double_click)

        if type == 'backend':
            self.tree_backend = tree
        else:
            self.tree_appsvr = tree

    def set_app_icon(self, image_path):
        # Set the AppID for better Windows taskbar handling
        app_id = u'fortinet.fortisiem.log'
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(app_id)

        # Load the image from the provided path and setting it as the icon
        image = Image.open(image_path)
        image = image.resize((64, 64), Image.Resampling.LANCZOS)
        self.photo = ImageTk.PhotoImage(image)
        self.root.iconphoto(True, self.photo)

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

        # Create Edit menu
        edit_menu = tk.Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="Edit", menu=edit_menu)
        
        # Add Preferences submenu
        self.preferences_menu = tk.Menu(edit_menu, tearoff=0)
        edit_menu.add_cascade(label="Preferences", menu=self.preferences_menu)
        self.preferences_menu.add_command(label="Light Theme", command=lambda: self.apply_theme("light"))
        self.preferences_menu.add_command(label="Dark Theme", command=lambda: self.apply_theme("dark"))
        self.preferences_menu.add_command(label="System Default", command=self.apply_system_theme)

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

    def on_close(self):
        self.cleanup()
        self.root.destroy()

    def cleanup(self):
        temp_dir = tempfile.gettempdir()
    
        # Check if logbase is in the temporary directory
        if self.logbase and os.path.commonpath([self.logbase, temp_dir]) == temp_dir:
            try:
                shutil.rmtree(self.logbase)  # Attempt to delete the directory
            except Exception as e:
                pass
    
        # Check if file_path is in the temporary directory
        if hasattr(self, 'file_path') and self.file_path and os.path.commonpath([self.file_path, temp_dir]) == temp_dir:
            try:
                os.remove(self.file_path)  # Attempt to delete the file
            except Exception as e:
                pass
            
        # Clear any current open grid data
        self.tree_backend.delete(*self.tree_backend.get_children())
        self.tree_appsvr.delete(*self.tree_appsvr.get_children())
        
        # Clear log data
        self.logbase = None
        self.backend_logs = []
        self.appserver_logs = []
    
        # Clear system information header
        self.systeminfo.clear()
        self.networks.clear()
        self.update_system_info_header()
    
        # Clear dates in the combobox
        self.date_to_logs.clear()
        self.update_datechooser()
        
        # Clear sorts
        self.treeview_sort_column(self.tree_backend, False, None)
        self.treeview_sort_column(self.tree_appsvr, False, None)
        
        self.file_menu.entryconfig("Close current log", state=tk.DISABLED)
        
        # Disable UI elements
        self.update_ui_elements('disabled')
        
        gc.collect()

    def handle_result(self, download_path):
        if download_path:
            self.file_path = download_path
            self.launch_extractor()
            try:
                if self.root.winfo_exists() and self.dropdown.winfo_exists():
                    self.update_ui_elements('readonly')
            except tk.TclError:
                pass
    
    def fetch_ssh_logs(self):
        self.update_ui_elements('disabled')
        current_theme = sv_ttk.get_theme()  # Get the current theme
        top_level_window = tk.Toplevel(self.root)
        form = SSHCredentialsForm(top_level_window, callback=self.handle_credentials, theme=current_theme)
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
        self.root.after(100, lambda: self.start_ssh_client(credentials))

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
            on_complete=self.on_ssh_complete
        )

        # Ensure the SSHClient window is modal to the main window
        self.ssh_window.transient(self.root)
        self.ssh_window.grab_set()
        self.ssh_window.focus_set()

        # Center the SSHClient window over the main window
        self.set_initial_window_position(self.ssh_window)

        self.cleanup()
        self.ssh_client.start_operations('phziplogs /tmp', self.download_path, self.result_queue)
        self.root.wait_window(self.ssh_window)

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

    def open_file(self):
        self.file_path = filedialog.askopenfilename(title="Open Log File", filetypes=[("TAR files", "*.tar")])
        if not self.file_path:
            return  # User cancelled the dialog
        self.cleanup()
        self.update_ui_elements('disabled')
        self.launch_extractor()
        
    def open_existing(self):
        directory = filedialog.askdirectory(title='Select the directory containing the extracted logs')
        if not directory:
            return  # User cancelled the dialog or closed the window
    
        # Check if the selected directory contains the 'backend' directory
        if not os.path.isdir(os.path.join(directory, 'backend')):
            messagebox.showerror("Error", "Selected directory does not appear to be a valid log directory")
            self.cleanup()
            return  # Exit if the 'backend' directory is not found
    
        self.cleanup()
        self.update_ui_elements('disabled')
        self.logbase = directory
        self.load_system_info_and_logs()
        self.update_ui_elements('readonly')

    def launch_extractor(self):
        if not self.file_path or not os.path.exists(self.file_path):
            return
    
        # Check if the tarball contains the 'backend' directory
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
                return  # User does not want to overwrite; do nothing
        else:
            self.create_extractor_window()

    def create_extractor_window(self):
        current_theme = sv_ttk.get_theme()
        extractor_app = FSMLogsExtractorApp(self.file_path, force=True, theme=current_theme)
        extractor_app.on_extraction_complete = self.handle_extraction_complete  # Ensure callback is set
        extractor_app.mainloop()
    
    def handle_extraction_complete(self, extracted_path):
        self.logbase = extracted_path
        self.load_system_info_and_logs()
        self.update_ui_elements('readonly')
    
    def update_datechooser(self):
        dates = sorted(self.date_to_logs.keys())
        self.dropdown['values'] = dates
        if len(dates) > 0:
            self.latest_date = dates[-1]
            self.dropdown.set(self.latest_date)
            self.root.after(100, self.load_logs)
        else:
            self.dropdown.set('')

    def extract_date_from_content(self, file_path):
        try:
            with open(file_path, 'r') as file:
                first_line = file.readline()
                backlogs_pattern = re.search(r'(\d{4}-\d{2}-\d{2})T\d{2}:\d{2}:\d{2}\.\d{6}-\d{2}:\d{2}', first_line)
                appsvr_pattern = re.search(r'(\d{4}-\d{2}-\d{2}) \d{2}:\d{2}:\d{2},\d{3}', first_line)
    
                if backlogs_pattern:
                    timestamp = datetime.strptime(backlogs_pattern.group(1), '%Y-%m-%d')
                    return timestamp.strftime('%Y-%m-%d')
                elif appsvr_pattern:
                    return appsvr_pattern.group(1)
        except Exception as e:
            print(f"Error reading {file_path}: {e}")
        return None

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
                    if file_name.startswith('phoenix') and file_name.endswith('.log'):
                        file_path = os.path.join(path, file_name)
                        log_type = 'backend' if directory == 'backend' else 'appserver'
                        start_date, end_date = parser.extract_date_range(file_path, log_type)
                        
                        if start_date and end_date:
                            current_date = start_date
                            while current_date <= end_date:
                                date_str = current_date.strftime('%Y-%m-%d')
                                date_to_logs[date_str].append(file_path)
                                
                                if log_type == 'backend':
                                    if oldest_backend_date is None or current_date < oldest_backend_date:
                                        oldest_backend_date = current_date
                                
                                current_date += timedelta(days=1)
        
        # Filter date_to_logs to include only dates from the oldest_backend_date onwards
        if oldest_backend_date:
            filtered_date_to_logs = {date: logs for date, logs in date_to_logs.items() if datetime.strptime(date, '%Y-%m-%d') >= oldest_backend_date}
            date_to_logs = filtered_date_to_logs
        
        sorted_dates = sorted(date_to_logs.keys())
        if sorted_dates:
            self.latest_date = sorted_dates[-1]
        else:
            self.latest_date = None
        return date_to_logs

    def treeview_sort_column(self, tv, reverse, col=None):
        # Clear arrows for all columns except the currently sorted one
        for column in tv['columns']:
            if column != col:
                tv.heading(column, text=column)  # Reset the heading without an arrow
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
        
        # Rearrange the items according to the sorted order
        for index, (val, k) in enumerate(l):
            tv.move(k, '', index)
        
        # Update heading with arrow for the current sorted column
        new_reverse = not reverse
        arrow = '↓' if reverse else '↑'
        current_heading = re.split(r' \↑| \↓', tv.heading(col, 'text'))[0]
        tv.heading(col, text=f"{current_heading} {arrow}", command=lambda: self.treeview_sort_column(tv, new_reverse, col))

    def get_errors_from_file(self, log_file_path, log_type, target_date, existing_errors=None):
        parser = LogParser()
        errors = existing_errors if existing_errors else {}
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
                    if key not in errors:
                        errors[key] = {'count': 0, 'first_seen': timestamp, 'last_seen': timestamp}
                        if first_timestamp is None or timestamp < first_timestamp:
                            first_timestamp = timestamp
                    errors[key]['count'] += 1
                    errors[key]['first_seen'] = min(errors[key]['first_seen'], timestamp)
                    errors[key]['last_seen'] = max(errors[key]['last_seen'], timestamp)
            except Exception as parse_error:
                print(f"Error parsing line {line_number} in file {log_file_path}: {parse_error}")
                print(f"Line content: {line.strip()}")
    
        return errors
    
    def aggregate_errors_across_files(self, log_files, log_type, target_date):
        all_errors = {}
        for log_file_path in log_files:
            all_errors = self.get_errors_from_file(log_file_path, log_type, target_date, existing_errors=all_errors)
    
        results = []
        for (process, event, file_name, parsed_line_number), details in all_errors.items():
            results.append([
                details['count'],
                details['first_seen'].strftime('%I:%M %p'),
                details['last_seen'].strftime('%I:%M %p'),
                event, process, file_name, parsed_line_number
            ])
        return results

    
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
            backend_results = self.aggregate_errors_across_files(self.backend_logs, 'backend', date)
            for result in backend_results:
                cleaned_result = ["" if r is None or r == 'None' else r for r in result]
                self.tree_backend.insert("", "end", values=cleaned_result)
    
        if self.appserver_logs:
            appserver_results = self.aggregate_errors_across_files(self.appserver_logs, 'appserver', date)
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
    
    def add_right_click_menu(self, tree):
        menu = tk.Menu(tree, tearoff=0)
        menu.add_command(label="Open Selected Logs", command=lambda: self.on_open_selected_logs(tree))
        tree.bind("<Button-3>", lambda event, t=tree: self.popup_menu(event, menu, t))
    
    def popup_menu(self, event, menu, tree):
        try:
            if tree.identify_row(event.y):
                menu.post(event.x_root, event.y_root)
        except tk.TclError:
            pass  # Do nothing if right-click is not on a row

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

    def determine_logs(self, tree):
        return self.backend_logs if tree == self.tree_backend else self.appserver_logs

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
        min_widths = [50, 45, 50, 175, 65, 50, 55]
        max_widths = [75, 45, 50, 500, 95, 300, 75]
    
        # Apply width adjustments to both Treeviews
        adjust_tree_columns(self.tree_backend, min_widths, max_widths)
        adjust_tree_columns(self.tree_appsvr, min_widths, max_widths)
        
    def create_text_widget_context_menu(self, text_widget):
        context_menu = tk.Menu(text_widget, tearoff=0)
        context_menu.add_command(label="Copy", command=lambda: text_widget.event_generate("<<Copy>>"))
        context_menu.add_separator()
        context_menu.add_command(label="Select All", command=lambda: text_widget.tag_add("sel", "1.0", "end"))
    
        # Bind the right-click event
        def popup(event):
            try:
                context_menu.tk_popup(event.x_root, event.y_root)
            finally:
                context_menu.grab_release()
    
        text_widget.bind("<Button-3>", popup)
    
    def search_text(self, text_widget, parent_window):
        search_top = tk.Toplevel(parent_window)
        search_top.title("Search Text")
        search_top.transient(parent_window)
    
        top_frame = tk.Frame(search_top)
        top_frame.pack(side='top', fill='x', padx=10, pady=10)
    
        # Search entry and label
        tk.Label(top_frame, text="Find:").pack(side='left', padx=(0, 10))
        search_entry_widget = tk.Entry(top_frame, width=30)
        search_entry_widget.pack(side='left', fill='x', expand=True)
        search_entry_widget.focus_set()
    
        # Case sensitivity options right to the search box
        case_sensitivity = tk.StringVar(value="insensitive")
        options_frame = tk.Frame(top_frame)  # Adjust to be part of top_frame
        options_frame.pack(side='left', padx=10)
        tk.Label(options_frame, text="Match case:").pack()
        tk.Radiobutton(options_frame, text="Sensitive", variable=case_sensitivity, value="sensitive").pack(side='top')
        tk.Radiobutton(options_frame, text="Insensitive", variable=case_sensitivity, value="insensitive").pack(side='top')
    
        def find_next():
            search_query = search_entry_widget.get()
            options = {'nocase': case_sensitivity.get() == "insensitive"}
            start_index = '1.0' if not text_widget.tag_ranges('current') else text_widget.tag_ranges('current')[1]
    
            # Clear previous highlights
            text_widget.tag_remove('search', '1.0', tk.END)
            text_widget.tag_remove('current', '1.0', tk.END)
    
            # Search and highlight all matches
            pos = start_index
            first_match = None
            while True:
                pos = text_widget.search(search_query, pos, tk.END, **options)
                if not pos:
                    break
                end_pos = f"{pos}+{len(search_query)}c"
                text_widget.tag_add('search', pos, end_pos)
                text_widget.tag_config('search', background='yellow')
                if not first_match:
                    first_match = pos  # Store first match to highlight as current
                pos = end_pos
    
            # Highlight the current match
            if first_match:
                end_match = f"{first_match}+{len(search_query)}c"
                text_widget.tag_add('current', first_match, end_match)
                text_widget.tag_config('current', background='orange')
                text_widget.see(first_match)
            else:
                messagebox.showinfo("Search complete", "No occurrences found.", parent=search_top)
    
        search_button = tk.Button(top_frame, text="Find Next", command=find_next)
        search_button.pack(side='right', padx=(10, 0))
        search_entry_widget.bind("<Return>", lambda event: find_next())
        search_top.protocol("WM_DELETE_WINDOW", on_close)
    
        def on_close():
            text_widget.tag_remove('search', '1.0', tk.END)
            text_widget.tag_remove('current', '1.0', tk.END)
            search_top.destroy()
    
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

    def parse_system_info(self, file_path):
        with open(file_path, 'r', encoding='ISO-8859-1') as file:
            content = file.read()
    
        # Remove ANSI escape codes
        ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
        cleaned_content = ansi_escape.sub('', content)
    
        # Extract hostname
        hostname_pattern = r'Hostname:\s+(\S+)'
        hostname_match = re.search(hostname_pattern, cleaned_content)
        if hostname_match:
            self.systeminfo['hostname'] = hostname_match.group(1)
    
        # Extract IP addresses
        ip_pattern = re.compile(r'Intf-IP\[ifcfg-\S+\]:\s+(\S+)')
        self.networks = ip_pattern.findall(cleaned_content)
    
        # Extract role
        role_pattern = r'FortiSIEM Role:\s+(\S+)'
        role_match = re.search(role_pattern, cleaned_content)
        if role_match:
            self.systeminfo['role'] = role_match.group(1)
    
        # Extract version
        version_pattern = r'Binary Version:\s+(\S+)'
        version_match = re.search(version_pattern, cleaned_content)
        if version_match:
            self.systeminfo['version'] = version_match.group(1)
    
        # If the role is Supervisor, check the configCollection directory
        if self.systeminfo.get('role') == 'Supervisor':
            config_dir = os.path.join(self.logbase, 'configCollection')
            if os.path.exists(config_dir):
                for file_name in os.listdir(config_dir):
                    if file_name.startswith('phoenix_config') and file_name.endswith('.txt'):
                        config_file_path = os.path.join(config_dir, file_name)
                        with open(config_file_path, 'r', encoding='ISO-8859-1') as config_file:
                            for line in config_file:
                                if line.startswith('superfollower='):
                                    superfollower_value = line.split('=')[1].strip().lower()
                                    if superfollower_value == 'true':
                                        self.systeminfo['role'] = 'Follower Supervisor'
                                    else:
                                        self.systeminfo['role'] = 'Leader Supervisor'
                                    break

        self.update_system_info_header()

    def update_system_info_header(self):
        # Update the header labels with the extracted system information
        self.hostname_value.config(text=f"{self.systeminfo.get('hostname', '')}")
        self.ip_value.config(text=f"{', '.join(self.networks) if self.networks else ''}")
        self.role_value.config(text=f"{self.systeminfo.get('role', '')}")
        self.version_value.config(text=f"{self.systeminfo.get('version', '')}")
        
    def update_system_info(self):
        if self.logbase:
            system_info_path = os.path.join(self.logbase, 'system', 'phshowVersion.txt')
            if os.path.exists(system_info_path):
                self.parse_system_info(system_info_path)
                
    def load_system_info_and_logs(self):
        def load():
            self.update_system_info()  # Load system info
            self.organize_logs()       # Organize logs
            self.root.after(0, self.update_datechooser)  # Update the combobox with dates
            self.root.after(0, self.load_logs)        # Load logs for the selected date
            self.root.after(0, self.initialize_conditional_tabs)  # Initialize conditional tabs
            self.root.after(0, self.load_phoenix_config)  # Load the config file content
    
            # Check and load each tab's content if the tab exists
            if hasattr(self, 'server_combobox') and hasattr(self, 'server_text'):
                self.root.after(0, self.update_file_combobox, os.path.join(self.logbase, 'appsvr'), 'server*.log', self.server_combobox, 'server.log', self.server_text)
            if hasattr(self, 'svnlite_combobox') and hasattr(self, 'svnlite_text'):
                self.root.after(0, self.update_file_combobox, os.path.join(self.logbase, 'backend'), 'svnlite*.log', self.svnlite_combobox, 'svnlite.log', self.svnlite_text)
            if hasattr(self, 'archiver_text'):
                self.root.after(0, self.load_log_file, os.path.join(self.logbase, 'backend', 'archiver.log'), self.archiver_text)
            if hasattr(self, 'postgresql_combobox') and hasattr(self, 'postgresql_text'):
                self.root.after(0, self.update_file_combobox, os.path.join(self.logbase, 'postgres'), 'postgresql*.log', self.postgresql_combobox, 'postgresql.log', self.postgresql_text)
            
            self.file_menu.entryconfig("Close current log", state=tk.NORMAL)
            self.root.after(0, self.spinner.stop)
    
        # Start the spinner before loading logs
        self.spinner.start()
        self.center_spinner()
        
        # Run the load function in a separate thread
        threading.Thread(target=load).start()

def main(args):
    if platform.system() == "Windows":
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    #root = ThemedTk(theme="adapta")
    root = tk.Tk()
    sv_ttk.set_theme("dark")

    app = LogViewerApp(root)
    root.mainloop()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract errors from log files.")
    parser.add_argument('--install', action='store_true', help="Update right click context menu in Windows Explorer.")
    args = parser.parse_args()
    
    main(args)
