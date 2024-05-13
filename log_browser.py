import tkinter as tk
from tkinter import ttk, messagebox, font, PhotoImage, scrolledtext, filedialog
import tkinter.font as tkFont
from ttkthemes import ThemedTk
import argparse
from datetime import datetime
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

        # Initialize GUI components with minimal padding
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
                    result_queue.put(local_path)
                    if self.on_complete:  # Call the callback if set
                        self.on_complete()

    def connect(self):
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(self.hostname, username=self.username, password=self.password, key_filename=self.key_filename)
            self.scp = SCPClient(self.client.get_transport(), progress=self.progress)
            self.connected = True
        except Exception as e:
            self.safe_insert(f"Connection failed: {e}\n", "error")
            self.connected = False

    def execute_command(self, command):
        if not self.is_alive():
            return  # Abort operation if GUI is not alive
        self.safe_insert(f"Connecting to {self.hostname}\n", 'info')
        try:
            stdin, stdout, stderr = self.client.exec_command(command)
            stderr_output = []
            while True:
                if not self.is_alive():
                    break
                # Handle stdout
                line = stdout.readline()
                if line:
                    self.safe_insert(line)
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
                    self.safe_insert(f"Command failed with exit status {exit_status}: {error_message}\n", "error")
                else:
                    self.safe_insert(f"Command failed with exit status {exit_status}\n", "error")
        except Exception as e:
            self.safe_insert(f"Failed to execute command: {e}\n", "error")
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
            self.safe_insert(f"\nFailed to download file: {e}\n", "error")
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
            # Fixed character width set for wrapping
            fixed_width = 80  # Standard width for readability in characters
    
            # Use textwrap to wrap the text accordingly
            wrapped_text = textwrap.fill(text, width=fixed_width)
            
            # Insert the wrapped text into the Text widget
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
    def __init__(self, parent, callback=None):
        super().__init__(parent)
        self.parent = parent
        self.callback = callback
        self.parent.geometry('600x250')
        self.parent.title("Enter the host and credentials")
        self.pack(padx=10, pady=10)
        self.init_ui()
        self.load_credentials()
        
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
        
        # Labels and entries for hostname and username
        tk.Label(self, text="Hostname/IP:").grid(row=0, column=0, sticky="w")
        self.hostname_entry = tk.Entry(self)
        self.hostname_entry.grid(row=0, column=1, columnspan=4, padx=5)
        self.hostname_entry.focus_set()
    
        tk.Label(self, text="Username:").grid(row=1, column=0, sticky="w")
        self.username_entry = tk.Entry(self)
        self.username_entry.grid(row=1, column=1, columnspan=4, padx=5)

        auth_frame = tk.LabelFrame(self, text="Authentication Method", padx=5)
        auth_frame.grid(row=0, column=5, padx=50)
        rb1 = tk.Radiobutton(auth_frame, text="Password", variable=self.auth_var, value='password', command=self.toggle_auth_method, takefocus=0)
        rb1.grid(row=0, column=0, sticky="w")
        rb2 = tk.Radiobutton(auth_frame, text="Private Key", variable=self.auth_var, value='key', command=self.toggle_auth_method, takefocus=0)
        rb2.grid(row=1, column=0, sticky="w")
    
        # Initialize label for authentication method
        self.auth_label = tk.Label(self, text="Password:")
        self.auth_label.grid(row=2, column=0, pady=3, sticky="w")
    
        # Authentication inputs and browse button
        self.password_entry = tk.Entry(self, show="*")
        self.password_entry.grid(row=2, column=1, columnspan=4, pady=3, padx=5)
        self.key_entry = tk.Entry(self)
        self.key_entry.grid(row=2, column=1, columnspan=4, pady=3)
        self.key_entry.grid_remove()
        self.browse_button = tk.Button(self, text="Browse", command=self.browse_keyfile)
        self.browse_button.grid(row=2, column=5)
        self.browse_button.grid_remove()

        tk.Label(self, text="Days:").grid(row=4, column=0, sticky="w")
        self.days_entry = tk.Scale(self, from_=1, to=7, orient='horizontal', length=150)
        self.days_entry.grid(row=4, column=1, pady=10)

        action_frame = tk.LabelFrame(self, relief="flat")
        action_frame.grid(row=5, column=5)

        # Submit button
        self.submit_button = tk.Button(action_frame, text="Submit", command=self.submit_credentials, state="disabled")
        self.submit_button.grid(row=0, column=1, padx=5)
                
        cancel_button = tk.Button(action_frame, text="Cancel", command=self.cancel)
        cancel_button.grid(row=0, column=0, padx=5)
        
        for widget in [self.hostname_entry, self.username_entry, self.password_entry, self.submit_button, cancel_button]:
            widget.lift()
    
        # Bind the Enter key to the submit_credentials method
        self.parent.bind("<Return>", lambda event: self.submit_credentials())
        
        self.hostname_entry.bind("<KeyRelease>", self.validate_inputs)
        self.username_entry.bind("<KeyRelease>", self.validate_inputs)
    
    def validate_inputs(self, event=None):
        if self.hostname_entry.get().strip() and self.username_entry.get().strip():
            self.submit_button['state'] = 'normal'
        else:
            self.submit_button['state'] = 'disabled'
    
    def toggle_auth_method(self):
        if self.auth_var.get() == 'password':
            self.auth_label.config(text="Password:")
            self.password_entry.grid()  # Ensure password entry is visible
            self.key_entry.grid_remove()  # Hide key entry
            self.browse_button.grid_remove()  # Hide browse button
        else:
            self.auth_label.config(text="Private Key:")
            self.password_entry.grid_remove()  # Hide password entry
            self.key_entry.grid()  # Ensure key entry is visible
            self.browse_button.grid()  # Ensure browse button is visible

    def browse_keyfile(self):
        filename = filedialog.askopenfilename(title="Select Key File", filetypes=(("Private Key Files", "*.pem *.key"), ("All Files", "*.*")))
        if filename:
            self.key_entry.delete(0, tk.END)
            self.key_entry.insert(0, filename)

    def close_form(self):
        if self.parent.winfo_exists():
            self.parent.destroy()
        
    def submit_credentials(self, event=None):
        hostname = self.hostname_entry.get().strip()
        username = self.username_entry.get().strip()
        days = self.days_entry.get()
    
        if hostname and username:
            top_level_window = tk.Toplevel(self.parent)
            result_queue = queue.Queue()
    
            # Construct the download path using the temporary directory and a unique file name
            temp_directory = tempfile.gettempdir()
            unique_filename = f"AOLogs-{uuid.uuid4()}.tar"
            download_path = os.path.join(temp_directory, unique_filename)
    
            if self.auth_var.get() == 'password':
                password = self.password_entry.get().strip()
                ssh_client = SSHClient(top_level_window, hostname, username, password=password, days=days, on_complete=self.close_form)
            else:
                keyfile = self.key_entry.get().strip()
                ssh_client = SSHClient(top_level_window, hostname, username, key_filename=keyfile, days=days, on_complete=self.close_form)
    
            # Start the SSH operation with the dynamically generated file path
            ssh_client.start_operations('phziplogs /tmp', download_path, result_queue)
            top_level_window.wait_window()  # Wait for the operation window to close
    
            if self.callback:
                self.callback(result_queue.get())

            
    def cancel(self):
        self.parent.destroy()
        
class FSMLogsExtractorApp(tk.Tk):
    def __init__(self, tarball, force):
        super().__init__()
        self.title("FSM Logs Extractor")
        self.geometry('900x400')

        self.attributes('-topmost', True)
        self.output_text = scrolledtext.ScrolledText(self, width=100, height=15)
        self.output_text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        progress_frame = tk.Frame(self)
        progress_frame.pack(padx=10, pady=5, fill=tk.X, expand=False)

        self.progress_bar = ttk.Progressbar(progress_frame, orient='horizontal', mode='determinate', length=400)
        self.progress_bar.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.progress_label = tk.Label(progress_frame, text="0%", width=10)
        self.progress_label.pack(side=tk.RIGHT, padx=5)

        self.protocol("WM_DELETE_WINDOW", self.on_close_extract)

        self.tarball = tarball
        self.force = force
        self.thread = threading.Thread(target=self.extract_tarball)
        self.thread.start()

    def extract_tarball(self):
        # Get the directory of the tarball
        tarball_dir = os.path.dirname(self.tarball)
        
        # Create a directory name based on the tarball's name without extension
        dir_name = os.path.splitext(os.path.basename(self.tarball))[0]
        
        # Combine the directory of the tarball with the new directory name
        output_path = os.path.join(tarball_dir, dir_name)
    
        # Proceed with checking for existing directory and potentially overwriting
        if os.path.exists(output_path) and not self.force:
            self.prompt_overwrite(output_path)
        else:
            self.process_extraction(output_path)
        
    def prompt_overwrite(self, path):
        # Temporarily lower the extraction window so it doesn't cover the dialog
        self.lower()
        
        response = messagebox.askyesno("Directory exists", f"The directory {path} already exists. Do you want to overwrite it?")
        
        # Lift the extraction window back after the dialog closes
        self.lift()
        self.attributes('-topmost', True)  # Ensure it stays on top of the Log Viewer
    
        if response:
            shutil.rmtree(path)
            self.process_extraction(path)
        else:
            self.destroy()

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
    
                        # Correct the file name after removing .gz
                        dir_path, filename = os.path.split(extract_path)
                        if '.log' in filename:
                            filename = filename.replace('.log', '') + '.log'
                        if '_log' in filename:
                            filename = filename.replace('_log', '') + '.log'
                        if '.gz' in filename:
                            filename = filename.replace('.gz', '')
                        extract_path = os.path.join(dir_path, filename)
    
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
            self.quit_button.config(state=tk.NORMAL)
            
    def update_gui(self, message):
        self.output_text.insert(tk.END, message + '\n')
        self.output_text.yview(tk.END)

    def update_progress(self, progress):
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
    # Regular expression patterns for fields in appserver log type
    field_patterns = {
        'phCustId': r'\[phCustId\]=(\d+),',
        'eventSeverity': r'\[eventSeverity\]=([A-Z_]+),',
        'phEventCategory': r'\[phEventCategory\]=(\d+),',
        'methodName': r'\[methodName\]=(\S+?),',
        'className': r'\[className\]=(\S+?),',
        'procName': r'\[procName\]=(\S+?),',
        'lineNumber': r'\[lineNumber\]=(-?\d+),'
    }

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
            # Updated pattern to capture event type for appserver logs
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
                    
                # Dictionary to hold the values we want to extract
                fields = {
                    'phCustId': None,
                    'eventSeverity': None,
                    'phEventCategory': None,
                    'methodName': None,
                    'className': None,
                    'procName': None,
                    'lineNumber': None
                }
            
                # Regular expression to extract specific fields from the body
                field_patterns = {
                    'phCustId': r'\[phCustId\]=(\d+),',
                    'eventSeverity': r'\[eventSeverity\]=([A-Z_]+),',
                    'phEventCategory': r'\[phEventCategory\]=(\d+),',
                    'methodName': r'\[methodName\]=(\S+?),',
                    'className': r'\[className\]=(\S+?),',
                    'procName': r'\[procName\]=(\S+?),',
                    'lineNumber': r'\[lineNumber\]=(-?\d+),'
                }
                
                # Iterate over the fields and try to find matches in the body
                for field, pattern in field_patterns.items():
                    match = re.search(pattern, body)
                    if match:
                        fields[field] = match.group(1)
                return timestamp, None, event, fields['eventSeverity'], fields['procName'], file, fields['lineNumber']
        except (IndexError, ValueError):
            return None

class LogViewerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("FortiSIEM Support Log Viewer")
        self.ssh_used = False
        self.ssh_objects = []
        self.logbase = None
        self.date_to_logs = {}
        self.set_app_icon('fortisiem.png')
        self.root.geometry('1080x750')  # Set initial window size
        self.root.minsize(800, 600)     # Set minimum window size
        self.initialize_font()
        self.setup_styles()
        self.initialize_gui()
        self.initialize_menu()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def initialize_gui(self):
        frame_top = ttk.Frame(self.root)
        frame_top.pack(fill='x', padx=5, pady=5)
    
        self.selected_date = tk.StringVar()
        ttk.Label(frame_top, text="Date:", font=self.bold_font).pack(side='left', padx=(5, 2))
    
        dates = sorted(self.date_to_logs.keys())
        self.dropdown = ttk.Combobox(frame_top, textvariable=self.selected_date, font=(self.standard_font, 12), state='readonly', values=dates)
        self.dropdown.pack(side='left', fill='x', expand=True, padx=(2, 5))
        self.dropdown.bind("<<ComboboxSelected>>", self.load_logs)
    
        if dates:
            self.latest_date = dates[-1]
            self.dropdown.set(self.latest_date)
    
        # Frame and Label for backend logs
        frame_backend = ttk.Frame(self.root)
        frame_backend.pack(fill='both', expand=True, side='top', padx=5, pady=(5, 0))
    
        self.label_backend = ttk.Label(frame_backend, text="Backend:", font=self.active_file_font)  # Use the bold font here
        self.label_backend.pack(side='top', fill='x', pady=(0, 5))  # Pack the label at the top of the frame
    
        self.setup_treeview(frame_backend, 'backend')
        self.add_right_click_menu(self.tree_backend)
    
        # Frame and Label for appsvr logs
        frame_appsvr = ttk.Frame(self.root)
        frame_appsvr.pack(fill='both', expand=True, side='top', padx=5, pady=(5, 0))
    
        self.label_appsvr = ttk.Label(frame_appsvr, text="AppServer:", font=self.active_file_font)  # Use the bold font here
        self.label_appsvr.pack(side='top', fill='x', pady=(0, 5))  # Pack the label at the top of the frame
    
        self.setup_treeview(frame_appsvr, 'appsvr')
        self.add_right_click_menu(self.tree_appsvr)

    def initialize_font(self):
        # Set Arial as the application's standard font for text
        self.standard_font = tkFont.Font(family="Arial", size=10)
        self.bold_font = tkFont.Font(family="Arial", size=11, weight="bold")
        self.active_file_font = tkFont.Font(family="Arial", size=10, weight="bold")

    def setup_styles(self):
        # Apply the standard font to all ttk widgets
        style = ttk.Style(self.root)
        style.configure('.', font=self.standard_font)  # '.' applies to all ttk widgets

        # Specific styling for Treeview (if you have tables)
        style.configure('Treeview', rowheight=25)  # Adjust row height if needed
        style.configure('Treeview.Heading', font=self.bold_font)  # Headings style

    def set_app_icon(self, image_path):
        # Set the AppID for better Windows taskbar handling
        app_id = u'fortinet.fortisiem.log'  # Customize this string as needed
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

    def on_close(self):
        temp_dir = tempfile.gettempdir()  # Get the system temporary directory path
    
        # Check if logbase is in the temporary directory
        if self.logbase and os.path.commonpath([self.logbase, temp_dir]) == temp_dir:
            try:
                shutil.rmtree(self.logbase)  # Attempt to delete the directory
                print(f"Temporary directory {self.logbase} deleted successfully.")
            except Exception as e:
                print(f"Failed to delete temporary directory {self.logbase}: {e}")
    
        # Check if file_path is in the temporary directory
        if hasattr(self, 'file_path') and self.file_path and os.path.commonpath([self.file_path, temp_dir]) == temp_dir:
            try:
                os.remove(self.file_path)  # Attempt to delete the file
                print(f"Temporary file {self.file_path} deleted successfully.")
            except Exception as e:
                print(f"Failed to delete temporary file {self.file_path}: {e}")
    
        self.root.destroy()

    def handle_result(self, result):
        self.file_path = result
        self.launch_extractor()
    
    def fetch_ssh_logs(self):
        self.ssh_used = True
        top_level_window = tk.Toplevel(self.root)
        file_path = SSHCredentialsForm(top_level_window, callback=self.handle_result)
        top_level_window.mainloop()

    def open_file(self):
        self.file_path = filedialog.askopenfilename(title="Open Log File", filetypes=[("TAR files", "*.tar")])
        if not self.file_path:
            return  # User cancelled the dialog
    
        # Launch the extraction app
        self.launch_extractor()
        
    def open_existing(self):
        # Ask the user to select a directory
        directory = filedialog.askdirectory(title='Select the directory containing the extracted logs')
        if not directory:
            return  # User cancelled the dialog or closed the window
    
        self.logbase = directory
        self.date_to_logs = self.organize_logs_by_date()
        self.update_combobox()
        self.load_logs()
    
    def launch_extractor(self):
        if not self.file_path or not os.path.exists(self.file_path):
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
        # Create and show the extractor app window
        extractor_app = FSMLogsExtractorApp(self.file_path, force=True)
        extractor_app.on_extraction_complete = self.handle_extraction_complete  # Ensure callback is set
        extractor_app.mainloop()
    
    def handle_extraction_complete(self, extracted_path):
        # Update logbase and organize logs
        self.logbase = extracted_path
        self.date_to_logs = self.organize_logs_by_date()
        self.update_combobox()
    
    def update_combobox(self):
        dates = sorted(self.date_to_logs.keys())
        self.dropdown['values'] = dates
        if dates:
            self.latest_date = dates[-1]
            self.dropdown.set(self.latest_date)
            self.root.after(100, self.load_logs)

    def extract_date_from_content(self, file_path):
        try:
            with open(file_path, 'r') as file:
                first_line = file.readline()
                # Pattern for ISO 8601 format
                backlogs_pattern = re.search(r'(\d{4}-\d{2}-\d{2})T\d{2}:\d{2}:\d{2}\.\d{6}-\d{2}:\d{2}', first_line)
                # Pattern for simpler log date format
                appsvr_pattern = re.search(r'(\d{4}-\d{2}-\d{2}) \d{2}:\d{2}:\d{2},\d{3}', first_line)
    
                # Check which pattern matches and process accordingly
                if backlogs_pattern:
                    timestamp = datetime.strptime(backlogs_pattern.group(1), '%Y-%m-%d')
                    return timestamp.strftime('%Y-%m-%d')
                elif appsvr_pattern:
                    return appsvr_pattern.group(1)
        except Exception as e:
            print(f"Error reading {file_path}: {e}")
        return None

    def organize_logs_by_date(self):
        date_to_logs = {}
        directories = ["backend", "appsvr"]
        for directory in directories:
            path = os.path.join(self.logbase, directory)
            if os.path.exists(path):  # Check if the directory exists
                for file_name in os.listdir(path):
                    if file_name.startswith('phoenix') and file_name.endswith('.log'):
                        file_path = os.path.join(path, file_name)
                        date_part = self.extract_date_from_content(file_path)
                        if date_part:
                            if date_part not in date_to_logs:
                                date_to_logs[date_part] = []
                            date_to_logs[date_part].append(file_path)
        sorted_dates = sorted(date_to_logs.keys())
        if sorted_dates:
            self.latest_date = sorted_dates[-1]  # Store the latest date
        else:
            self.latest_date = None
        return date_to_logs

    def setup_treeview(self, parent, type):
        tree = ttk.Treeview(parent, columns=("Count", "First Seen", "Last Seen", "Event", "Process", "File", "Line"), show="headings", selectmode='extended')

        # Setting up columns with initial sort direction arrows
        for col in tree['columns']:
            # Initialize each column heading without arrows
            tree.heading(col, text=col, command=lambda _col=col: self.treeview_sort_column(tree, _col, False))
            if col in ["Count", "Line"]:
                tree.column(col, anchor='e', width=100, stretch=False, minwidth=100)
            elif col in ["First Seen", "Last Seen"]:
                tree.column(col, anchor='center', width=150)
            else:
                tree.column(col, anchor='w', width=150)
    
        scroll_y = ttk.Scrollbar(parent, orient='vertical', command=tree.yview)
        scroll_y.pack(side='right', fill='y')
        tree.configure(yscrollcommand=scroll_y.set)
        tree.pack(side='left', fill='both', expand=True)
        tree.bind("<Double-1>", self.on_double_click)
    
        if type == 'backend':
            self.tree_backend = tree
        else:
            self.tree_appsvr = tree

    def treeview_sort_column(self, tv, col, reverse):
        # Clear arrows for all columns except the currently sorted one
        for column in tv['columns']:
            if column != col:
                tv.heading(column, text=column)  # Reset the heading without an arrow
        
        # Sorting logic remains the same
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
        tv.heading(col, text=f"{current_heading} {arrow}", command=lambda: self.treeview_sort_column(tv, col, new_reverse))

    def get_errors_from_file(self, log_file_path, log_type):
        parser = LogParser()  # Create an instance of the LogParser class
        errors = {}
        first_timestamp = None
        line_number = 0
    
        try:
            with open(log_file_path, 'r', encoding='ISO-8859-1') as file:
                for line in file:
                    line_number += 1
                    try:
                        parsed = parser.parse_log(line, log_type)  # Use the parse_log method
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
    
        except Exception as e:
            print(f"Error opening or reading file {log_file_path}: {e}")
    
        results = []
        for (process, event, file_name, parsed_line_number), details in errors.items():
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
    
        # Update labels with filenames
        backend_logs = [log for log in self.date_to_logs[date] if 'backend' in log]
        appsvr_logs = [log for log in self.date_to_logs[date] if 'appsvr' in log]
        one_level_up = os.path.dirname(self.logbase)
    
        # Calculating relative paths from one directory higher
        backend_paths = ', '.join([os.path.relpath(log, one_level_up) for log in backend_logs])
        appsvr_paths = ', '.join([os.path.relpath(log, one_level_up) for log in appsvr_logs])
    
        self.label_backend.config(text=f"Backend: {backend_paths}")
        self.label_appsvr.config(text=f"AppServer: {appsvr_paths}")
    
        for log_path in self.backend_logs:
            results = self.get_errors_from_file(log_path, 'backend')
            for result in results:
                cleaned_result = ["" if r is None or r == 'None' else r for r in result]
                self.tree_backend.insert("", "end", values=cleaned_result)
        
        for log_path in self.appserver_logs:
            results = self.get_errors_from_file(log_path, 'appserver')
            for result in results:
                cleaned_result = ["" if r is None or r == 'None' else r for r in result]
                self.tree_appsvr.insert("", "end", values=cleaned_result)
    
        # Sort by 'Count' in descending order after populating
        self.treeview_sort_column(self.tree_backend, "Count", True)
        self.treeview_sort_column(self.tree_appsvr, "Count", True)
    
        # Adjust column widths after populating and sorting
        self.adjust_column_widths()

    def configure_window_size(self, top):
        default_width = 1500
        default_height = 600
        screen_width = top.winfo_screenwidth()
        screen_height = top.winfo_screenheight()
        window_width = min(default_width, screen_width)
        window_height = min(default_height, screen_height)
        if window_width < default_width or window_height < default_height:
            top.state('zoomed')  # This maximizes the window
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

    def on_open_selected_logs(self, tree):
        selected_items = tree.selection()
        if not selected_items:
            messagebox.showinfo("Info", "No entries selected.")
            return
    
        log_entries = []
        event_names = set()  # Use a set to avoid duplicate event names
        log_type = 'backend' if tree == self.tree_backend else 'appserver'
        log_files = self.determine_logs(tree)
        for item in selected_items:
            details = tree.item(item, "values")
            event_name, process, filename, line_number = details[3], details[4], details[5], details[6]
            log_entries.extend(self.filter_log_entries(log_files, event_name, process, filename, line_number, log_type))
            event_names.add(event_name)
    
        # Format the title with comma-separated list and "and" for the last item
        if len(event_names) > 1:
            sorted_names = sorted(event_names)
            title = "Displaying logs for " + ", ".join(sorted_names[:-1]) + ", and " + sorted_names[-1]
        else:
            title = f"Displaying logs for {next(iter(event_names))}"  # Safe as we check if event_names is not empty earlier
    
        self.display_logs(log_entries, title=title)

    def on_double_click(self, event):
        tree = event.widget
        selected_items = tree.selection()
        if selected_items:  # Check if the selection is not empty
            item = selected_items[0]  # Get the first selected item
            log_type = 'backend' if tree == self.tree_backend else 'appserver'
            details = tree.item(item, "values")
            event_name, process, filename, line_number = details[3], details[4], details[5], details[6]
            log_entries = self.filter_log_entries(self.backend_logs if tree == self.tree_backend else self.appserver_logs, event_name, process, filename, line_number, log_type)
            title = f"Displaying logs for {event_name}"
            self.display_logs(log_entries, title=title)
    
    def display_logs(self, log_entries, title):
        top = tk.Toplevel(self.root)
        top.title(title)
        self.configure_window_size(top)
    
        text = tk.Text(top, wrap='word', bg='white')  # Set default background to white
        text.pack(side='left', fill='both', expand=True)
    
        # Define the scrollbar for the Text widget
        scroll = tk.Scrollbar(top, command=text.yview)
        scroll.pack(side='right', fill='y')
        text.config(yscrollcommand=scroll.set)
    
        # Define a tag for alternate row coloring with a light grayish-blue background
        text.tag_configure('evenRow', background='#B3E2F0')  # Light grayish-blue background
    
        sorted_log_entries = sorted(log_entries, key=lambda entry: entry[0])
        for index, (timestamp, entry) in enumerate(sorted_log_entries):
            text.insert('end', f"{entry}\n")
            # Apply the 'evenRow' tag to even-indexed rows
            if index % 2 == 0:
                line_index_start = f"{index + 1}.0"
                line_index_end = f"{index + 1}.end+1c"  # Extend the tag to the end of the line
                text.tag_add('evenRow', line_index_start, line_index_end)
    
        text.config(state='disabled')
        text.yview_moveto(0)

    def filter_log_entries(self, log_files, event_name, process_name, filename, line_number, log_type):
        log_entries = []
        for log_file_path in log_files:
            try:
                with open(log_file_path, 'r', encoding='ISO-8859-1') as file:
                    for line in file:
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
            except Exception as e:
                messagebox.showerror("Error", f"Failed to read file {log_file_path}: {str(e)}")
        return sorted(log_entries, key=lambda x: x[0])


    def determine_logs(self, tree):
        return self.backend_logs if tree == self.tree_backend else self.appserver_logs

    def adjust_column_widths(self):
        def adjust_tree_columns(tree, min_widths, max_widths):
            tree.update_idletasks()  # Ensure the UI is updated before measurements
            tree_font = self.standard_font
    
            for index, col in enumerate(tree["columns"]):
                max_width = tree_font.measure(tree.heading(col)['text']) + 20  # Include padding for aesthetics
    
                for item in tree.get_children(''):
                    cell_value = str(tree.set(item, col))
                    cell_value = ' '.join(cell_value.split())
                    cell_width = tree_font.measure(cell_value)
                    max_width = max(max_width, cell_width)
    
                # Apply minimum and maximum width constraints
                final_width = min(max(min_widths[index], max_width), max_widths[index])
                tree.column(col, width=final_width)
    
        # Minimum and maximum widths for each column
        min_widths = [50, 45, 50, 200, 65, 50, 55]
        max_widths = [75, 45, 50, 500, 95, 200, 75]
    
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

def main(args):
    if platform.system() == "Windows":
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    root = ThemedTk(theme="adapta")

    app = LogViewerApp(root)
    root.mainloop()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract errors from log files.")
    parser.add_argument('--install', action='store_true', help="Update right click context menu in Windows Explorer.")
    args = parser.parse_args()
    
    main(args)
