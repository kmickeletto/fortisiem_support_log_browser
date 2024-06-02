import os
import sys
import requests
import zipfile
import tempfile
import shutil
import tkinter as tk
from tkinter import messagebox

class AutoUpdater:
    def __init__(self, repo_name, current_version, logger=None):
        self.repo_name = repo_name
        self.current_version = current_version
        self.api_url = f'https://api.github.com/repos/{repo_name}/releases/latest'
        self.logger = logger.get_logger(self) if logger else DummyLogger()

    def get_latest_release_info(self):
        self.logger.info('Fetching the latest release info.')
        response = requests.get(self.api_url)
        response.raise_for_status()
        release_info = response.json()
        self.logger.info(f'Latest release info fetched: {release_info["tag_name"]}')
        return release_info

    def check_for_updates(self):
        latest_release_info = self.get_latest_release_info()
        latest_version = latest_release_info['tag_name']
        self.logger.info(f"Current version: {self.current_version}")
        self.logger.info(f"Latest version: {latest_version}")
        return latest_version != self.current_version

    def download_latest_version(self):
        latest_release_info = self.get_latest_release_info()
        zip_url = latest_release_info['zipball_url']
        self.logger.info('Downloading the latest version.')
        response = requests.get(zip_url, stream=True)
        response.raise_for_status()
        with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as tmp_file:
            for chunk in response.iter_content(chunk_size=8192):
                tmp_file.write(chunk)
            self.logger.info(f'Latest version downloaded to {tmp_file.name}')
            return tmp_file.name

    def install_update(self, zip_path):
        self.logger.info('Installing the update.')
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            extract_dir = tempfile.mkdtemp()
            zip_ref.extractall(extract_dir)
            extracted_folder_name = os.listdir(extract_dir)[0]
            extracted_path = os.path.join(extract_dir, extracted_folder_name)

            app_dir = os.path.dirname(os.path.abspath(__file__))
            for item in os.listdir(extracted_path):
                s = os.path.join(extracted_path, item)
                d = os.path.join(app_dir, item)
                if os.path.isdir(s):
                    shutil.copytree(s, d, dirs_exist_ok=True)
                else:
                    shutil.copy2(s, d)

            shutil.rmtree(extract_dir)
            os.remove(zip_path)
            self.logger.info('Update installed successfully. Restarting the application.')
            os.execv(sys.executable, ['python'] + sys.argv)

# Make sure DummyLogger is defined if it is not imported from another module.
class DummyLogger:
    def __getattr__(self, name):
        return lambda *args, **kwargs: None
