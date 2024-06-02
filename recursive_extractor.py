import os
import re
import tarfile
import gzip
from datetime import datetime
import time
from argparse import ArgumentParser

class RecursiveExtractor:
    def __init__(self, output_function=None):
        self.output_function = output_function
        self.error_count = 0
        self.file_extensions = ('tar', 'tgz', 'tbz', 'tb2', 'tar.gz', 'tar.bz2')
        self.last_message = ""

    def log(self, message, end='\n'):
        self.last_message += message
        if end == '\n':
            if self.output_function:
                self.output_function(self.last_message)
            else:
                print(self.last_message, end=end)
            self.last_message = ""  # Reset after printing
        else:
            self.last_message += end

    def file_extension(self, file_name):
        match = re.compile(r"^.*?[.](?P<ext>tar[.]gz|tar[.]bz2|\w+)$", re.IGNORECASE).match(file_name)
        if match:
            return match.group('ext')
        else:
            return ''

    def appropriate_folder_name(self, folder_fullpath):
        if os.path.exists(folder_fullpath):
            folder_name = os.path.basename(folder_fullpath)
            parent_fullpath = os.path.dirname(folder_fullpath)
            now = datetime.now()
            timestamp = now.strftime('%Y-%m-%d')
            elapsed_seconds = now.hour * 3600 + now.minute * 60 + now.second
            new_folder_name = f'{folder_name}-{timestamp}-{elapsed_seconds}'
            new_folder_fullpath = os.path.join(parent_fullpath, new_folder_name)
            return self.appropriate_folder_name(new_folder_fullpath)
        else:
            return folder_fullpath

    def extract(self, tarfile_fullpath, delete_tar_file=True, top_level=False):
        try:
            tarfile_fullpath = os.path.normpath(tarfile_fullpath)
            with tarfile.open(tarfile_fullpath) as tar:
                extract_folder_fullpath = self.appropriate_folder_name(tarfile_fullpath[:-1 * len(self.file_extension(tarfile_fullpath)) - 1])
                extract_folder_fullpath = os.path.normpath(extract_folder_fullpath)
                extract_folder_name = os.path.basename(extract_folder_fullpath)
                if top_level:
                    self.log(f"Extracting {tarfile_fullpath}", end='\n')
                else:
                    self.log(f"Extracting {extract_folder_name}", end='\n')
                tar.extractall(extract_folder_fullpath)
            if delete_tar_file:
                os.remove(tarfile_fullpath)
            return extract_folder_fullpath
        except Exception as e:
            self.log(f'(Error) {str(e)}')
            self.error_count += 1

    def extract_gz(self, tarfile_fullpath, delete_tar_file=True):
        try:
            tarfile_fullpath = os.path.normpath(tarfile_fullpath)
            with gzip.open(tarfile_fullpath, 'rb') as gz:
                extract_folder_fullpath = self.appropriate_folder_name(tarfile_fullpath[:-1 * len(self.file_extension(tarfile_fullpath)) - 1])
                extract_folder_fullpath = os.path.normpath(extract_folder_fullpath)
                extract_folder_name = os.path.basename(extract_folder_fullpath)
                self.log(f"Extracting {extract_folder_name}", end='\n')
                with open(extract_folder_fullpath, "wb") as output:
                    output.write(gz.read())
            if delete_tar_file:
                #time.sleep(0.1)
                os.remove(tarfile_fullpath)
            return extract_folder_fullpath
        except Exception as e:
            self.log(f'(Error) {str(e)}')
            self.error_count += 1

    def walk_tree_and_extract(self, parent_dir):
        parent_dir = os.path.normpath(parent_dir)
        try:
            dir_contents = os.listdir(parent_dir)
        except OSError as e:
            self.log(f'Error occurred. Could not open folder {parent_dir}\n{str(e).capitalize()}')
            self.error_count += 1
            return

        for content in dir_contents:
            content_fullpath = os.path.join(parent_dir, content)
            content_fullpath = os.path.normpath(content_fullpath)
            if os.path.isdir(content_fullpath):
                self.walk_tree_and_extract(content_fullpath)
            elif os.path.isfile(content_fullpath):
                if self.file_extension(content_fullpath) in self.file_extensions:
                    extract_folder_name = self.extract(content_fullpath)
                    if extract_folder_name:
                        dir_contents.append(extract_folder_name)
                elif self.file_extension(content_fullpath) == 'gz':
                    extract_folder_name = self.extract_gz(content_fullpath)
                    if extract_folder_name:
                        dir_contents.append(extract_folder_name)
            else:
                self.log(f'Skipping {content_fullpath}. <Neither file nor folder>')

    def extract_top_level(self, tarfile_fullpath, remove_parent):
        tarfile_fullpath = os.path.normpath(tarfile_fullpath)
        extract_folder_fullpath = self.extract(tarfile_fullpath, remove_parent, True)
        if extract_folder_fullpath:
            self.walk_tree_and_extract(extract_folder_fullpath)
            return extract_folder_fullpath
        return None

def main():
    parser = ArgumentParser(description=f'Nested tar archive extractor')
    parser.add_argument('--remove-parent', action='store_true', help='Removes the parent tar file after extraction.')
    parser.add_argument('tar_paths', metavar='tarball', type=str, nargs='+', help='Path of the tar file to be extracted.')
    args = parser.parse_args()

    extractor = RecursiveExtractor()

    for tar_path in args.tar_paths:
        tar_path = os.path.normpath(tar_path)
        print(f"Extraction Complete: {tar_path}")
        if os.path.exists(tar_path):
            extractor.extract_top_level(tar_path, args.remove_parent)
        else:
            print(f'Not a valid path: {tar_path}')
            extractor.error_count += 1

    if extractor.error_count != 0:
        print(f'{extractor.error_count} error(s) occurred.')

if __name__ == '__main__':
    main()
