# Steps
# 0. Input: root directory to traverse recursively to find duplicate files
# 1. for each file in root directory
# 2.     calculate hash and if does not exist in dict then add sha to file path
# 3.     if file with same sha already exists then print that current file is duplicate of respective file in dict
# 4.     ask to delete current file and if yes the delete
# 5. TODO make it scalable so that it completes in fraction of a time

import os  
import argparse
import sys
from collections import defaultdict
import hashlib

def scantree(path, ignore_dir_names=[]):
    """Recursively yield DirEntry objects for given directory."""
    for entry in os.scandir(path):
        if entry.is_dir(follow_symlinks=False):
            # if entry.name in ignore_dir_names:
            #     print("ignoring ***" + entry.name)
            #     yield entry
            yield from scantree(entry.path)
        else:
            yield entry

class File(object):
    def __init__(self, file_path):
        self.filepath = file_path
        self.file_data_hash = None

    @property
    def file_path(self):
        return self.filepath
        
    @property
    def hash(self):
        if self.file_data_hash == None:
            self.file_data_hash = self._hash()
        return self.file_data_hash

    def _hash(self): 
    
        # A arbitrary (but fixed) buffer  
        # size (change accordingly) 
        # 65536 = 65536 bytes = 64 kilobytes  
        BUF_SIZE = 65536 
    
        # Initializing the sha256() method 
        sha256 = hashlib.sha256() 
    
        # Opening the file provided as 
        # the first commandline arguement 
        with open(self.filepath, 'rb') as f: 
            
            while True: 
                
                # reading data = BUF_SIZE from 
                # the file and saving it in a 
                # variable 
                data = f.read(BUF_SIZE) 
    
                # True if eof = 1 
                if not data: 
                    break
        
                # Passing that data to that sh256 hash 
                # function (updating the function with 
                # that data) 
                sha256.update(data) 
    
        
        # sha256.hexdigest() hashes all the input 
        # data passed to the sha256() via sha256.update() 
        # Acts as a finalize method, after which 
        # all the input data gets hashed hexdigest() 
        # hashes the data, and returns the output 
        # in hexadecimal format 
        return sha256.hexdigest()
    
def list_files(directory=".", recursive=True):
    all_filepaths = []
    ignore_dir_names = ["venv2", "venv3", ".git", "__pycache__"]

    for entry in scantree(directory, ignore_dir_names):
        all_filepaths.append(entry.path)

    for filepath in all_filepaths:
        print(filepath)
    
def list_duplicate_files(directory=".", recursive=True):
    # import pdb; pdb.set_trace()
    #all_filepaths = []
    sha_to_filepaths_dict = defaultdict(list)

    ignore_dir_names = ["venv2", "venv3", ".git"]
    
    for entry in scantree(directory, ignore_dir_names):
        # all_filepaths.append(entry.path)
        f = File(entry.path)
        if f.hash in sha_to_filepaths_dict:
            matching_file_list = sha_to_filepaths_dict[f.hash]
            if f.file_path not in matching_file_list:
                matching_file_list.append(f.file_path)
            print("Found Duplicate file: %s=>%s" % (f.file_path, matching_file_list[0]))
            # TODO ask if user wants to delete this file
        else:
            sha_to_filepaths_dict[f.hash].append(f.file_path)

    # for filepath in all_filepaths:
    #     print(filepath)

    total_files_scanned = len(sha_to_filepaths_dict)
    if (total_files_scanned == 0):
        print("No files found")
    else:
        print("Total files found: %s" % total_files_scanned)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")

    # Command: list-files
    parser_list_files = subparsers.add_parser(
        "list-files",
        help="List all files recursively",
    )
    parser_list_files.add_argument(
        "-d", "--directory",
        help="path of dir",
        required=True,
    )
    # Command: list-duplicate-files
    parser_list_duplicate_files = subparsers.add_parser(
        "list-duplicate-files",
        help="list files which are duplicates",
    )
    parser_list_duplicate_files.add_argument(
        "-d", "--directory",
        help="path of dir",
        required=True,
    )

    args = parser.parse_args()
    if not args.command:
        parser.parse_args(["--help"])
        sys.exit(0)

    # Do the stuff here
    print(args)

    if args.command == "list-files":
        list_files(args.directory)
    if args.command == "list-duplicate-files":
        list_duplicate_files(args.directory)