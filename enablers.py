"""
Decription:     A simple utility to enable/disable firewall, defender, task manager. It also creates restore and shadow copy points
Author:         Nadir Hussain
Dated:          Jan 25, 2025
"""
import subprocess
import winreg
import ctypes
import sys

"""Check if the script is running with administrative privileges."""
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

# Registry key operations
def modify_registry_key(key, sub_key, value_name, value):
    try:
        with winreg.OpenKey(key, sub_key, 0, winreg.KEY_SET_VALUE) as reg_key:
            winreg.SetValueEx(reg_key, value_name, 0, winreg.REG_DWORD, value)
        print(f"Successfully modified {sub_key} -> {value_name}")
    except Exception as e:
        print(f"Failed to modify {sub_key} -> {value_name}: {e}")

# Enable or disable Windows Defender
def set_defender_state(enable):
    value = 0 if enable else 1
    modify_registry_key(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware", value)

# Enable or disable Firewall
def set_firewall_state(enable):
    value = 1 if enable else 0
    modify_registry_key(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile", "EnableFirewall", value)
    modify_registry_key(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile", "EnableFirewall", value)

# Enable or disable Task Manager
def set_task_manager_state(enable):
    value = 0 if enable else 1
    modify_registry_key(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableTaskMgr", value)

# Create a restore point
def create_restore_point(description):
    try:
        subprocess.run(["powershell", "-Command", f"Checkpoint-Computer -Description \"{description}\" -RestorePointType \"MODIFY_SETTINGS\""], check=True)
        print("Restore point created successfully.")
    except Exception as e:
        print(f"Failed to create restore point: {e}")

# List existing restore points
def list_restore_points():
    try:
        subprocess.run(["powershell", "-Command", "Get-ComputerRestorePoint"], check=True)
    except Exception as e:
        print(f"Failed to list restore points: {e}")

# Create a shadow copy
def create_shadow_copy(drive):
    try:
        subprocess.run(["vssadmin", "create", "shadow", f"/for={drive}"], check=True)
        print("Shadow copy created successfully.")
    except Exception as e:
        print(f"Failed to create shadow copy: {e}")

# List existing shadow copies
def list_shadow_copies():
    try:
        subprocess.run(["vssadmin", "list", "shadows"], check=True)
    except Exception as e:
        print(f"Failed to list shadow copies: {e}")

# Main
if __name__ == "__main__":
    
    if not is_admin():
        print("Requesting administrative privileges...")
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1
        )
        sys.exit()

    set_defender_state(enable=True)
    set_firewall_state(enable=True)
    set_task_manager_state(enable=True)

    create_restore_point("My restore point")
    list_restore_points()

    create_shadow_copy("C:")
    list_shadow_copies()
