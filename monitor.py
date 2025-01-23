import os
import time
import csv
import psutil
import random
import ctypes
import winreg
from threading import Thread, Event
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from pynput import keyboard, mouse
import math
import win32api
import win32security
import win32con
import sys
import subprocess
from collections import deque

MONITOR_DIR = "/Users/nadir/ransomware"
RAW_DATA_CSV = "raw_data.csv"

class SystemMetricsCollector:
    def __init__(self):
        self.cpu_usage = 0
        self.memory_usage = 0
        self.io_read_count = 0
        self.io_write_count = 0
        self.shadow_copy_count = 0
        self.restore_point_count = 0
        self.registry_edits = 0
        self.security_states = {
            'firewall_disabled': False,
            'defender_disabled': False,
            'task_manager_disabled': False
        }
        self.prev_io = {'read': 0, 'write': 0}
        self.stop_event = Event()
        self.base_cpu = psutil.cpu_percent()
        self.base_memory = psutil.virtual_memory().percent

        self.process_metrics = {
            'created': 0,
            'terminated': 0,
            'prev_processes': set(psutil.pids())
        }
        self.file_patterns = {
            'sequential_ops': 0,
            'random_ops': 0,
            'accessed_files': deque(maxlen=10),
            'last_operation_time': {}
        }
        self.operation_sequences = deque(maxlen=20)

    def track_process_changes(self):
        while not self.stop_event.is_set():
            curr_processes = set(psutil.pids())
            created = len(curr_processes - self.process_metrics['prev_processes'])
            terminated = len(self.process_metrics['prev_processes'] - curr_processes)
            
            if created > 0 or terminated > 0:
                print(f"Process changes - Created: {created}, Terminated: {terminated}")
                self.process_metrics['created'] += created
                self.process_metrics['terminated'] += terminated
                self.process_metrics['prev_processes'] = curr_processes
            time.sleep(0.1)
                
    def get_io_counts(self):
        try:
            io_counters = psutil.disk_io_counters()
            current_read = io_counters.read_bytes
            current_write = io_counters.write_bytes
            
            delta_read = max(0, (current_read - self.prev_io['read']) / 1024)  # Convert to KB
            delta_write = max(0, (current_write - self.prev_io['write']) / 1024)  # Convert to KB
            
            self.prev_io['read'] = current_read
            self.prev_io['write'] = current_write
            
            return delta_read, delta_write
        except:
            return 0, 0

    def get_shadow_copy_count(self):
        try:
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            result = subprocess.run(
                ['vssadmin.exe', 'list', 'shadows'], 
                capture_output=True,
                text=True,
                startupinfo=si,
                shell=True
            )
            return result.stdout.count('Shadow Copy ID:')
        except Exception as e:
            print(f"Shadow copy error: {e}")
            return 0

    def get_restore_points(self):
        try:
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            result = subprocess.run(
                ['powershell.exe', '-NoProfile', '-Command', 
                'Get-ComputerRestorePoint | Measure-Object | Select-Object -ExpandProperty Count'],
                capture_output=True,
                text=True,
                startupinfo=si,
                shell=True
            )
            return int(result.stdout.strip() or 0)
        except Exception as e:
            print(f"Restore point error: {e}")
            return 0

    def check_security_settings(self):
        try:
            # Check Firewall - both paths must be disabled
            firewall_disabled = True
            firewall_paths = [
                r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile",
                r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile"
            ]
            for path in firewall_paths:
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
                    if winreg.QueryValueEx(key, "EnableFirewall")[0] != 0:
                        firewall_disabled = False
                    winreg.CloseKey(key)
                except:
                    firewall_disabled = False
            self.security_states['firewall_disabled'] = firewall_disabled

            # Windows Defender check
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows Defender")
                self.security_states['defender_disabled'] = winreg.QueryValueEx(key, "DisableAntiSpyware")[0] == 1
                winreg.CloseKey(key)
            except:
                self.security_states['defender_disabled'] = False

            # Task Manager check
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Policies\System")
                self.security_states['task_manager_disabled'] = winreg.QueryValueEx(key, "DisableTaskMgr")[0] == 1
                winreg.CloseKey(key)
            except:
                self.security_states['task_manager_disabled'] = False

        except Exception as e:
            print(f"Error checking security settings: {e}")

    def monitor_registry_changes(self):
        reg_keys = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows Defender"),
            (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"),
            (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Policies\System")
        ]
        
        prev_values = {}
        
        while not self.stop_event.is_set():
            for hkey, path in reg_keys:
                try:
                    key = winreg.OpenKey(hkey, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
                    i = 0
                    while True:
                        try:
                            name, data, type = winreg.EnumValue(key, i)
                            current = f"{path}\\{name}"
                            if current not in prev_values or prev_values[current] != data:
                                self.registry_edits += 1
                                prev_values[current] = data
                            i += 1
                        except WindowsError:
                            break
                    winreg.CloseKey(key)
                except Exception as e:
                    print(f"Registry error: {e}")
            time.sleep(0.5)

    def monitor_metrics(self):
        while not self.stop_event.is_set():
            self.cpu_usage = psutil.cpu_percent(interval=0.1)  # Shorter interval
            self.memory_usage = psutil.virtual_memory().percent
            new_read, new_write = self.get_io_counts()
            self.io_read_count = new_read
            self.io_write_count = new_write
            self.shadow_copy_count = self.get_shadow_copy_count()
            self.restore_point_count = self.get_restore_points()
            self.check_security_settings()
            time.sleep(0.1)

class InputMonitor:
    def __init__(self):
        self.key_presses = 0
        self.mouse_activity = 0

    def on_key_press(self, key):
        self.key_presses += 1

    def on_mouse_move(self, x, y):
        self.mouse_activity += 1

    def reset_counters(self):
        self.key_presses = 0
        self.mouse_activity = 0

def compute_entropy(file_path):
    try:
        if not os.path.exists(file_path):
            return 0.0
            
        with open(file_path, "rb") as f:
            data = f.read(8192)  # Read first 8KB for efficiency
        if not data:
            return 0.0
            
        byte_count = {}
        for byte in data:
            byte_count[byte] = byte_count.get(byte, 0) + 1
            
        total_bytes = len(data)
        entropy = 0
        
        for count in byte_count.values():
            prob = count / total_bytes
            entropy -= prob * math.log2(prob)
            
        return round(entropy, 3)
    except:
        return 0.0

class FileEventHandler(FileSystemEventHandler):
    def __init__(self, metrics_collector, input_monitor):
        super().__init__()
        self.last_timestamp = None
        self.metrics = metrics_collector
        self.input = input_monitor

    def analyze_file_pattern(self, event_type, file_path):
        current_time = time.time()
        file_key = f"{event_type}:{file_path}"
        
        if file_key in self.metrics.file_patterns['last_operation_time']:
            time_diff = current_time - self.metrics.file_patterns['last_operation_time'][file_key]
            if time_diff < 0.5:  # Sequential threshold
                self.metrics.file_patterns['sequential_ops'] += 1
                print(f"Sequential operation detected on {file_path}")
            else:
                self.metrics.file_patterns['random_ops'] += 1
                print(f"Random operation detected on {file_path}")
        
        self.metrics.file_patterns['last_operation_time'][file_key] = current_time
        self.metrics.file_patterns['accessed_files'].append(file_path)
        
        # Record operation sequence
        self.metrics.operation_sequences.append({
            'type': event_type,
            'path': file_path,
            'time': current_time
        })
        print(f"Operation sequence length: {len(self.metrics.operation_sequences)}")

    def normalize_metrics(self, file_size, cpu_usage, memory_usage):
        norm_size = math.log2(file_size + 1) if file_size > 0 else 0
        norm_cpu = cpu_usage / 100.0
        norm_memory = memory_usage / 100.0
        return norm_size, norm_cpu, norm_memory

    def get_file_size_kb(self, file_path):
        try:
            if os.path.exists(file_path):
                return round(os.path.getsize(file_path) / 1024, 2)  # Convert to KB
            return 0
        except:
            return 0

    def log_event(self, event_type, file_path):
        timestamp = time.time()
        time_diff = timestamp - self.last_timestamp if self.last_timestamp else 0

        self.analyze_file_pattern(event_type, file_path)
        file_size = self.get_file_size_kb(file_path)
        norm_size, norm_cpu, norm_memory = self.normalize_metrics(
            file_size, 
            self.metrics.cpu_usage, 
            self.metrics.memory_usage
        )

        print(f"Type: {event_type}")
        print(f"Path: {file_path}")
        print(f"Size: {file_size}KB (normalized: {norm_size:.2f})")
        print(f"Entropy: {compute_entropy(file_path)}")
        print(f"Sequential ops: {self.metrics.file_patterns['sequential_ops']}")
        print(f"Random ops: {self.metrics.file_patterns['random_ops']}")
        print(f"Process changes - Created: {self.metrics.process_metrics['created']}, Terminated: {self.metrics.process_metrics['terminated']}")

        try:
            with open(RAW_DATA_CSV, mode="a", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([
                    event_type,
                    time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp)),
                    round(time_diff, 3),
                    self.input.key_presses,
                    self.input.mouse_activity,
                    norm_size,
                    os.path.splitext(file_path)[-1],
                    compute_entropy(file_path),
                    norm_cpu,
                    norm_memory,
                    round(self.metrics.io_read_count, 2),
                    round(self.metrics.io_write_count, 2),
                    self.metrics.shadow_copy_count,
                    self.metrics.restore_point_count,
                    self.metrics.registry_edits,
                    self.metrics.security_states['firewall_disabled'],
                    self.metrics.security_states['defender_disabled'],
                    self.metrics.security_states['task_manager_disabled'],
                    psutil.cpu_count(),
                    self.metrics.process_metrics['created'],
                    self.metrics.process_metrics['terminated'],
                    self.metrics.file_patterns['sequential_ops'],
                    self.metrics.file_patterns['random_ops'],
                    len(self.metrics.operation_sequences)
                ])

            self.last_timestamp = timestamp
            self.input.reset_counters()

        except Exception as e:
            print(f"Error logging event: {e}")

    def on_created(self, event):
        self.log_event("created", event.src_path)

    def on_modified(self, event):
        self.log_event("modified", event.src_path)

    def on_deleted(self, event):
        self.log_event("deleted", event.src_path)

    def on_moved(self, event):
        if event.dest_path.endswith(".encrypted"):
            self.log_event("encrypted", event.dest_path)
        else:
            self.log_event("renamed", event.dest_path)

def main():
    # Keep console window open
    if not sys.stdout.isatty():
        sys.stdout = open('CONOUT$', 'w')
        sys.stderr = open('CONOUT$', 'w')

    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("Requesting admin privileges...")
        if sys.argv[-1] != 'asadmin':
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__ + ' asadmin', None, 1)
            sys.exit()

    if not os.path.exists(RAW_DATA_CSV):
        with open(RAW_DATA_CSV, mode="w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "operation", "timestamp", "time_diff", "key_presses", 
                "mouse_activity", "file_size", "file_extension", "entropy", 
                "cpu_usage", "memory_usage", "io_read_count", "io_write_count", 
                "shadow_copy_count", "restore_point_count", "registry_edits",
                "firewall_disabled", "defender_disabled", "task_manager_disabled",
                "num_processors", "processes_created", "processes_terminated",
                "sequential_operations", "random_operations", "operation_sequence_length"
            ])

    metrics_collector = SystemMetricsCollector()
    input_monitor = InputMonitor()

    keyboard_listener = keyboard.Listener(on_press=input_monitor.on_key_press)
    mouse_listener = mouse.Listener(on_move=input_monitor.on_mouse_move)
    keyboard_listener.start()
    mouse_listener.start()

    metrics_thread = Thread(target=metrics_collector.monitor_metrics)
    registry_thread = Thread(target=metrics_collector.monitor_registry_changes)
    process_thread = Thread(target=metrics_collector.track_process_changes)
    process_thread.start()
    metrics_thread.start()
    registry_thread.start()

    event_handler = FileEventHandler(metrics_collector, input_monitor)
    observer = Observer()
    observer.schedule(event_handler, MONITOR_DIR, recursive=True)

    try:
        print(f"Monitoring directory: {MONITOR_DIR}")
        observer.start()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        metrics_collector.stop_event.set()
        metrics_thread.join()
        registry_thread.join()
    finally:
        observer.join()

if __name__ == "__main__":
    main()