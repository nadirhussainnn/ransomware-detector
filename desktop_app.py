"""
Decription:     A desktop app, that monitors the data in real-time, sends it to saved_model, and returns status of prediction i.e Normal or anomaly
Author:         Nadir Hussain
Dated:          Jan 25, 2025
"""

import os
import sys
import time
import math
from collections import deque
import threading
from threading import Thread, Event

# For loading model and data processing
import joblib
import pandas as pd
from sklearn.preprocessing import StandardScaler

# For monitoring filesystem events
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# For capturing keyboard and mouse events
from pynput import keyboard, mouse

# for cpu, memory and other resource details
import psutil

# For registry edits, shadow copy and restore point operations
import subprocess

# For interacting with Windows APIs and settings
import ctypes
import winreg
import win32api
import win32security
import win32con

# Allow user to select directory to be monitored
import tkinter as tk
from tkinter import filedialog

# For alert
from plyer import notification
from plyer.utils import platform
from plyer.platforms.win.notification import WindowsNotification

# Show all columns in pandas DF
pd.set_option("display.max_columns", None)  

# constant names of files to be loaded
MODEL_FILE = "best_model.pkl"
SCALER_FILE = "scaler.pkl"


# Allowing users to select a directory under monitoring, we could do this for whole system but it was making system too slow
def select_directory():
    root = tk.Tk()
    root.withdraw()  # Hide main window
    directory = filedialog.askdirectory(title="Select Directory to Monitor")
    return directory

"""
Collects and monitors system metrics related to CPU, memory, I/O, and security settings.
"""
class SystemMetricsCollector:
    def __init__(self):

        # Attributes for CPU, memory, I/O counts, security settings etc.
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

        self.file_patterns = {
            'sequential_ops': 0,
            'accessed_files': deque(maxlen=10),
            'last_operation_time': {}
        }
        self.operation_sequences = deque(maxlen=20)

    """
    Calculates changes in disk I/O (read and write) in kilobytes.
    """
    def get_io_counts(self):
        try:
            io_counters = psutil.disk_io_counters()
            current_read = io_counters.read_bytes
            current_write = io_counters.write_bytes
            delta_read = max(0, (current_read - self.prev_io['read']) / 1024)
            delta_write = max(0, (current_write - self.prev_io['write']) / 1024)
            self.prev_io['read'] = current_read
            self.prev_io['write'] = current_write
            return delta_read, delta_write
        except:
            return 0, 0
    """Counts the number of shadow copies on the system using the vssadmin tool."""
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
    
    """Retrieves the count of system restore points using PowerShell commands."""
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

    """ Checks for security settings for the system."""
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

    """Monitors specific registry keys for changes in values."""
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

    """Continuously monitors CPU, memory, I/O, shadow copies, restore points, and security settings."""
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


"""Monitors keyboard presses and mouse movements"""
class InputMonitor:
    def __init__(self):
        self.key_presses = 0
        self.mouse_activity = 0

    """Increments the counter for key presses when a key is pressed.
    In normal, key presses are more, exp: rename. While automated actions have very low key presses
    """
    def on_key_press(self, key):
        self.key_presses += 1

    """Increments the counter for mouse activity mouse is moved. In normal, mouse movements are more. While auto-mated actions have very low mouse movements"""
    def on_mouse_move(self, x, y):
        self.mouse_activity += 1

    """Resets the counters for key presses and mouse activity to zero"""
    def reset_counters(self):
        self.key_presses = 0
        self.mouse_activity = 0


"""Calculates the Shannon entropy of a file's content to estimate randomness. Encrypted files have more shannon entropy usually"""
def compute_entropy(file_path):
    try:
        if not os.path.exists(file_path):
            return 0.0
        with open(file_path, "rb") as f:
            data = f.read(8192)  
        if not data:
            return 0.0
        byte_count = [0] * 256
        for byte in data:
            byte_count[byte] += 1
        total_bytes = len(data)
        entropy = -sum(
            (count / total_bytes) * math.log2(count / total_bytes)
            for count in byte_count if count > 0
        )
        return round(entropy, 3)
    except:
        return 0.0

"""
Handles file system events and integrates them with metrics collection, input monitoring, and machine learning model predictions for detecting anomalies.
"""
class FileEventHandler(FileSystemEventHandler):
    def __init__(self, metrics_collector, input_monitor, model, scaler):
        super().__init__()
        self.model = model
        self.scaler = scaler
        self.last_timestamp = None
        self.metrics = metrics_collector
        self.input = input_monitor
        self.logged_events = []  # Track last events by file path
        self.last_aggregation_time = time.time()  # Track the last aggregation timestamp
        self.lock = threading.Lock()  # Thread-safe access to logged_events

        # Starts a thread for periodic aggregation. We call model for prediction every 3 seconds. Till 3 seconds, all events occured in monitored directory are preserved. If no events in past 3 seconds, we don't call predict
        self.aggregation_thread = threading.Thread(target=self.periodic_aggregation)
        self.aggregation_thread.daemon = True
        self.aggregation_thread.start()

    def periodic_aggregation(self):
        while True:
            # Call every 3 seconds
            time.sleep(3)  
            self.aggregate_and_predict()
    
    # Show notifications with title, message and icon
    def show_notification(self, title, message):
        notif_window = tk.Tk()
        notif_window.title(title)
        notif_window.geometry("300x100")
        notif_window.configure(bg='white')
        notif_window.attributes('-topmost', True)

        label_title = tk.Label(notif_window, text=title, bg='white', fg='black', font=("Arial", 12, "bold"))
        label_title.pack(pady=10)

        label_msg = tk.Label(notif_window, text=message, bg='white', fg='black', wraplength=250)
        label_msg.pack(pady=10)

        def close():
            notif_window.destroy()

        notif_window.after(5000, close)  # Close after 4 seconds
        notif_window.mainloop()
    # def show_notification(self, title, message):
    #     current_dir = os.path.dirname(os.path.abspath(__file__))
    #     icon_path = os.path.join(current_dir, "static", "icon.ico")

    #     # Debug print
    #     print(f"Icon path: {icon_path}")
    #     print(f"Icon exists: {os.path.exists(icon_path)}")

    #     notification.notify(
    #         title=title,
    #         message=message,
    #         app_icon = icon_path,
    #         app_name="Ransomware Detector",
    #         timeout=10
    #     )

    "It runs in separate thread, calls model to predict on aggregated 3 second bin"
    def aggregate_and_predict(self):
        current_time = time.time()

        with self.lock:
            # Filter events in the last 3 seconds
            recent_events = [
                event for event in self.logged_events
                if current_time - event['timestamp'] <= 3
            ]

            # If no events in past 3 seconds, we don't call predict
            if not recent_events:
                return

            # Convert to DataFrame for aggregation
            df = pd.DataFrame(recent_events)
            print(f"Aggregating {len(df)} events from the last 3 seconds...")

            # Aggregate the events, with same logic as it was used for training set data aggregation
            aggregated_data = pd.DataFrame({
                'num_files_affected': [len(df)],
                'num_varying_extensions': [df['file_extension'].nunique()],
                'cpu_usage': [df['cpu_usage'].mean()],
                'memory_usage': [df['memory_usage'].mean()],
                'time_diff': [df['time_diff'].mean()],
                'entropy': [df['entropy'].mean()],
                'key_presses': [df['key_presses'].mean()],
                'mouse_activity': [df['mouse_activity'].mean()],
                'file_size': [df['file_size'].mean()],
                'io_read_count': [df['io_read_count'].mean()],
                'io_write_count': [df['io_write_count'].mean()],
                'registry_edits': [df['registry_edits'].sum()],
                'shadow_copy_count': [df['shadow_copy_count'].max()],
                'restore_point_count': [df['restore_point_count'].max()],
                'firewall_disabled': [df['firewall_disabled'].max()],
                'defender_disabled': [df['defender_disabled'].max()],
                'task_manager_disabled': [df['task_manager_disabled'].max()],
                'sequential_operations': [self.metrics.file_patterns['sequential_ops']],
                'operation_sequence_length': [len(self.metrics.operation_sequences)]
            })

            # Scale the aggregated data. We use same scalar that was used for model training
            aggregated_data_scaled = self.scaler.transform(aggregated_data)

            # Predict probabilities using the model
            probabilities = self.model.predict_proba(aggregated_data_scaled)

            # Display the probabilities
            print("Probabilities:", probabilities)

            # Get the label with the highest probability (if needed)
            prediction = self.model.classes_[probabilities.argmax(axis=1)]

            # Example: Take action based on a probability threshold for "anomaly"
            anomaly_probability = probabilities[0, list(self.model.classes_).index("anomaly")]
            if anomaly_probability > 0.5: 
                self.show_notification("🚨RANSOMWARE ATTACK🚨", "Ransomware attack detected! Take immediate action.")

                print("Ransomware behavior detected! Take immediate action.")
            else:
                print("System is normal.")

            self.logged_events = recent_events

    
    """Analyzes file operation patterns to detect sequential operations and track accessed files. Ransomware typically make large sequential actions for exp it may create folder, then files in it, and then encrypt them. Normal behavior is random"""
    def analyze_file_pattern(self, event_type, file_path):
        current_time = time.time()
        file_key = f"{event_type}:{file_path}"

        # Default: Increment random_operations for new or unrelated events
        is_random = True

        if file_key in self.metrics.file_patterns['last_operation_time']:
            time_diff = current_time - self.metrics.file_patterns['last_operation_time'][file_key]

            if time_diff < 1.0:  # Sequential threshold i.e things done on folder/file in past 1 second
                self.metrics.file_patterns['sequential_ops'] += 1
                print(f"Sequential operation detected: {file_path}")
            else:
                # Reset sequential_ops if the sequence is broken
                print(f"Sequence broken. Resetting sequential operations.")
                self.metrics.file_patterns['sequential_ops'] = 0

        # Update last operation time and accessed files
        self.metrics.file_patterns['last_operation_time'][file_key] = current_time
        self.metrics.file_patterns['accessed_files'].append(file_path)

        # Record the operation in the sequence
        self.metrics.operation_sequences.append({
            'type': event_type,
            'path': file_path,
            'time': current_time
        })

        # Reset sequence length if it reaches maxlen
        if len(self.metrics.operation_sequences) == self.metrics.operation_sequences.maxlen:
            print(f"Operation sequence reached max length ({self.metrics.operation_sequences.maxlen}). Resetting...")
            self.metrics.operation_sequences.clear()

    # normalize file size, cpu and memory usage for consistent scaling
    def normalize_metrics(self, file_size, cpu_usage, memory_usage):
        norm_size = math.log2(file_size + 1) if file_size > 0 else 0
        norm_cpu = cpu_usage / 100.0
        norm_memory = memory_usage / 100.0
        return norm_size, norm_cpu, norm_memory

    # Get file size in KBs
    def get_file_size_kb(self, file_path):
        try:
            if os.path.exists(file_path):
                return round(os.path.getsize(file_path) / 1024, 2)  # Convert to KB
            return 0
        except:
            return 0
    
    """Logs details of a file system event and updates relevant metrics."""
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
        
        # This is raw data, means everything that happens is collected here. Aggregator will aggregate into bins, as I did for training, with separate aggregator.py code
        try:
            self.logged_events.append(
                {
                    'operation': event_type,
                    'timestamp': timestamp,
                    'time_diff': round(time_diff, 3),
                    'key_presses': self.input.key_presses,
                    'mouse_activity': self.input.mouse_activity,
                    'file_size': norm_size,
                    'file_extension': os.path.splitext(file_path)[-1],
                    'entropy': compute_entropy(file_path),
                    'cpu_usage': norm_cpu,
                    'memory_usage': norm_memory,
                    'io_read_count': round(self.metrics.io_read_count, 2),
                    'io_write_count': round(self.metrics.io_write_count, 2),
                    'shadow_copy_count': self.metrics.shadow_copy_count,
                    'restore_point_count': self.metrics.restore_point_count,
                    'registry_edits': self.metrics.registry_edits,
                    'firewall_disabled': self.metrics.security_states['firewall_disabled'],
                    'defender_disabled': self.metrics.security_states['defender_disabled'],
                    'task_manager_disabled': self.metrics.security_states['task_manager_disabled'],
                    'sequential_operations': self.metrics.file_patterns['sequential_ops'],
                    'operation_sequence_length': len(self.metrics.operation_sequences)
                }
            )

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
        self.log_event("renamed", event.dest_path)

def main():
    # Keep console window open
    if not sys.stdout.isatty():
        sys.stdout = open('CONOUT$', 'w')
        sys.stderr = open('CONOUT$', 'w')

    # Run under admin previliges
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("Requesting admin privileges...")
        if sys.argv[-1] != 'asadmin':
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__ + ' asadmin', None, 1)
            sys.exit()

     # Get directory from user
    MONITOR_DIR = select_directory()
    if not MONITOR_DIR:
        print("No directory selected. Exiting...")
        return
        
    # Multiple threads run and they monitor different things
    metrics_collector = SystemMetricsCollector()
    input_monitor = InputMonitor()

    keyboard_listener = keyboard.Listener(on_press=input_monitor.on_key_press)
    mouse_listener = mouse.Listener(on_move=input_monitor.on_mouse_move)

    keyboard_listener.start()
    mouse_listener.start()

    metrics_thread = Thread(target=metrics_collector.monitor_metrics)
    registry_thread = Thread(target=metrics_collector.monitor_registry_changes)

    metrics_thread.start()
    registry_thread.start()

    # Loading best model and scalar saved during train time
    model = joblib.load(MODEL_FILE)
    scaler = joblib.load(SCALER_FILE)

    # Observe all events of files
    event_handler = FileEventHandler(metrics_collector, input_monitor, model, scaler)
    observer = Observer()
    observer.schedule(event_handler, MONITOR_DIR, recursive=True)

    try:
        print(f"Monitoring directory for prediction: {MONITOR_DIR}")
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
