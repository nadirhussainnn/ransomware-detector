import os
import time
import pandas as pd
import joblib
import psutil
import random
import ctypes
import math
from plyer import notification
from threading import Thread, Event
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from pynput import keyboard, mouse

# Paths
MONITOR_DIR = "/Users/nadir/ransomware"
MODEL_FILE = "ransomware_detection_model.pkl"

# Globals for system metrics and input activity
cpu_usage = 0
memory_usage = 0
stop_event = Event()
key_presses = 0
mouse_activity = 0

# Logging configuration
import logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# File entropy calculation
def compute_entropy(file_path):
    try:
        with open(file_path, "rb") as f:
            data = f.read()
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
        return entropy
    except (PermissionError, FileNotFoundError) as e:
        logging.warning(f"Error computing entropy for {file_path}: {e}")
        return 0.0

# Monitor CPU and memory usage
def monitor_system_metrics():
    global cpu_usage, memory_usage
    while not stop_event.is_set():
        cpu_usage = psutil.cpu_percent(interval=1)
        memory_usage = psutil.virtual_memory().percent
        time.sleep(0.1)

# Monitor keyboard and mouse activity
def on_key_press(key):
    global key_presses
    key_presses += 1

def on_mouse_move(x, y):
    global mouse_activity
    mouse_activity += 1

# Event handler for filesystem monitoring
class FileEventHandler(FileSystemEventHandler):
    def __init__(self):
        self.last_timestamp = None
        self.data = []

    def log_event(self, event_type, file_path):
        global key_presses, mouse_activity, cpu_usage, memory_usage
        try:
            timestamp = time.time()
            time_diff = timestamp - self.last_timestamp if self.last_timestamp else 0
            file_stats = os.stat(file_path) if os.path.exists(file_path) else None
            file_size = file_stats.st_size if file_stats else 0
            file_extension = os.path.splitext(file_path)[-1] if file_stats else "unknown"
            entropy = compute_entropy(file_path)
            meta_changed = bool(random.choice([True, False]))

            log_entry = {
                "operation": event_type,
                "timestamp": pd.to_datetime(timestamp, unit="s"),
                "time_diff": time_diff,
                "key_presses": key_presses,
                "mouse_activity": mouse_activity,
                "file_size": file_size,
                "file_extension": file_extension,
                "entropy": entropy,
                "meta_changed": meta_changed,
                "cpu_usage": cpu_usage,
                "memory_usage": memory_usage
            }
            self.data.append(log_entry)
            key_presses = 0
            mouse_activity = 0
            self.last_timestamp = timestamp
        except Exception as e:
            logging.error(f"Error logging event: {e}")

    def on_created(self, event):
        self.log_event("created", event.src_path)

    def on_modified(self, event):
        self.log_event("modified", event.src_path)

    def on_deleted(self, event):
        self.log_event("deleted", event.src_path)

    def on_moved(self, event):
        self.log_event("renamed", event.dest_path)

# Load and validate the model
def load_model(model_path):
    model = joblib.load(model_path)
    logging.info("Model loaded successfully.")
    return model

# Check for ransomware
def check_for_ransomware(data, model):
    if not data:
        return False

    df = pd.DataFrame(data)
    df["time_bin"] = pd.to_datetime(df["timestamp"]).dt.floor("5s")
    aggregated_data = df.groupby("time_bin").agg(
        num_files_affected=("operation", "count"),
        num_varying_extensions=("file_extension", "nunique"),
        avg_cpu_usage=("cpu_usage", "mean"),
        avg_memory_usage=("memory_usage", "mean"),
        avg_time_diff=("time_diff", "mean"),
        avg_entropy=("entropy", "mean"),
        avg_key_presses=("key_presses", "mean"),
        avg_mouse_activity=("mouse_activity", "mean"),
        avg_file_size=("file_size", "mean"),
        #meta_changes=("meta_changed", "sum"),
        #files_created=("operation", lambda x: (x == "created").sum()),
        files_encrypted=("operation", lambda x: (x == "encrypted").sum()),
        #files_renamed=("operation", lambda x: (x == "renamed").sum()),
        files_modified=("operation", lambda x: (x == "modified").sum())
    ).reset_index()

    features = [
        "num_files_affected", "num_varying_extensions", "avg_cpu_usage",
        "avg_memory_usage", "avg_time_diff", "avg_entropy", "avg_key_presses",
        "avg_mouse_activity", "avg_file_size", 
        #"meta_changes", "files_created",
        "files_encrypted", 
        #"files_renamed", 
        "files_modified"
    ]
    for feature in features:
        if feature not in aggregated_data.columns:
            aggregated_data[feature] = 0

    X = aggregated_data[features]
    predictions = model.predict(X)
    probabilities = model.predict_proba(X) if hasattr(model, "predict_proba") else None

    logging.info("Model Predictions:\n%s", predictions)
    if probabilities is not None:
        logging.info("Model Prediction Probabilities:\n%s", probabilities)

    return "anomaly" in predictions

# Show notifications
def show_notification(title, message):
    logging.warning(f"{title}: {message}")
    notification.notify(title=title, message=message, timeout=10)

# Main function
def main():
    model = load_model(MODEL_FILE)
    keyboard_listener = keyboard.Listener(on_press=on_key_press)
    mouse_listener = mouse.Listener(on_move=on_mouse_move)
    keyboard_listener.start()
    mouse_listener.start()

    metrics_thread = Thread(target=monitor_system_metrics)
    metrics_thread.start()

    event_handler = FileEventHandler()
    observer = Observer()
    observer.schedule(event_handler, MONITOR_DIR, recursive=True)

    try:
        logging.info(f"Monitoring directory: {MONITOR_DIR}")
        observer.start()
        while True:
            time.sleep(5)
            if check_for_ransomware(event_handler.data, model):
                show_notification("Ransomware Detected", "Suspicious activity detected. Monitoring stopped.")
                break
    except KeyboardInterrupt:
        logging.info("Monitoring stopped.")
    finally:
        observer.stop()
        stop_event.set()
        metrics_thread.join()
    observer.join()

if __name__ == "__main__":
    main()