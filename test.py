import joblib
import pandas as pd

# Load the saved model and scaler
model = joblib.load("ransomware_detection_model.pkl")
scaler = joblib.load("scaler.pkl")

# New dummy input data point
data_point = {
    'num_files_affected': [12],
    'num_varying_extensions': [4],
    'cpu_usage': [0.76],
    'memory_usage': [0.85],
    'time_diff': [0.02],
    'entropy': [6.77],
    'key_presses': [8],
    'mouse_activity': [0],
    'file_size': [12345],
    'io_read_count': [20],
    'io_write_count': [180],
    'registry_edits': [7],
    'shadow_copy_count': [1],
    'restore_point_count': [1],
    'firewall_disabled': [0],  # FALSE corresponds to 0
    'defender_disabled': [0],  # FALSE corresponds to 0
    'task_manager_disabled': [0],  # FALSE corresponds to 0
    'sequential_operations': [0],
    'operation_sequence_length': [7]
}

# Convert to DataFrame
test_df = pd.DataFrame(data_point)

# Scale the input data
scaled_data = scaler.transform(test_df)

# Predict using the model
prediction = model.predict(scaled_data)

# Display the prediction
print("Prediction:", prediction)

# Check the result
if "anomaly" in prediction:
    print("The model predicts: Ransomware behavior detected!")
else:
    print("The model predicts: System is normal.")
