"""
Decription:     Aggregates the raw_data.csv by creating a 3 second bins on data
Author:         Nadir Hussain
Dated:          Jan 25, 2025
"""
import pandas as pd

"""
Aggregates raw file system monitoring data into labeled datasets with time bins. Also, as I noted down the labels while using system normally and with injector, so I have defined the labels, this functions assigns labels too.
"""
def aggregate_data_with_labels(input_file, output_file):
    try:
        print("Loading raw data...")
        df = pd.read_csv(input_file)
        print(f"Total rows in dataset: {len(df)}")

        print("Converting timestamps to datetime format...")
        df['timestamp'] = pd.to_datetime(df['timestamp'], format='%Y-%m-%d %H:%M:%S', errors='coerce')

        # Drop rows with invalid or missing critical values
        critical_columns = ['operation', 'timestamp']
        before_cleaning = len(df)
        df = df.dropna(subset=critical_columns)
        after_cleaning = len(df)
        print(f"Rows removed during cleaning: {before_cleaning - after_cleaning}")

        # This is what I noted down while collecting raw_data
        ranges_with_labels = [
            # 0 to 678 records in raw_data, when i was using system normally
            (0, 678, "normal"), 
            # 679 to 1327 records in raw_data, when i injected the ransomware
            (679, 1327, "anomaly"), 
            (1328, 1837, "normal"),
            (1838, 2176, "normal"),
            (2177, 3599, "normal"),
            (3600, 3817, "anomaly"),
            (3818, 6550, "normal"),
            (6551, 6695, "anomaly"),
            (6696, 6951, "anomaly"),
            (6952, 7614, "normal"),
            (7615, 7918, "anomaly"),
            (7919, 9660 , "normal"),
            (9661, 10242, "anomaly"),
            (10243, 10292 , "normal"),
            (10293 , 18517, "normal"),
            (18518 , 23731, "normal"),
        ]

        aggregated_data = []

        for start, end, label in ranges_with_labels:
            print(f"\nProcessing rows {start} to {end} with label '{label}'...")

            # Validate start and end indices
            if start >= len(df) or end < start:
                print(f"Invalid range: {start} to {end}. Skipping...")
                continue

            start = max(0, start)
            end = min(len(df) - 1, end)
            print(f"Validated range: {start} to {end}")

            # Filter the rows for the current range
            range_df = df.iloc[start:end+1].copy()
            print(f"Range DataFrame size: {len(range_df)}")

            if range_df.empty:
                print(f"No data found in range {start} to {end}. Skipping...")
                continue

            # Create time bins (3-second window)
            range_df['time_bin'] = (range_df['timestamp'] - range_df['timestamp'].min()).dt.total_seconds() // 3

            # Perform aggregation for full bins i.e records that come under exactly 3 second window
            grouped = range_df.groupby('time_bin')
            aggregated_df = grouped.agg(
                num_files_affected=('operation', 'count'),
                num_varying_extensions=('file_extension', 'nunique'),
                cpu_usage=('cpu_usage', 'mean'),
                memory_usage=('memory_usage', 'mean'),
                time_diff=('time_diff', 'mean'),
                entropy=('entropy', 'mean'),
                key_presses=('key_presses', 'mean'),
                mouse_activity=('mouse_activity', 'mean'),
                file_size=('file_size', 'mean'),
                io_read_count=('io_read_count', 'mean'),
                io_write_count=('io_write_count', 'mean'),
                registry_edits=('registry_edits', 'sum'),
                shadow_copy_count=('shadow_copy_count', 'max'),
                restore_point_count=('restore_point_count', 'max'),
                firewall_disabled=('firewall_disabled', 'max'),
                defender_disabled=('defender_disabled', 'max'),
                task_manager_disabled=('task_manager_disabled', 'max'),
                sequential_operations=('sequential_operations', 'sum'),
                operation_sequence_length=('operation_sequence_length', 'max')
            ).reset_index()

            # Round floating-point values to 2 decimal places
            aggregated_df = aggregated_df.round(2)

            # Handle leftover rows i.e records that belong to the current rane, but at the end those could not be make a 3 second bin, so treated as leftover and are added all together as single record. Definitely, it will be record of all rows at the end where bin is less than 3 second
            valid_time_bins = aggregated_df['time_bin']
            leftover_rows = range_df.loc[~range_df['time_bin'].isin(valid_time_bins)]

            if not leftover_rows.empty:
                print(f"Handling leftover rows: {len(leftover_rows)} rows.")
                leftover_agg = leftover_rows.agg(
                    num_files_affected=('operation', 'count'),
                    num_varying_extensions=('file_extension', 'nunique'),
                    cpu_usage=('cpu_usage', 'mean'),
                    memory_usage=('memory_usage', 'mean'),
                    time_diff=('time_diff', 'mean'),
                    entropy=('entropy', 'mean'),
                    key_presses=('key_presses', 'mean'),
                    mouse_activity=('mouse_activity', 'mean'),
                    file_size=('file_size', 'mean'),
                    io_read_count=('io_read_count', 'mean'),
                    io_write_count=('io_write_count', 'mean'),
                    registry_edits=('registry_edits', 'sum'),
                    shadow_copy_count=('shadow_copy_count', 'max'),
                    restore_point_count=('restore_point_count', 'max'),
                    firewall_disabled=('firewall_disabled', 'max'),
                    defender_disabled=('defender_disabled', 'max'),
                    task_manager_disabled=('task_manager_disabled', 'max'),
                    sequential_operations=('sequential_operations', 'sum'),
                    operation_sequence_length=('operation_sequence_length', 'max')
                ).to_frame().T

                leftover_agg['time_bin'] = 'leftover'
                aggregated_df = pd.concat([aggregated_df, leftover_agg], ignore_index=True)

            # Add label to the aggregated data
            aggregated_df['label'] = label
            aggregated_data.append(aggregated_df)

        # Combine all aggregated ranges
        if aggregated_data:
            final_aggregated_data = pd.concat(aggregated_data, ignore_index=True)
            print(f"Saving aggregated data to {output_file}...")
            final_aggregated_data.to_csv(output_file, index=False)
            print(f"Aggregated data saved successfully to {output_file}")
        else:
            print("No aggregated data to save.")

    except Exception as e:
        print(f"Error during aggregation: {e}")

if __name__ == "__main__":
    
    # File that contains the output of monitor.py
    input_file = 'raw_data.csv'

    # This will be file used for training
    output_file = 'aggregated_data_with_labels.csv'
    aggregate_data_with_labels(input_file, output_file)