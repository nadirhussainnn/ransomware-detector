import pandas as pd

def aggregate_data_with_labels(input_file, output_file):
    try:
        print("Loading raw data...")
        df = pd.read_csv(input_file)

        print("Converting timestamps to datetime format...")
        df['timestamp'] = pd.to_datetime(df['timestamp'])

        # Add operation type flags if not present in the raw dataset
        operation_types = ['created', 'encrypted', 'renamed', 'modified']
        for op_type in operation_types:
            df[f'files_{op_type}'] = (df['operation'] == op_type).astype(int)

        # Define row ranges with labels
        ranges_with_labels = [
            (0, 9, "normal"),
            (10, 58, "anomaly")  # Example placeholder
        ]

        aggregated_data = []

        for start, end, label in ranges_with_labels:
            print(f"Processing rows {start} to {end} with label '{label}'...")

            # Filter the rows for the current range
            range_df = df.iloc[start:end + 1]

            # Create time bins (3-second window)
            range_df['time_bin'] = (range_df['timestamp'] - range_df['timestamp'].min()).dt.total_seconds() // 3

            # Perform aggregation for full bins
            grouped = range_df.groupby('time_bin')

            aggregated_df = grouped.agg(
                num_files_affected=('operation', 'count'),
                num_varying_extensions=('file_extension', 'nunique'),
                avg_cpu_usage=('cpu_usage', 'mean'),
                avg_memory_usage=('memory_usage', 'mean'),
                avg_time_diff=('time_diff', 'mean'),
                avg_entropy=('entropy', 'mean'),
                avg_key_presses=('key_presses', 'mean'),
                avg_mouse_activity=('mouse_activity', 'mean'),
                avg_file_size=('file_size', 'mean'),
                avg_permission_denials=('permission_denials', 'sum'),
                avg_io_read_count=('io_read_count', 'mean'),
                avg_io_write_count=('io_write_count', 'mean'),
                avg_registry_edits=('registry_edits', 'sum'),
                firewall_disabled=('firewall_disabled', 'max'),
                defender_disabled=('defender_disabled', 'max'),
                task_manager_disabled=('task_manager_disabled', 'max'),
                shadow_copy_count=('shadow_copy_count', 'max'),
                restore_point_count=('restore_point_count', 'max'),
                num_processors=('num_processors', 'max'),
                files_created=('files_created', 'sum'),
                files_encrypted=('files_encrypted', 'sum'),
                files_renamed=('files_renamed', 'sum')
            ).reset_index()

            # Round floating-point values to 2 decimal places
            aggregated_df = aggregated_df.round(2)

            # Handle leftover rows
            valid_time_bins = aggregated_df['time_bin']
            leftover_rows = range_df.loc[~range_df['time_bin'].isin(valid_time_bins)]

            if not leftover_rows.empty:
                leftover_agg = leftover_rows.agg(
                    num_files_affected=('operation', 'count'),
                    num_varying_extensions=('file_extension', 'nunique'),
                    avg_cpu_usage=('cpu_usage', 'mean'),
                    avg_memory_usage=('memory_usage', 'mean'),
                    avg_time_diff=('time_diff', 'mean'),
                    avg_entropy=('entropy', 'mean'),
                    avg_key_presses=('key_presses', 'mean'),
                    avg_mouse_activity=('mouse_activity', 'mean'),
                    avg_file_size=('file_size', 'mean'),
                    avg_permission_denials=('permission_denials', 'sum'),
                    avg_io_read_count=('io_read_count', 'mean'),
                    avg_io_write_count=('io_write_count', 'mean'),
                    avg_registry_edits=('registry_edits', 'sum'),
                    firewall_disabled=('firewall_disabled', 'max'),
                    defender_disabled=('defender_disabled', 'max'),
                    task_manager_disabled=('task_manager_disabled', 'max'),
                    shadow_copy_count=('shadow_copy_count', 'max'),
                    restore_point_count=('restore_point_count', 'max'),
                    num_processors=('num_processors', 'max'),
                    files_created=('files_created', 'sum'),
                    files_encrypted=('files_encrypted', 'sum'),
                    files_renamed=('files_renamed', 'sum')
                ).to_frame().T
                leftover_agg['time_bin'] = 'leftover'
                aggregated_df = pd.concat([aggregated_df, leftover_agg], ignore_index=True)

            # Add label to the aggregated data
            aggregated_df['label'] = label
            aggregated_data.append(aggregated_df)

        # Combine all aggregated ranges
        final_aggregated_data = pd.concat(aggregated_data, ignore_index=True)

        print(f"Saving aggregated data to {output_file}...")
        final_aggregated_data.to_csv(output_file, index=False)
        print(f"Aggregated data saved successfully to {output_file}")

    except Exception as e:
        print(f"Error during aggregation: {e}")

# Run the script
if __name__ == "__main__":
    input_file = 'raw_data.csv'
    output_file = 'aggregated_data_with_labels.csv'
    aggregate_data_with_labels(input_file, output_file)
