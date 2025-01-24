from sklearn.decomposition import PCA
import pandas as pd
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import silhouette_score
import logging
import plotly.express as px
import plotly.io as pio

pio.renderers.default = "browser"  # or "notebook" if using Jupyter Notebook

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def perform_clustering_with_pca_and_profile(input_file):
    try:
        logging.info("Loading the aggregated data...")
        df = pd.read_csv(input_file)

        logging.info("Aggregated data loaded successfully. Preview:")
        logging.info(df.head())

        # Save labels for later use
        if 'label' in df.columns:
            labels = df['label']
            logging.info("Excluding 'label' column from clustering.")
            df = df.drop(columns=['label'])
        else:
            labels = None

        # Select only numeric columns for clustering
        numeric_cols = df.select_dtypes(include=['float64', 'int64']).columns
        logging.info(f"Numeric columns selected for clustering: {list(numeric_cols)}")

        logging.info("Checking for missing data...")
        if df.isnull().values.any():
            logging.warning("Missing data found. Filling missing values with the column mean...")
            df.fillna(df.mean(), inplace=True)

        logging.info("Standardizing the data...")
        scaler = StandardScaler()
        data_scaled = scaler.fit_transform(df[numeric_cols])
        logging.info("Data standardization completed.")

        # Perform PCA for dimensionality reduction
        logging.info("Performing PCA for dimensionality reduction...")
        pca = PCA(n_components=2)
        data_pca = pca.fit_transform(data_scaled)
        logging.info("PCA completed. Explained variance ratio:")
        logging.info(pca.explained_variance_ratio_)

        # Determine Optimal Number of Clusters (k=3 assumed optimal)
        optimal_k = 2
        logging.info(f"Running KMeans with k={optimal_k} clusters...")
        kmeans = KMeans(n_clusters=optimal_k, random_state=42, n_init=10)
        kmeans.fit(data_pca)

        # Add cluster labels and PCA components to the DataFrame
        df['cluster'] = kmeans.labels_
        df['PCA1'] = data_pca[:, 0]
        df['PCA2'] = data_pca[:, 1]
        if labels is not None:
            df['label'] = labels

        # Interactive Visualization with Plotly
        logging.info("Visualizing clusters with interactive Plotly scatter plot...")

        # Build hover data only for columns not already included in the DataFrame
        hover_data = {
            'Cluster': df['cluster'],
        }
        if labels is not None:
            hover_data['Label'] = labels

        fig = px.scatter(
            df,
            x='PCA1',
            y='PCA2',
            color='cluster',
            title="Clusters Visualization (k=3)",
            hover_data=hover_data,  # Avoid duplicating PCA1 and PCA2
            labels={"cluster": "Cluster"}
        )

        fig.update_traces(marker=dict(size=10, opacity=0.7), selector=dict(mode='markers'))
        fig.show()

        logging.info("Clustering process completed successfully.")

    except Exception as e:
        logging.error(f"An error occurred: {e}", exc_info=True)

# Example usage
input_file = 'aggregated_data_with_labels.csv'
perform_clustering_with_pca_and_profile(input_file)