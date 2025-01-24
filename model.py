import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, ConfusionMatrixDisplay
import joblib
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
DATASET = "aggregated_data_with_labels.csv"

def load_and_explore_dataset(file_path):
    """Load and explore the dataset."""
    logging.info("Loading dataset...")
    df = pd.read_csv(file_path)

    logging.info("\nDataset Information:")
    logging.info(df.info())
    logging.info("\nFirst 5 rows of the dataset:")
    logging.info(df.head())
    logging.info("\nDataset Description:")
    logging.info(df.describe())

    # Visualize correlations
    numeric_df = df.select_dtypes(include=['number'])
    plt.figure(figsize=(10, 8))
    sns.heatmap(numeric_df.corr(), annot=True, fmt=".2f", cmap="coolwarm", cbar=True)
    plt.title("Feature Correlation Heatmap")
    plt.show()

    return df

def preprocess_dataset(df):
    """Preprocess the dataset: handle missing values, split features and target."""
    logging.info("\nPreprocessing dataset...")
    
    # Separate features and target
    X = df.drop(columns=['label', 'time_bin'], errors='ignore')  # Drop irrelevant columns
    y = df['label']

    # Handle missing values
    if X.isnull().any().any():
        logging.info("Handling missing values...")
        X.fillna(X.median(), inplace=True)
        logging.info("Missing values filled with column median.")

    # Standardize features
    scaler = StandardScaler()
    X_scaled = pd.DataFrame(scaler.fit_transform(X), columns=X.columns)
    logging.info("\nFeatures standardized.")

    return X_scaled, y

def check_dataset_balance(y):
    """Check balance of the target labels."""
    balance = y.value_counts()
    logging.info("\nDataset Balance:")
    for label, count in balance.items():
        percentage = (count / len(y)) * 100
        logging.info(f"Label '{label}': {count} ({percentage:.2f}%)")
    return balance

def train_and_evaluate_models(X_train, X_test, y_train, y_test):
    """Train and evaluate multiple classifiers."""
    classifiers = {
        "Logistic Regression": LogisticRegression(max_iter=1000, class_weight='balanced'),
        "Random Forest": RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced'),
        "SVM": SVC(probability=True, random_state=42),
        "Gradient Boosting": GradientBoostingClassifier(random_state=42)
    }

    results = {}
    for name, model in classifiers.items():
        logging.info(f"\nTraining {name}...")
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)

        logging.info(f"{name} Accuracy: {accuracy:.4f}")
        logging.info(f"{name} Classification Report:\n{classification_report(y_test, y_pred)}")

        # Confusion matrix
        cm = confusion_matrix(y_test, y_pred)
        ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=model.classes_).plot(cmap="viridis")
        plt.title(f"Confusion Matrix: {name}")
        plt.show()

        results[name] = accuracy

    return results

def save_best_model(results, classifiers, X_train, y_train):
    """Save the best model based on accuracy."""
    best_model_name = max(results, key=results.get)
    logging.info(f"Best Model: {best_model_name} with Accuracy: {results[best_model_name]:.4f}")

    best_model = classifiers[best_model_name]
    best_model.fit(X_train, y_train)
    joblib.dump(best_model, "ransomware_detection_model.pkl")
    logging.info("Best model saved as 'ransomware_detection_model.pkl'.")

def main():
    # Load and explore the dataset
    df = load_and_explore_dataset(DATASET)

    # Preprocess the dataset
    X, y = preprocess_dataset(df)

    # Check dataset balance
    check_dataset_balance(y)

    # Split the dataset
    logging.info("\nSplitting dataset into training and testing sets...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    # Train and evaluate models
    logging.info("\nTraining and evaluating models...")
    results = train_and_evaluate_models(X_train, X_test, y_train, y_test)

    # Save the best model
    save_best_model(results, classifiers={
        "Logistic Regression": LogisticRegression(max_iter=1000, class_weight='balanced'),
        "Random Forest": RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced'),
        "SVM": SVC(probability=True, random_state=42),
        "Gradient Boosting": GradientBoostingClassifier(random_state=42)
    }, X_train=X_train, y_train=y_train)

if __name__ == "__main__":
    main()
