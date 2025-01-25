"""
Decription:     Loading, pre-processing, analyzing data. Training, testing, saving model
Author:         Nadir Hussain
Dated:          Jan 25, 2025
"""

# Data manipulation and visualization
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt

# Pre-processing and splitting pkgs
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

# For finding best Parameter
from sklearn.model_selection import GridSearchCV

# Machine learning models from sklearn
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import KNeighborsClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.naive_bayes import GaussianNB

# Also implemented voting classifer to combine above all, and have a vote on prediction
from sklearn.ensemble import VotingClassifier

# Evaluation metrics
from sklearn.metrics import (
    confusion_matrix, 
    ConfusionMatrixDisplay,
    accuracy_score,
    f1_score, 
    recall_score, 
    matthews_corrcoef
    )

from sklearn.metrics import make_scorer, matthews_corrcoef

# Model saving and logging
import joblib
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

DATASET = "aggregated_data_with_labels.csv"

"""
Loads a dataset from a CSV file, explores its structure and statistical properties, and visualizes feature correlations.
"""
def load_and_explore_dataset(file_path):

    logging.info("Loading dataset...")
    df = pd.read_csv(file_path)

    logging.info("\nDataset Information:")
    logging.info(df.info())
    logging.info("\nFirst 5 rows of the dataset:")
    logging.info(df.head())
    logging.info("\nDataset Description:")
    logging.info(df.describe())

    # Visualizing correlations for my own info only. 
    # numeric_df = df.select_dtypes(include=['number'])
    # plt.figure(figsize=(10, 8))
    # sns.heatmap(numeric_df.corr(), annot=True, fmt=".2f", cmap="coolwarm", cbar=True)
    # plt.title("Feature Correlation Heatmap")
    # plt.show()

    return df

"""Preprocess the dataset: handle missing values, split features and target."""
def preprocess_dataset(df):
    logging.info("\nPreprocessing dataset...")
    
    # Separating features and target, and drop irrelevant columns for training
    X = df.drop(columns=['label', 'time_bin'], errors='ignore')  
    y = df['label']

    # Handling missing values
    if X.isnull().any().any():
        logging.info("Handling missing values...")
        X.fillna(X.median(), inplace=True)
        logging.info("Missing values filled with column median.")

    # Standardize features
    scaler = StandardScaler()
    X_scaled = pd.DataFrame(scaler.fit_transform(X), columns=X.columns)
    logging.info("\nFeatures standardized.")
    joblib.dump(scaler, "scaler.pkl")

    return X_scaled, y

"""Check the balance of dataset i.e number and % of two classes in dataset"""
def check_dataset_balance(y):
    balance = y.value_counts()
    logging.info("\nDataset Balance:")
    for label, count in balance.items():
        percentage = (count / len(y)) * 100
        logging.info(f"Label '{label}': {count} ({percentage:.2f}%)")
    return balance

"""Train and evaluate multiple classifiers."""
def train_and_evaluate_models(X_train, X_test, y_train, y_test):
    logging.info(X_train.info())

    classifiers ={
        "Logistic Regression": LogisticRegression(C= 10, solver= 'lbfgs'),
        "Random Forest": RandomForestClassifier(n_estimators=50, random_state=42, class_weight='balanced_subsample'),
        "SVM": SVC(probability=True, random_state=42, C=10, gamma='scale', kernel='rbf'),
        "Gradient Boosting": GradientBoostingClassifier(random_state=42, n_estimators=50, learning_rate=0.1),
        "K-Nearest Neighbors": KNeighborsClassifier(n_neighbors=3),
        "Decision Tree": DecisionTreeClassifier(random_state=42, class_weight=None, min_samples_split=5)
    }

    # Adding a Voting Classifier with soft rule, because all calssifiers are not reliable as of my experiements. And we want a more robust aggregation of prediction
    voting_clf = VotingClassifier(
        estimators=[
            ('lr', classifiers["Logistic Regression"]),
            ('rf', classifiers["Random Forest"]),
            ('svc', classifiers["SVM"]),
            ('gb', classifiers["Gradient Boosting"]),
            ('knn', classifiers["K-Nearest Neighbors"]),
            ('dt', classifiers["Decision Tree"])
        ],
        voting='soft'  
    )
    classifiers["Voting Classifier"] = voting_clf


    results = {}
    for name, model in classifiers.items():
        logging.info(f"\nTraining {name}...")
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)

        accuracy = accuracy_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred, average="weighted")
        recall = recall_score(y_test, y_pred, average="weighted")
        mcc = matthews_corrcoef(y_test, y_pred)

        # Confusion matrix
        cm = confusion_matrix(y_test, y_pred)
        ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=model.classes_).plot(cmap="viridis")
        plt.title(f"Confusion Matrix: {name}")
        plt.show()

        logging.info(f"{name} Accuracy: {accuracy:.4f}")
        logging.info(f"{name} F1 Score: {f1:.4f}")
        logging.info(f"{name} Recall: {recall:.4f}")
        logging.info(f"{name} MCC: {mcc:.4f}")

        results[name] = {
            "accuracy": accuracy,
            "f1": f1,
            "recall": recall,
            "mcc": mcc
        }  

    return results

"""Save the best model based on accuracy."""
def save_best_model(results, classifiers, X_train, y_train):
    # I chose mcc over accuracy, f1, recall, precision because our dataset is imbalanced, i.e 89.95% normal and 10.05% anomaly
    best_model_name = max(results, key=lambda name: results[name]["mcc"])
    logging.info(f"Best Model: {best_model_name} with MCC Score: {results[best_model_name]['mcc']:.4f}")


    best_model = classifiers[best_model_name]
    best_model.fit(X_train, y_train)

     # Check if the model has the feature_importances_ attribute, it shows which features matter the most for this best model
    if hasattr(best_model, "feature_importances_"):
        feature_importances = best_model.feature_importances_
        plt.barh(X_train.columns, feature_importances)
        plt.title(f"Feature Importances ({best_model_name})")
        plt.xlabel("Importance")
        plt.ylabel("Feature")
        plt.show()
    else:
        logging.info(f"The model '{best_model_name}' does not support feature importance.")

    joblib.dump(best_model, "best_model.pkl")
    logging.info("Best model saved as 'best_model.pkl'.")

# Add GridSearchCV for hyperparameter tuning
def perform_grid_search(X_train, y_train):
    param_grids = {
        "Random Forest": {
            "model": RandomForestClassifier(random_state=42),
            "params": {
                "n_estimators": [50, 100, 200],
                "max_depth": [None, 10, 20],
                "class_weight": ["balanced", "balanced_subsample"]
            }
        },
        "Gradient Boosting": {
            "model": GradientBoostingClassifier(random_state=42),
            "params": {
                "n_estimators": [50, 100, 200],
                "learning_rate": [0.01, 0.1, 0.2],
                "max_depth": [3, 5, 10]
            }
        },
        "SVM": {
            "model": SVC(probability=True, random_state=42),
            "params": {
                "C": [0.1, 1, 10],
                "kernel": ["linear", "rbf", "poly"],
                "gamma": ["scale", "auto"]
            }
        },
        "Logistic Regression": {
            "model": LogisticRegression(max_iter=1000, class_weight="balanced"),
            "params": {
                "C": [0.1, 1, 10],
                "solver": ["liblinear", "lbfgs"]
            }
        },
        "KNN": {
            "model": KNeighborsClassifier(),
            "params": {
                "n_neighbors": [3, 5, 7],
                "weights": ["uniform", "distance"],
                "metric": ["euclidean", "manhattan"]
            }
        },
        "Decision Tree": {
            "model": DecisionTreeClassifier(random_state=42),
            "params": {
                "max_depth": [None, 10, 20],
                "min_samples_split": [2, 5, 10],
                "class_weight": ["balanced", None]
            }
        }
    }

    best_params = {}
    mcc_scorer = make_scorer(matthews_corrcoef)

    for name, config in param_grids.items():
        print(f"Performing GridSearch for {name}...")
        grid_search = GridSearchCV(
            estimator=config["model"], 
            param_grid=config["params"], 
            cv=3, 
            scoring=mcc_scorer
        )
        grid_search.fit(X_train, y_train)
        best_params[name] = {
            "Best Params": grid_search.best_params_,
            "Best Score": grid_search.best_score_
        }
        print(f"Best parameters for {name}: {grid_search.best_params_}")
        print(f"Best MCC Score for {name}: {grid_search.best_score_:.4f}")

    # Save the best parameters to a text file
    output_file = "best_params_report.txt"
    with open(output_file, "w") as f:
        for model, details in best_params.items():
            f.write(f"Model: {model}\n")
            f.write(f"Best Params: {details['Best Params']}\n")
            f.write(f"Best MCC Score: {details['Best Score']:.4f}\n\n")

    print(f"Best parameters and scores saved to {output_file}")

def main():

    try:
        # Load and explore the dataset
        df = load_and_explore_dataset(DATASET)

        # Preprocess the dataset
        X, y = preprocess_dataset(df)

        # Check dataset balance
        check_dataset_balance(y)

        # Split the dataset
        logging.info("\nSplitting dataset into training and testing sets...")
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

        # Performing grid search cv to determine best params
        perform_grid_search(X_train, y_train)

        # Train and evaluate models
        logging.info("\nTraining and evaluating models...")
        results = train_and_evaluate_models(X_train, X_test, y_train, y_test)

        # Save the best model
        save_best_model(results, classifiers={
            "Logistic Regression": LogisticRegression(C= 10, solver= 'lbfgs'),
            "Random Forest": RandomForestClassifier(n_estimators=50, random_state=42, class_weight='balanced_subsample'),
            "SVM": SVC(probability=True, random_state=42, C=10, gamma='scale', kernel='rbf'),
            "Gradient Boosting": GradientBoostingClassifier(random_state=42, n_estimators=50, learning_rate=0.1),
            "K-Nearest Neighbors": KNeighborsClassifier(n_neighbors=3),
            "Decision Tree": DecisionTreeClassifier(random_state=42, class_weight=None)
        }, X_train=X_train, y_train=y_train)
        
    except Exception as e:
        print("Exception occured ", e)


if __name__ == "__main__":
    main()
