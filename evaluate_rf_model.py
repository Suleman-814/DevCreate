# evaluate_rf_model.py

import pandas as pd
import numpy as np
from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
from joblib import load
import seaborn as sns
import matplotlib.pyplot as plt

def evaluate_model(model_path, scaler_path, test_csv):
    print("Loading model and data...")
    # Load the model and scaler
    model = load(model_path)
    scaler = load(scaler_path)
    
    # Load and prepare test data
    df = pd.read_csv(test_csv)
    X = df[["packets", "bytes", "duration", "pps", "bps", "mean_iat", 
            "var_iat", "syn_ratio", "ack_ratio", "payload_bytes"]].values
    y_true = df['label'].values
    
    # Scale the features
    X = scaler.transform(X)
    
    # Make predictions
    print("Making predictions...")
    y_pred = model.predict(X)
    y_pred_proba = model.predict_proba(X)[:, 1]  # Probability scores
    
    # Calculate metrics
    precision = precision_score(y_true, y_pred)
    recall = recall_score(y_true, y_pred)
    f1 = f1_score(y_true, y_pred)
    accuracy = accuracy_score(y_true, y_pred)
    roc_auc = roc_auc_score(y_true, y_pred_proba)
    
    # Print results
    print("\nModel Evaluation Results:")
    print(f"Precision: {precision:.4f}")
    print(f"Recall: {recall:.4f}")
    print(f"F1 Score: {f1:.4f}")
    print(f"Accuracy: {accuracy:.4f}")
    print(f"ROC AUC: {roc_auc:.4f}")
    
    # Confusion Matrix
    cm = confusion_matrix(y_true, y_pred)
    print("\nConfusion Matrix:")
    print(cm)
    
    # Detailed Classification Report
    print("\nClassification Report:")
    print(classification_report(y_true, y_pred, target_names=['normal', 'anomaly']))
    
    # Plot confusion matrix
    plt.figure(figsize=(10, 8))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
    plt.title('Confusion Matrix')
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    plt.savefig('confusion_matrix.png')
    plt.close()
    
    # Feature importance if available
    if hasattr(model, 'feature_importances_'):
        features = ["packets", "bytes", "duration", "pps", "bps", "mean_iat", 
                   "var_iat", "syn_ratio", "ack_ratio", "payload_bytes"]
        importances = model.feature_importances_
        indices = np.argsort(importances)[::-1]
        
        print("\nFeature Importance:")
        for f in range(len(features)):
            print(f"{features[indices[f]]:<15} {importances[indices[f]]:.4f}")
        
        # Plot feature importance
        plt.figure(figsize=(12, 6))
        plt.title("Feature Importance")
        plt.bar(range(len(features)), importances[indices])
        plt.xticks(range(len(features)), [features[i] for i in indices], rotation=45)
        plt.tight_layout()
        plt.savefig('feature_importance.png')
        plt.close()

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Evaluate Random Forest IDS model')
    parser.add_argument('--model', default='models/rf_model.joblib',
                      help='Path to the trained model')
    parser.add_argument('--scaler', default='models/scaler.joblib',
                      help='Path to the fitted scaler')
    parser.add_argument('--test-data', default='data/processed_dataset.csv',
                      help='Path to the test dataset')
    
    args = parser.parse_args()
    
    evaluate_model(args.model, args.scaler, args.test_data)
