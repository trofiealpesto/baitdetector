import requests
import csv
import json
from io import StringIO
import random
import time
from urllib.parse import urlparse
import os
import pandas as pd
import numpy as np
from scipy.sparse import hstack
from data_collection import get_or_create_dataset
from feature_engineering import extract_advanced_features, create_tfidf_features
from model import train_and_evaluate_models, hyperparameter_tuning, save_model



def main():
    # Step 1: Data Collection
    print("Getting or creating dataset...")
    urls, labels = get_or_create_dataset(size=2000, filename='baitdetector_dataset.json')

    # Step 2: Feature Extraction and Engineering
    print("Extracting features...")
    features = [extract_advanced_features(url) for url in urls]
    X_features = pd.DataFrame(features)
    
    print("Creating TF-IDF features...")
    tfidf_features, _ = create_tfidf_features(urls)
    
    # Combine features
    X = hstack([X_features, tfidf_features])
    y = np.array(labels)

    # Step 3: Model Experimentation
    print("Training and evaluating models...")
    results, models = train_and_evaluate_models(X, y)
    for model_name, metrics in results.items():
        print(f"\n{model_name} Results:")
        for metric, value in metrics.items():
            print(f"{metric}: {value:.4f}")

    # Step 4: Hyperparameter Tuning
    print("\nPerforming hyperparameter tuning...")
    best_results, best_model = hyperparameter_tuning(X, y, model_type='RandomForest')
    print("\nBest Model Results:")
    for metric, value in best_results.items():
        print(f"{metric}: {value}")

    # Step 5: Save the best model
    save_model(best_model, 'best_baitdetector_model.joblib')

    print("\nBaitDetector pipeline completed successfully!")

if __name__ == "__main__":
    main()