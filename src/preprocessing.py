import pandas as pd
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline

def preprocess_data(X, y):
    """
    Preprocess the feature matrix X and target vector y.
    """
    # Assume X is a pandas DataFrame
    # Identify numeric and categorical columns
    numeric_features = X.select_dtypes(include=['int64', 'float64']).columns
    categorical_features = X.select_dtypes(include=['object']).columns

    # Create preprocessing steps for numeric and categorical data
    numeric_transformer = StandardScaler()
    categorical_transformer = OneHotEncoder(handle_unknown='ignore')

    # Combine preprocessing steps
    preprocessor = ColumnTransformer(
        transformers=[
            ('num', numeric_transformer, numeric_features),
            ('cat', categorical_transformer, categorical_features)
        ])

    # Create a preprocessing and modeling pipeline
    pipeline = Pipeline([
        ('preprocessor', preprocessor)
    ])

    # Fit and transform the data
    X_processed = pipeline.fit_transform(X)

    return X_processed, y, pipeline

# Usage example:
# X_processed, y, preprocessing_pipeline = preprocess_data(X, y)