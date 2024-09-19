# BaitDetector: Phishing URL Detection

<p align="center">
<img align="center" width="752" alt="image" src="[https://github.com/user-attachments/assets/63f10b34-462c-4070-8a29-c29159d90f22](https://github.com/user-attachments/assets/d7023b1e-a62b-4acb-a1db-56f8b46dfe66)">
</p>

## Project Overview
BaitDetector is a machine learning-based tool designed to identify phishing URLs. It currently uses a Random Forest classifier trained on a dataset of both legitimate and phishing URLs to predict whether a given URL is potentially malicious.

## Features
- Data collection from reputable sources (GitHub's Phishing.Database and Majestic Million)
- Extensive feature extraction from URLs, including lexical and statistical features
- TF-IDF vectorization for n-gram analysis
- Random Forest classifier for prediction
- Cross-validation and performance metrics evaluation
- Visualization of feature importance and data distributions

## Requirements
- Python 3.x
- Libraries: requests, pandas, numpy, scikit-learn, matplotlib, seaborn, tldextract, patool

You can install the required libraries using:
```
pip install requests pandas numpy scikit-learn matplotlib seaborn tldextract patool
```

## Usage
1. Run the data collection and preprocessing cells to gather and prepare the dataset.
2. Execute the feature extraction cell to create the feature matrix.
3. Train the model and evaluate its performance using the provided cells.
4. Visualize the results and feature importance using the matplotlib and seaborn plots.

## Model Performance
The model's performance is evaluated using various metrics:
- Accuracy
- ROC AUC score
- Precision, Recall, and F1-score
- Cross-validation scores

Refer to the output of the evaluation cells for specific performance metrics on your dataset.

## Feature Importance
The project includes visualizations of the most important features for classification. This can provide insights into what characteristics are most indicative of phishing URLs.

## Data Visualization
Several plots are generated to help understand the distribution of features and their correlation:
- Histograms of numerical features
- Count plots of binary features
- Correlation heatmap
- Confusion matrix

## Future Improvements
- Implement real-time URL checking functionality
- Expand the feature set to include more advanced indicators of phishing
- Experiment with other machine learning algorithms or ensemble methods
- Develop a user interface for easy interaction with the model

## Disclaimer
This tool is for educational and research purposes only. It should not be used as the sole method for detecting phishing URLs in a production environment. Always use caution when dealing with suspicious URLs and consult with cybersecurity professionals for comprehensive protection.

## Contributing
Contributions to improve the model's accuracy, expand the feature set, or enhance the project's functionality are welcome. Please feel free to fork the repository and submit pull requests.
