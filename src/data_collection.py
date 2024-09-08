import requests
import csv
import json
from io import StringIO
import random
import time
from urllib.parse import urlparse
import os


def fetch_phishing_urls_phishtank(limit=1000):
    """Fetch phishing URLs from PhishTank API."""
    api_url = "http://data.phishtank.com/data/online-valid.json"
    response = requests.get(api_url)
    if response.status_code == 200:
        data = response.json()
        return [entry['url'] for entry in data[:limit]]
    else:
        print("Failed to fetch data from PhishTank")
        return []

def fetch_phishing_urls_openphish(limit=1000):
    """Fetch phishing URLs from OpenPhish."""
    api_url = "https://openphish.com/feed.txt"
    response = requests.get(api_url)
    if response.status_code == 200:
        urls = response.text.strip().split('\n')
        return urls[:limit]
    else:
        print("Failed to fetch data from OpenPhish")
        return []

def fetch_legitimate_urls_alexa(limit=1000):
    """Fetch legitimate URLs from Alexa Top Sites."""
    alexa_url = "http://s3.amazonaws.com/alexa-static/top-1m.csv.zip"
    response = requests.get(alexa_url)
    if response.status_code == 200:
        csv_content = StringIO(response.content.decode('utf-8'))
        csv_reader = csv.reader(csv_content)
        urls = ["http://" + row[1] for row in csv_reader]
        return random.sample(urls, min(limit, len(urls)))
    else:
        print("Failed to fetch data from Alexa Top Sites")
        return []

def fetch_legitimate_urls_majestic(limit=1000):
    """Fetch legitimate URLs from Majestic Million."""
    majestic_url = "https://downloads.majestic.com/majestic_million.csv"
    response = requests.get(majestic_url)
    if response.status_code == 200:
        csv_content = StringIO(response.text)
        csv_reader = csv.reader(csv_content)
        next(csv_reader)  # Skip header
        urls = ["http://" + row[2] for row in csv_reader]
        return random.sample(urls, min(limit, len(urls)))
    else:
        print("Failed to fetch data from Majestic Million")
        return []

def validate_url(url):
    """Basic URL validation."""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def collect_balanced_dataset(size=2000):
    """Collect a balanced dataset of phishing and legitimate URLs."""
    half_size = size // 2
    quarter_size = half_size // 2

    phishing_urls = (
        fetch_phishing_urls_phishtank(quarter_size) +
        fetch_phishing_urls_openphish(quarter_size)
    )
    legitimate_urls = (
        fetch_legitimate_urls_alexa(quarter_size) +
        fetch_legitimate_urls_majestic(quarter_size)
    )

    # Validate URLs
    phishing_urls = [url for url in phishing_urls if validate_url(url)]
    legitimate_urls = [url for url in legitimate_urls if validate_url(url)]

    # Ensure we have the desired number of URLs
    phishing_urls = phishing_urls[:half_size]
    legitimate_urls = legitimate_urls[:half_size]

    all_urls = phishing_urls + legitimate_urls
    labels = [1] * len(phishing_urls) + [0] * len(legitimate_urls)

    # Shuffle the dataset
    combined = list(zip(all_urls, labels))
    random.shuffle(combined)
    all_urls, labels = zip(*combined)

    return list(all_urls), list(labels)

def save_dataset(urls, labels, filename='dataset.json'):
    """
    Save the dataset to a JSON file.
    
    Args:
    urls (list): List of URLs
    labels (list): List of corresponding labels (0 for legitimate, 1 for phishing)
    filename (str): Name of the file to save the dataset
    """
    dataset = [{"url": url, "label": label} for url, label in zip(urls, labels)]
    
    with open(filename, 'w') as f:
        json.dump(dataset, f, indent=2)
    
    print(f"Dataset saved to {filename}")

def load_dataset(filename='dataset.json'):
    """
    Load the dataset from a JSON file.
    
    Args:
    filename (str): Name of the file to load the dataset from
    
    Returns:
    tuple: (urls, labels)
    """
    if not os.path.exists(filename):
        print(f"File {filename} not found.")
        return None, None
    
    with open(filename, 'r') as f:
        dataset = json.load(f)
    
    urls = [entry['url'] for entry in dataset]
    labels = [entry['label'] for entry in dataset]
    
    print(f"Dataset loaded from {filename}")
    return urls, labels

def get_or_create_dataset(size=2000, filename='dataset.json'):
    """
    Get the dataset from file if it exists, otherwise create and save a new one.
    
    Args:
    size (int): Size of the dataset to create if needed
    filename (str): Name of the file to save/load the dataset
    
    Returns:
    tuple: (urls, labels)
    """
    urls, labels = load_dataset(filename)
    
    if urls is None or len(urls) != size:
        print(f"Creating new dataset of size {size}")
        urls, labels = collect_balanced_dataset(size)
        save_dataset(urls, labels, filename)
    
    return urls, labels