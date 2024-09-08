import re
from urllib.parse import urlparse
import tldextract
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer

def extract_advanced_features(url):
    parsed = urlparse(url)
    extracted = tldextract.extract(url)
    
    # Basic features
    length = len(url)
    domain_length = len(extracted.domain)
    path_length = len(parsed.path)
    
    # Advanced features
    num_digits = sum(c.isdigit() for c in url)
    num_parameters = len(parsed.query.split('&')) if parsed.query else 0
    has_https = int(parsed.scheme == 'https')
    num_subdomains = len(extracted.subdomain.split('.')) if extracted.subdomain else 0
    
    # Suspicious patterns
    suspicious_words = ['login', 'signin', 'account', 'bank', 'confirm', 'secure', 'webscr', 'update']
    count_suspicious = sum(word in url.lower() for word in suspicious_words)
    
    has_ip_pattern = int(bool(re.match(r'\d+\.\d+\.\d+\.\d+', extracted.domain)))
    
    return {
        'length': length,
        'domain_length': domain_length,
        'path_length': path_length,
        'num_digits': num_digits,
        'num_parameters': num_parameters,
        'has_https': has_https,
        'num_subdomains': num_subdomains,
        'count_suspicious': count_suspicious,
        'has_ip_pattern': has_ip_pattern
    }

def create_tfidf_features(urls, max_features=1000):
    vectorizer = TfidfVectorizer(max_features=max_features, analyzer='char', ngram_range=(3, 5))
    tfidf_features = vectorizer.fit_transform(urls)
    return tfidf_features, vectorizer
