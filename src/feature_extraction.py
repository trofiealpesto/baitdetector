import re
from urllib.parse import urlparse
import tldextract
import numpy as np

def extract_url_features(url):
    """
    Extract features from a URL.
    """
    parsed_url = urlparse(url)
    extracted = tldextract.extract(url)
    
    # Basic features
    length = len(url)
    num_dots = url.count('.')
    num_hyphens = url.count('-')
    num_underscores = url.count('_')
    num_digits = sum(c.isdigit() for c in url)
    has_https = int(parsed_url.scheme == 'https')
    
    # Domain-specific features
    domain_length = len(extracted.domain)
    subdomain_length = len(extracted.subdomain)
    top_level_domain = extracted.suffix
    
    # Path-specific features
    path_length = len(parsed_url.path)
    num_directories = parsed_url.path.count('/')
    num_parameters = len(parsed_url.query.split('&')) if parsed_url.query else 0
    
    # Lexical features
    num_suspicious_words = sum(1 for word in ['secure', 'account', 'banking', 'login', 'signin'] if word in url.lower())
    has_ip_address = int(bool(re.match(r'\d+\.\d+\.\d+\.\d+', extracted.domain)))
    
    return {
        'length': length,
        'num_dots': num_dots,
        'num_hyphens': num_hyphens,
        'num_underscores': num_underscores,
        'num_digits': num_digits,
        'has_https': has_https,
        'domain_length': domain_length,
        'subdomain_length': subdomain_length,
        'top_level_domain': top_level_domain,
        'path_length': path_length,
        'num_directories': num_directories,
        'num_parameters': num_parameters,
        'num_suspicious_words': num_suspicious_words,
        'has_ip_address': has_ip_address
    }

def process_urls(urls):
    """
    Process a list of URLs and return a feature matrix.
    """
    features = []
    for url in urls:
        url_features = extract_url_features(url)
        features.append(list(url_features.values()))
    
    return np.array(features)
