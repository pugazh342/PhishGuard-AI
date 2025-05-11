import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import requests
import re
import urllib.parse
import tldextract
import whois
from datetime import datetime
import socket
import ssl
from bs4 import BeautifulSoup
import warnings

warnings.filterwarnings('ignore')

class AdvancedPhishingDetector:
    def __init__(self):
        self.model = None
        self.feature_columns = None
        self.threshold = 0.85

    def prepare_dataset(self, dataset_path):
        df = pd.read_csv(dataset_path)
        if 'url' not in df.columns or 'label' not in df.columns:
            raise ValueError("Dataset must contain 'url' and 'label' columns")
        return df

    def extract_features(self, url):
        features = {}
        try:
            parsed = urllib.parse.urlparse(url)
            extracted = tldextract.extract(url)

            features['url_length'] = len(url)
            features['domain_length'] = len(extracted.domain)
            features['num_subdomains'] = len(extracted.subdomain.split('.')) if extracted.subdomain else 0
            features['has_ip'] = self._is_ip_address(extracted.domain)
            features['has_port'] = 1 if parsed.port else 0
            features['num_digits'] = sum(c.isdigit() for c in url)
            features['num_params'] = len(parsed.query.split('&')) if parsed.query else 0
            features['num_fragments'] = len(parsed.fragment.split('#')) if parsed.fragment else 0
            features['has_at_symbol'] = '@' in url
            features['has_redirect'] = '//' in parsed.path
            features['num_dots'] = url.count('.')
            features['num_hyphens'] = url.count('-')
            features['num_underscores'] = url.count('_')
            features['num_equals'] = url.count('=')
            features['num_ampersands'] = url.count('&')
            features['num_percent'] = url.count('%')
            features['has_https'] = parsed.scheme == 'https'

            # Domain age
            try:
                domain_info = whois.whois(extracted.registered_domain)
                creation = domain_info.creation_date
                if isinstance(creation, list):
                    creation = creation[0]
                features['domain_age_days'] = (datetime.now() - creation).days if creation else -1
            except:
                features['domain_age_days'] = -1

            # Page checks
            try:
                response = requests.get(url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
                features['page_exists'] = 1
                features['has_login_form'] = self._check_login_form(response.text)
                features['has_external_scripts'] = self._check_external_scripts(response.text)
            except:
                features['page_exists'] = 0
                features['has_login_form'] = 0
                features['has_external_scripts'] = 0

            features['has_valid_ssl'] = self._check_ssl_certificate(extracted.registered_domain)
            features['in_phishtank'] = 0  # placeholder, API support optional

            return pd.DataFrame([features])
        except Exception as e:
            print(f"Feature extraction failed: {e}")
            return None

    def train_model(self, dataset_path):
        df = self.prepare_dataset(dataset_path)
        features_list = []
        for url in df['url']:
            f = self.extract_features(url)
            if f is not None:
                features_list.append(f)

        X = pd.concat(features_list, ignore_index=True)
        y = df['label'].iloc[:len(X)]
        X.fillna(-1, inplace=True)

        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
        self.model = GradientBoostingClassifier(n_estimators=200, learning_rate=0.05, max_depth=5)
        self.model.fit(X_train, y_train)

        y_pred = self.model.predict(X_test)
        print("Classification Report:\n", classification_report(y_test, y_pred))
        print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred))

        self.feature_columns = X.columns.tolist()
        joblib.dump({'model': self.model, 'feature_columns': self.feature_columns}, "advanced_phishing_model.pkl")

    def predict(self, url):
        if self.model is None:
            saved = joblib.load("advanced_phishing_model.pkl")
            self.model = saved['model']
            self.feature_columns = saved['feature_columns']

        features = self.extract_features(url)
        if features is None:
            return "Error", 0

        for col in set(self.feature_columns) - set(features.columns):
            features[col] = 0
        features = features[self.feature_columns]

        proba = self.model.predict_proba(features)[0, 1]
        prediction = "Phishing" if proba >= self.threshold else "Legitimate"
        return prediction, round(proba, 3)

    def _is_ip_address(self, domain):
        try:
            socket.inet_aton(domain)
            return 1
        except:
            return 0

    def _check_login_form(self, html):
        soup = BeautifulSoup(html, 'html.parser')
        return 1 if any("login" in str(form).lower() for form in soup.find_all('form')) else 0

    def _check_external_scripts(self, html):
        soup = BeautifulSoup(html, 'html.parser')
        return 1 if any('src' in script.attrs and not script['src'].startswith('/') for script in soup.find_all('script', src=True)) else 0

    def _check_ssl_certificate(self, domain):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    ssock.getpeercert()
            return 1
        except:
            return 0
