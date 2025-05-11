import requests
import pandas as pd
import gzip
import shutil
import os
from random import shuffle

def download_tranco_top_sites():
    print("📥 Downloading Tranco top domains...")
    url = "https://tranco-list.eu/top-1m.csv.zip"
    response = requests.get(url)
    with open("top-1m.csv.zip", "wb") as f:
        f.write(response.content)

    import zipfile
    with zipfile.ZipFile("top-1m.csv.zip", 'r') as zip_ref:
        zip_ref.extractall(".")

    df = pd.read_csv("top-1m.csv", header=None, names=["rank", "domain"])
    df['url'] = "http://" + df['domain']
    df = df[['url']].drop_duplicates()
    df['label'] = 0
    print(f"✅ Loaded {len(df)} legitimate URLs from Tranco")
    return df.head(50000)


def download_phishtank_feed():
    print("📥 Downloading PhishTank feed...")
    feed_url = "https://data.phishtank.com/data/online-valid.csv"
    response = requests.get(feed_url)
    
    if response.status_code != 200:
        raise Exception("Failed to download PhishTank feed")

    with open("phishtank.csv", "wb") as f:
        f.write(response.content)

    df = pd.read_csv("phishtank.csv")
    df = df[['url']].drop_duplicates()
    df['label'] = 1
    print(f"✅ Loaded {len(df)} phishing URLs")
    return df.head(50000)  # Limit to 50K for now

def create_combined_dataset():
    legit_df = download_tranco_top_sites()
    phishing_df = download_phishtank_feed()

    combined_df = pd.concat([legit_df, phishing_df], ignore_index=True)
    combined_df = combined_df.sample(frac=1).reset_index(drop=True)  # Shuffle
    combined_df.to_csv("phishing_dataset_large.csv", index=False)
    print("🎉 Dataset saved to phishing_dataset_large.csv")

from advanced_phishing_detector import AdvancedPhishingDetector

def train_model_on_dataset(dataset_path="phishing_dataset_large.csv"):
    print("\n🚀 Starting model training...")
    detector = AdvancedPhishingDetector()
    detector.train_model(dataset_path)
    print("🎉 Model training completed and saved to 'advanced_phishing_model.pkl'")

if __name__ == "__main__":
    create_combined_dataset()
    train_model_on_dataset()
