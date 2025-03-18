import csv
import json
import requests
import time
import ipaddress
import re
import pandas as pd
import numpy as np
import joblib
import os
from datetime import datetime
from tqdm import tqdm
from sklearn.ensemble import RandomForestClassifier

# API Key VirusTotal
API_KEY = 'ad5e8201521aabf0f7a81fc29435cc80fcc2d017f399a1efe1cc4e2836326084'

# File model
MODEL_PATH = "ml_model.pkl"

# File input/output
INPUT_FILE = 'input.csv'
SCAN_DATE = datetime.now().strftime("%Y-%m-%d")
OUTPUT_FILE = f'scan_results_{SCAN_DATE}.tsv'

# **CEK DAN LOAD MODEL (KALAU ADA)**
def load_or_train_model():
    if os.path.exists(MODEL_PATH):
        print("[INFO] Loading existing model...")
        return joblib.load(MODEL_PATH)
    
    print("[INFO] Training new model...")
    np.random.seed(42)  # Konsistensi hasil
    data = pd.DataFrame({
        'Malicious': np.random.randint(0, 10, 100),
        'Suspicious': np.random.randint(0, 10, 100),
        'Total': np.random.randint(10, 20, 100),
    })
    labels = np.random.choice(['False Positive', 'False Negative', 'True Positive', 'True Negative'], 100)

    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(data, labels)
    
    # Simpan model
    joblib.dump(model, MODEL_PATH)
    print("[INFO] Model saved!")
    return model

ml_model = load_or_train_model()

# Cek apakah string adalah IP
def is_ip(address):
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False

# Cek apakah string adalah domain
def is_domain(address):
    return re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', address) is not None

# Cek reputasi alamat di VirusTotal
def check_virustotal(address):
    url = f'https://www.virustotal.com/api/v3/domains/{address}'
    headers = {'x-apikey': API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        return None
    
    data = response.json()
    attributes = data.get('data', {}).get('attributes', {})

    return {
        'Country': attributes.get('country', 'Unknown'),
        'Owner': attributes.get('as_owner', 'Unknown'),
        'Malicious': attributes.get('last_analysis_stats', {}).get('malicious', 0),
        'Suspicious': attributes.get('last_analysis_stats', {}).get('suspicious', 0),
        'Total': sum(attributes.get('last_analysis_stats', {}).values()),
        'Scan Time': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

# Analisis file
def analyze_file():
    with open(INPUT_FILE, 'r', encoding='utf-8-sig') as infile:
        reader = csv.DictReader(infile, delimiter='\t')  
        print("[INFO] Header CSV:", reader.fieldnames)  # Debugging header
        
        # Cek apakah kolom yang diperlukan ada
        required_columns = {'Alert Id', 'Host IP', 'Remote Host'}
        if not required_columns.issubset(set(reader.fieldnames)):
            print("[ERROR] CSV tidak memiliki kolom yang diperlukan!")
            return
        
        # Ambil hanya baris dengan domain valid
        address_list = [row for row in reader if is_domain(row['Remote Host'])]

    with open(OUTPUT_FILE, 'w', newline='', encoding='utf-8') as outfile:
        fieldnames = ['Alert Id', 'Host IP', 'Address', 'Type', 'Country', 'Owner', 'Malicious', 'Suspicious', 'Total', 'Scan Time', 'ML Prediction']
        writer = csv.DictWriter(outfile, fieldnames=fieldnames, delimiter='\t')
        writer.writeheader()
        
        for row in tqdm(address_list, desc="Scanning Remote Hosts"):
            try:
                alert_id = row['Alert Id']
                host_ip = row['Host IP']
                address = row['Remote Host']
                
                vt_data = check_virustotal(address)
                if not vt_data:
                    continue
                
                # Prediksi menggunakan ML
                features = pd.DataFrame([{
                    'Malicious': vt_data['Malicious'],
                    'Suspicious': vt_data['Suspicious'],
                    'Total': vt_data['Total']
                }])
                
                ml_prediction = ml_model.predict(features)[0]
                
                writer.writerow({
                    'Alert Id': alert_id,
                    'Host IP': host_ip,
                    'Address': address,
                    'Type': 'Domain',
                    **vt_data,
                    'ML Prediction': ml_prediction
                })
                
                time.sleep(15)  # Hindari rate limit API
                
            except Exception as e:
                print(f"Error processing {address}: {e}")

# Ascii Banner
def print_banner():
    banner = r"""
    ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⣉⠟⣋⢻⣿⣿
    ⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿⠇⠃⠐⠀⣼⣿⣿
    ⡿⠟⠛⠛⢉⣭⣥⣆⠀⢹⠁⠉⣽⣆⢿⣿⣿
    ⡇⠀⠀⠀⠈⣿⣿⣿⣶⣾⣷⣶⣿⣿⢸⣿⣿
    ⡇⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⢸⣿⣿
    ⣿⣦⣀⠠⠼⢿⢿⣿⡿⠛⣋⣬⣿⣿⣸⣿⣿
    ⣿⣿⣿⣿⣷⡶⢈⠛⠻⠶⠚⠛⠋⣡⡜⢿⣿
    ⣿⣿⣿⣿⣿⠇⢨⣿⣶⣶⣶⣾⣿⢀⡿⡌⣿
    ⣿⣿⣿⣿⣿⡆⠘⠿⣿⣿⣿⣿⠿⢠⣴⡇⣽
    ⣿⣿⣿⣿⣿⣿⡄⣦⠀⠀⠀⠀⣰⠌⠉⢸⣿
    ⣿⣿⣿⣿⣿⣿⣷⢹⠿⢧⠸⡿⣿⣷⡇⢸⣿
    ⣿⣿⣿⣿⣿⣿⣿⠈⣓⡛⡀⠓⠬⠽⠇⢸⣿
    ⣿⣿⣿⣿⣿⣿⢋⣥⠉⠉⣛⠘⠛⠛⢃⢸⣿
    ⣿⣿⣿⣿⣿⣿⣌⠒⠛⢈⡀⠜⠵⠄⠁⣼⣿
    ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣶⣶⣶⣾⣿⣿

    [ VirusTotal Automated Scanner v0.3 ]
    """
    print("\033[91m" + banner + "\033[0m")  # Warna merah

if __name__ == '__main__':
    print_banner()
    analyze_file()
    print(f"\nScan selesai. Hasil tersimpan di {OUTPUT_FILE}")
