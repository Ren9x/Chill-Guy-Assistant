import tkinter as tk
from tkinter import filedialog, messagebox
import pandas as pd
import numpy as np
import joblib
import os
import time
import requests
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier
from tkinter import PhotoImage
from PIL import Image, ImageTk

# API Key VirusTotal
API_KEY = 'ad5e8201521aabf0f7a81fc29435cc80fcc2d017f399a1efe1cc4e2836326084'

# File model
MODEL_PATH = "ml_model.pkl"

# Load atau Train Model

def load_or_train_model():
    if os.path.exists(MODEL_PATH):
        return joblib.load(MODEL_PATH)
    
    np.random.seed(42)
    data = pd.DataFrame({
        'Malicious': np.random.randint(0, 10, 100),
        'Suspicious': np.random.randint(0, 10, 100),
        'Total': np.random.randint(10, 20, 100),
    })
    labels = ['Benign' if m == 0 and s == 0 else 'Malicious' for m, s in zip(data['Malicious'], data['Suspicious'])]
    
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(data, labels)
    
    joblib.dump(model, MODEL_PATH)
    return model

ml_model = load_or_train_model()

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

# GUI dengan Tkinter
def upload_file():
    filepath = filedialog.askopenfilename(filetypes=[("CSV Files", "*.csv"), ("Excel Files", "*.xlsx"), ("TSV Files", "*.tsv")])
    if not filepath:
        return
    
    if filepath.endswith(".csv"):
        df = pd.read_csv(filepath)
    elif filepath.endswith(".tsv"):
        df = pd.read_csv(filepath, delimiter='\t')
    else:
        df = pd.read_excel(filepath)
    
    messagebox.showinfo("File Loaded", "File berhasil dimuat!")
    process_data(df)

def process_data(df):
    results = []
    for index, row in df.iterrows():
        address = row.get('Remote Host', '')
        if not isinstance(address, str):
            continue
        
        vt_data = check_virustotal(address)
        if not vt_data:
            continue
        
        features = pd.DataFrame([{ 'Malicious': vt_data['Malicious'], 'Suspicious': vt_data['Suspicious'], 'Total': vt_data['Total'] }])
        ml_prediction = ml_model.predict(features)[0]
        
        results.append({
            'Address': address,
            'Country': vt_data['Country'],
            'Owner': vt_data['Owner'],
            'Malicious': vt_data['Malicious'],
            'Suspicious': vt_data['Suspicious'],
            'Total': vt_data['Total'],
            'Scan Time': vt_data['Scan Time'],
            'ML Prediction': ml_prediction
        })
    
    if results:
        result_df = pd.DataFrame(results)
        result_df.to_csv("scan_results.csv", index=False)
        messagebox.showinfo("Scan Selesai", "Hasil scan tersimpan dalam 'scan_results.csv'")

# Buat GUI
root = tk.Tk()
root.title("Chill-guy assistant")
root.geometry("500x300")

# Load gambar
image = Image.open("C:/Users/Acer/Documents/Chill-Guy-Assistant/chillguy.jpg")  # Ganti dengan path gambar yang dipakai
image = image.resize((100, 100))  # Atur ukuran
photo = ImageTk.PhotoImage(image)

# Tampilkan di UI
img_label = tk.Label(root, image=photo)
img_label.pack(pady=10)


label = tk.Label(root, text="Chill-guy assistant", font=("Arial", 14))
label.pack(pady=10)

upload_button = tk.Button(root, text="Upload File (xlsx, csv, tsv)", command=upload_file)
upload_button.pack(pady=20)

root.mainloop()
