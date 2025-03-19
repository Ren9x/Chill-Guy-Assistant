import tkinter as tk
from tkinter import filedialog, messagebox
import pandas as pd
import os
import requests
import time
import re
from datetime import datetime
from PIL import Image, ImageTk

# Ambil API Key dari environment variable
API_KEY = os.getenv('VT_API_KEY')
if not API_KEY:
    messagebox.showerror("Error", "API Key tidak ditemukan. Harap set VT_API_KEY di environment variables.")
    exit()

# Validasi domain
def is_valid_domain(domain):
    pattern = r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"
    return bool(re.match(pattern, domain))

# Cek reputasi alamat di VirusTotal
def check_virustotal(address):
    time.sleep(2)  # Hindari rate limiting
    url = f'https://www.virustotal.com/api/v3/domains/{address}'
    headers = {'x-apikey': API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        return None

    data = response.json()
    attributes = data.get('data', {}).get('attributes', {})

    malicious = attributes.get('last_analysis_stats', {}).get('malicious', 0)
    suspicious = attributes.get('last_analysis_stats', {}).get('suspicious', 0)

    status = "Safe" if malicious == 0 and suspicious == 0 else "Potentially Harmful"

    return {
        'Country': attributes.get('country', 'Unknown'),
        'Owner': attributes.get('as_owner', 'Unknown'),
        'Malicious': malicious,
        'Suspicious': suspicious,
        'Total': sum(attributes.get('last_analysis_stats', {}).values()),
        'Scan Time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'Status': status
    }

# Fungsi untuk membaca file dengan handling error
def read_file(filepath):
    try:
        if not os.path.exists(filepath):
            messagebox.showerror("Error", "File tidak ditemukan.")
            return None

        if filepath.endswith(".csv"):
            df = pd.read_csv(filepath, on_bad_lines='skip', sep=None, engine='python')
        else:
            messagebox.showerror("Error", "Format file tidak didukung. Harap unggah file CSV.")
            return None

        if df.empty:
            messagebox.showerror("Error", "File kosong atau tidak memiliki data yang valid.")
            return None

        messagebox.showinfo("File Loaded", "File berhasil dimuat!")
        return df
    except pd.errors.ParserError as e:
        messagebox.showerror("Error", f"Terjadi kesalahan dalam membaca file: {str(e)}")
        return None
    except Exception as e:
        messagebox.showerror("Error", f"Kesalahan umum: {str(e)}")
        return None

# Fungsi untuk upload file
def upload_file():
    filepath = filedialog.askopenfilename(filetypes=[("CSV Files", "*.csv")])
    if not filepath:
        return

    df = read_file(filepath)
    if df is not None:
        process_data(df)

# Fungsi untuk memproses data
def process_data(df):
    results = []
    for index, row in df.iterrows():
        address = row.get('Remote Host', '')
        if not isinstance(address, str) or not is_valid_domain(address):
            continue

        vt_data = check_virustotal(address)
        if not vt_data:
            continue

        results.append({
            'Address': address,
            'Country': vt_data['Country'],
            'Owner': vt_data['Owner'],
            'Malicious': vt_data['Malicious'],
            'Suspicious': vt_data['Suspicious'],
            'Total': vt_data['Total'],
            'Scan Time': vt_data['Scan Time'],
            'Status': vt_data['Status']
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
try:
    image = Image.open("chillguy.jpg")  # Ganti dengan path gambar yang dipakai
    image = image.resize((100, 100))  # Atur ukuran
    photo = ImageTk.PhotoImage(image)

    # Tampilkan di UI
    img_label = tk.Label(root, image=photo)
    img_label.pack(pady=10)
except Exception as e:
    messagebox.showwarning("Gambar Error", f"Tidak dapat memuat gambar: {str(e)}")

label = tk.Label(root, text="Chill-guy assistant", font=("Arial", 14))
label.pack(pady=10)

upload_button = tk.Button(root, text="Upload File (CSV saja)", command=upload_file)
upload_button.pack(pady=20)

root.mainloop()