import scapy.all as scapy
import requests
import os
import json
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext
from bs4 import BeautifulSoup
from sklearn.ensemble import RandomForestClassifier
import numpy as np

def safe_insert(text_widget, message):
    text_widget.after(0, lambda: text_widget.insert(tk.END, message + "\n"))
    text_widget.after(0, text_widget.yview_moveto, 1.0)

def safe_execution(func, output_text, progress, *args):
    try:
        func(*args, output_text=output_text)
    except Exception as e: 
        safe_insert(output_text, f"Error in {func.__name__}: {str(e)}")
    progress.step(20)

def extract_metadata(url, output_text):
    try:
        proxies = {
            'http': 'socks5h://127.0.0.1:9050',
            'https': 'socks5h://127.0.0.1:9050'
        }
        response = requests.get(url, proxies=proxies, timeout=20)
        soup = BeautifulSoup(response.text, "html.parser")
        title = soup.title.string if soup.title else "No Title"
        meta_tags = {
            meta.get("name", "unknown"): meta.get("content", "")
            for meta in soup.find_all("meta") if meta.get("content")
        }
        safe_insert(output_text, f"Extracted Metadata:\nTitle: {title}\nMeta:\n{json.dumps(meta_tags, indent=4)}")
    except Exception as e:
        safe_insert(output_text, f"Error in extract_metadata: {str(e)}")

def osint_lookup(ip, output_text):
    try:
        api_key = os.getenv('XpxON78mtJ3r9b2AoyU2b5bBab34QSnY')
        if not api_key:
            raise ValueError("SHODAN_API_KEY environment variable not set.")
        response = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={api_key}", timeout=10)
        data = response.json()
        safe_insert(output_text, f"OSINT Data for {ip}:\n{json.dumps(data, indent=4)}")
    except Exception as e:
        safe_insert(output_text, f"Error in osint_lookup: {str(e)}")

def tor_exit_nodes(output_text):
    try:
        response = requests.get("https://check.torproject.org/exit-addresses", timeout=10)
        exit_nodes = [line.split()[1] for line in response.text.split('\n') if line.startswith("ExitAddress")]
        safe_insert(output_text, f"Detected Tor Exit Nodes:\n{exit_nodes[:5]} ...")
    except Exception as e:
        safe_insert(output_text, f"Error in tor_exit_nodes: {str(e)}")

def train_ml_model(output_text):
    try:
        X_train = np.random.rand(100, 5)
        y_train = np.random.randint(0, 2, 100)
        model = RandomForestClassifier(n_estimators=10)
        model.fit(X_train, y_train)
        safe_insert(output_text, "Machine Learning Model Trained Successfully.")
    except Exception as e:
        safe_insert(output_text, f"Error in train_ml_model: {str(e)}")

def get_public_ip_and_geo(output_text):
    try:
        # Using ipinfo.io API to get public IP and geolocation
        response = requests.get("https://ipinfo.io/json")
        data = response.json()
        ip = data.get('ip', 'N/A')
        city = data.get('city', 'N/A')
        region = data.get('region', 'N/A')
        country = data.get('country', 'N/A')
        loc = data.get('loc', 'N/A').split(',')
        latitude, longitude = loc if len(loc) == 2 else ('N/A', 'N/A')
        
        safe_insert(output_text, f"Public IP and Geolocation:\nIP: {ip}\nCity: {city}\nRegion: {region}\nCountry: {country}\nLatitude: {latitude}\nLongitude: {longitude}")
    except Exception as e:
        safe_insert(output_text, f"Error in get_public_ip_and_geo: {str(e)}")

def run_analysis(output_text, progress, onion_url):
    def analysis():
        output_text.delete(1.0, tk.END)
        progress['value'] = 0

        # Input validation: check if onion_url is empty or not a .onion domain
        if not onion_url.strip():
            safe_insert(output_text, "⚠️ Please enter a valid Onion URL before starting analysis.")
            return
        if not onion_url.strip().endswith(".onion"):
            safe_insert(output_text, "❌ Only .onion domain URLs are supported for analysis.")
            return

        safe_insert(output_text, "Starting Analysis...\n")

        # Get public IP and geolocation
        safe_execution(get_public_ip_and_geo, output_text, progress)

        # Execute other analysis functions
        safe_execution(tor_exit_nodes, output_text, progress)
        safe_execution(extract_metadata, output_text, progress, onion_url)
        safe_execution(train_ml_model, output_text, progress)

        progress['value'] = 100
        safe_insert(output_text, "\nAnalysis Complete.")

    thread = threading.Thread(target=analysis)
    thread.start()

def create_gui():
    root = tk.Tk()
    root.title("Tor Analysis Tool")
    root.geometry("900x700")
    root.configure(bg="#000000")

    style = ttk.Style()
    style.configure("TButton", font=("Arial", 12), background="#FFFFFF", foreground="#000000")
    style.configure("TLabel", font=("Arial", 14, "bold"), background="#000000", foreground="#FFFFFF")
    style.configure("TProgressbar", thickness=10, background="#FFFFFF")

    header_frame = tk.Frame(root, bg="#FFFFFF", height=60)
    header_frame.pack(fill=tk.X)
    ttk.Label(header_frame, text="Tor Analysis Tool", font=("Arial", 20, "bold"),
              background="#FFFFFF", foreground="#000000").pack(pady=15)

    input_frame = tk.Frame(root, bg="#000000")
    input_frame.pack(pady=10)
    ttk.Label(input_frame, text="Enter Onion Site URL:", background="#000000",
              foreground="#FFFFFF").pack(side=tk.LEFT, padx=5)
    onion_url_entry = ttk.Entry(input_frame, width=50)
    onion_url_entry.pack(side=tk.LEFT, padx=5)

    output_frame = tk.Frame(root, bg="#000000")
    output_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

    output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, width=110, height=25,
                                            font=("Consolas", 10), bg="#FFFFFF", fg="#000000")
    output_text.pack(fill=tk.BOTH, expand=True)

    progress = ttk.Progressbar(root, orient=tk.HORIZONTAL, length=500,
                               mode='determinate', style="TProgressbar")
    progress.pack(pady=10)

    button_frame = tk.Frame(root, bg="#000000")
    button_frame.pack(pady=10)

    start_button = ttk.Button(button_frame, text="Start Analysis",
                              command=lambda: run_analysis(output_text, progress, onion_url_entry.get()))
    start_button.pack(ipadx=10, ipady=5)

    root.mainloop()

if __name__ == "__main__":
    create_gui()