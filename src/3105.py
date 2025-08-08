import requests
import os
import json
import threading
import time
import pytz
from datetime import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext
from bs4 import BeautifulSoup
import pygame

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
        safe_insert(output_text, f"\n=== Extracted Metadata ===\nTitle: {title}\nMeta:\n{json.dumps(meta_tags, indent=4)}\n")
    except Exception as e:
        safe_insert(output_text, f"Error in extract_metadata: {str(e)}\n")

def geolocate_ip(ip, output_text, label=""):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
        if response.status_code != 200:
            raise Exception(f"Failed to fetch data: {response.status_code}")
        data = response.json()
        city = data.get('city', 'N/A')
        region = data.get('regionName', 'N/A')
        country = data.get('country', 'N/A')
        timezone = data.get('timezone', 'N/A')
        lat = data.get('lat', 'N/A')
        lon = data.get('lon', 'N/A')

        if timezone != 'N/A':
            tz = pytz.timezone(timezone)
            local_time = datetime.now(tz).strftime('%Y-%m-%d %H:%M:%S')
        else:
            local_time = 'N/A'

        safe_insert(output_text,
            f"\n=== {label} Geolocation ===\n"
            f"IP: {ip}\n"
            f"City: {city}\n"
            f"Region: {region}\n"
            f"Country: {country}\n"
            f"Latitude: {lat}\n"
            f"Longitude: {lon}\n"
            f"Timezone: {timezone}\n"
            f"Local Time: {local_time}\n"
            f"-------------------------------\n")

        time.sleep(1)

    except requests.exceptions.RequestException as e:
        safe_insert(output_text, f"Network error for {ip}: {str(e)}\n")
    except Exception as e:
        safe_insert(output_text, f"Error in geolocate_ip for {ip}: {str(e)}\n")

def tor_exit_nodes(output_text):
    try:
        response = requests.get("https://check.torproject.org/exit-addresses", timeout=10)
        exit_nodes = [line.split()[1] for line in response.text.split('\n') if line.startswith("ExitAddress")]
        safe_insert(output_text, f"\n=== Detected Tor Exit Nodes (showing first 5) ===\n{exit_nodes[:5]}\n")
        for ip in exit_nodes[:5]:
            geolocate_ip(ip, output_text, label=f"Tor Exit Node {ip}")
    except Exception as e:
        safe_insert(output_text, f"Error in tor_exit_nodes: {str(e)}\n")

def get_public_ip_and_geo(output_text):
    try:
        response = requests.get("http://ip-api.com/json", timeout=10)
        data = response.json()
        ip = data.get('query', 'N/A')
        geolocate_ip(ip, output_text, label="Your Public IP")
    except Exception as e:
        safe_insert(output_text, f"Error in get_public_ip_and_geo: {str(e)}\n")

def run_analysis(output_text, progress, onion_url):
    def analysis():
        output_text.delete(1.0, tk.END)
        progress['value'] = 0

        if not onion_url.strip():
            safe_insert(output_text, "⚠ Please enter a valid Onion URL before starting analysis.\n")
            return
        if not onion_url.strip().endswith(".onion"):
            safe_insert(output_text, "❌ Only .onion domain URLs are supported for analysis.\n")
            return

        safe_insert(output_text, "Starting Analysis...\n")

        safe_execution(get_public_ip_and_geo, output_text, progress)
        safe_execution(tor_exit_nodes, output_text, progress)
        safe_execution(extract_metadata, output_text, progress, onion_url)

        progress['value'] = 100
        safe_insert(output_text, "\n✅ Analysis Complete.\n")

    thread = threading.Thread(target=analysis)
    thread.start()

def create_gui():
    # Fix: Try dummy audio if no device
    try:
        pygame.mixer.init()
    except pygame.error:
        os.environ["SDL_AUDIODRIVER"] = "dummy"
        pygame.mixer.init()
        print("⚠ No audio device detected. Using dummy driver.")

    try:
        pygame.mixer.music.load("hacker_theme.mp3.mp3")
        pygame.mixer.music.play(-1)
    except Exception as e:
        print(f"⚠ Music not loaded: {e}")

    root = tk.Tk()
    root.title("Tor Analysis Tool")
    root.geometry("1000x750")
    root.configure(bg="black")

    style = ttk.Style()
    style.theme_use('clam')
    style.configure("TButton", font=("Courier", 12, "bold"), background="black", foreground="lime")
    style.configure("TLabel", font=("Courier", 14, "bold"), background="black", foreground="lime")
    style.configure("TProgressbar", thickness=10, background="lime")

    header_frame = tk.Frame(root, bg="black")
    header_frame.pack(fill=tk.X)
    ttk.Label(header_frame, text="TOR ANALYSIS TOOL", font=("Courier", 24, "bold"), foreground="lime").pack(pady=10)

    input_frame = tk.Frame(root, bg="black")
    input_frame.pack(pady=10)
    ttk.Label(input_frame, text="Enter Onion Site URL:", background="black", foreground="lime").pack(side=tk.LEFT, padx=5)
    onion_url_entry = ttk.Entry(input_frame, width=60, font=("Courier", 12))
    onion_url_entry.pack(side=tk.LEFT, padx=5)

    output_frame = tk.Frame(root, bg="black")
    output_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

    output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, width=120, height=30,
                                            font=("Courier", 12), bg="black", fg="lime", insertbackground="lime")
    output_text.pack(fill=tk.BOTH, expand=True)

    progress = ttk.Progressbar(root, orient=tk.HORIZONTAL, length=500, mode='determinate', style="TProgressbar")
    progress.pack(pady=10)

    button_frame = tk.Frame(root, bg="black")
    button_frame.pack(pady=10)

    start_button = ttk.Button(button_frame, text="Start Analysis",
                              command=lambda: run_analysis(output_text, progress, onion_url_entry.get()))
    start_button.pack(ipadx=10, ipady=5)

    root.mainloop()

if __name__ == "__main__":
    create_gui()

