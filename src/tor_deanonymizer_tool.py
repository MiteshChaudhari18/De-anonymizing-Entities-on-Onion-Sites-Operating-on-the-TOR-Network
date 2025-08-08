import requests
from bs4 import BeautifulSoup
import whois
import shodan
import socket
from geopy.geocoders import Nominatim
from tkinter import Tk, Label, Button, Entry, Text, Scrollbar

# Shodan API key (replace with your key)
SHODAN_API_KEY = "YOUR_SHODAN_API_KEY"

# Setup for Shodan API
api = shodan.Shodan(SHODAN_API_KEY)

# Function to fetch HTTP headers
def fetch_headers(url):
    try:
        # Make request through Tor using SOCKS proxy
        proxies = {
            'http': 'socks5h://127.0.0.1:9050',
            'https': 'socks5h://127.0.0.1:9050'
        }
        response = requests.get(url, proxies=proxies, timeout=10)
        headers = response.headers
        return headers
    except Exception as e:
        return f"Error fetching headers: {e}"

# Function to extract links from the .onion site
def extract_links(url):
    try:
        # Make request through Tor using SOCKS proxy
        proxies = {
            'http': 'socks5h://127.0.0.1:9050',
            'https': 'socks5h://127.0.0.1:9050'
        }
        response = requests.get(url, proxies=proxies, timeout=10)
        soup = BeautifulSoup(response.content, 'html.parser')
        links = [a.get('href') for a in soup.find_all('a', href=True)]
        return links
    except Exception as e:
        return f"Error extracting links: {e}"

# Function to perform WHOIS lookup
def whois_lookup(domain):
    try:
        domain_info = whois.whois(domain)
        return domain_info
    except Exception as e:
        return f"Error fetching WHOIS info: {e}"

# Function to perform Shodan search for exposed services
def shodan_search(ip):
    try:
        results = api.search(ip)
        return results
    except shodan.APIError as e:
        return f"Error fetching Shodan results: {e}"

# Function to geolocate an IP address
def geolocate_ip(ip):
    geolocator = Nominatim(user_agent="tor_deanonymizer")
    try:
        location = geolocator.geocode(ip)
        return location.address if location else "Location not found"
    except Exception as e:
        return f"Error with geolocation: {e}"

# Function to handle user input and display results in the GUI
def analyze_onion_site():
    url = url_entry.get()

    # Fetch HTTP headers
    headers = fetch_headers(url)
    result_text.delete(1.0, "end")
    result_text.insert("end", "HTTP Headers:\n" + str(headers) + "\n\n")

    # Extract links from the page
    links = extract_links(url)
    result_text.insert("end", "Extracted Links:\n" + str(links) + "\n\n")

    # If there's a clearnet link, perform WHOIS lookup
    for link in links:
        if link.startswith("http"):
            domain = link.split('/')[2]  # Extract the domain from the URL
            whois_info = whois_lookup(domain)
            result_text.insert("end", f"WHOIS Info for {domain}:\n" + str(whois_info) + "\n\n")
            
            # Perform Shodan search for exposed services
            ip = socket.gethostbyname(domain)
            shodan_info = shodan_search(ip)
            result_text.insert("end", f"Shodan Info for {ip}:\n" + str(shodan_info) + "\n\n")
            
            # Geolocate IP
            geo_info = geolocate_ip(ip)
            result_text.insert("end", f"Geolocation for {ip}:\n" + str(geo_info) + "\n\n")

# Setup the GUI interface
root = Tk()
root.title("Tor Onion Site De-anonymizer")

# UI Elements
url_label = Label(root, text="Enter .onion URL (include http://):")
url_label.pack(padx=10, pady=5)

url_entry = Entry(root, width=50)
url_entry.pack(padx=10, pady=5)

analyze_button = Button(root, text="Analyze", command=analyze_onion_site)
analyze_button.pack(padx=10, pady=10)

result_text = Text(root, wrap="word", height=15, width=80)
result_text.pack(padx=10, pady=5)

scrollbar = Scrollbar(root, command=result_text.yview)
scrollbar.pack(side="right", fill="y")
result_text.config(yscrollcommand=scrollbar.set)

# Run the application
root.mainloop()
