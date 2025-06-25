from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from bs4 import BeautifulSoup
import re
import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading
import time


def extract_google_link(href):
    if href.startswith("/url?q="):
        return href.split("/url?q=")[1].split("&")[0]
    return href


# Enhanced search using Selenium
def search_web(email, engine="google"):
    query = f'"{email}"'
    search_url = {
        "google": f"https://www.google.com/search?q={query}",
        "duckduckgo": f"https://duckduckgo.com/?q={query}"
    }

    options = Options()
    options.add_argument("--headless")
    options.add_argument("--disable-gpu")
    options.add_argument("--log-level=3")
    options.add_argument("--disable-blink-features=AutomationControlled")

    driver = webdriver.Chrome(options=options)
    driver.get(search_url[engine])
    time.sleep(4)
    soup = BeautifulSoup(driver.page_source, "html.parser")
    driver.quit()

    # Extract phone numbers (more strict pattern)
    text = soup.get_text(separator=' ')
    phone_regex = re.compile(r'(?:\+?\d{1,3})?[ -.]?(?:\(?\d{3}\)?)[ -.]?\d{3}[ -.]?\d{4}')
    phones = set(phone_regex.findall(text))

    # Extract social links
    linkedin_links = []
    twitter_links = []

    for a in soup.find_all('a', href=True):
        href = a['href']
        if 'linkedin.com/in/' in href:
            link = extract_google_link(href)
            if link not in linkedin_links:
                linkedin_links.append(link)
        elif 'twitter.com/' in href and all(x not in href for x in ['intent', 'share', 'search']):
            link = extract_google_link(href)
            if link not in twitter_links:
                twitter_links.append(link)

    return list(phones), linkedin_links, twitter_links


# GUI Application
class OSINTApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Email OSINT Tool (Final Version)")
        self.root.geometry("750x600")

        tk.Label(root, text="Enter Email Address:").pack(pady=5)
        self.email_entry = tk.Entry(root, width=50)
        self.email_entry.pack(pady=5)

        self.search_button = tk.Button(root, text="Start Search", command=self.start_search)
        self.search_button.pack(pady=10)

        self.result_box = scrolledtext.ScrolledText(root, width=90, height=28)
        self.result_box.pack(pady=10)

    def start_search(self):
        email = self.email_entry.get().strip()
        if not email:
            messagebox.showerror("Input Error", "Please enter an email address.")
            return
        self.result_box.delete(1.0, tk.END)
        self.result_box.insert(tk.END, f"🔍 Searching for: {email}\n\n")
        threading.Thread(target=self.run_search, args=(email,), daemon=True).start()

    def run_search(self, email):
        self.result_box.insert(tk.END, "🌐 Trying Google search...\n")
        phones, linkedin, twitter = search_web(email, engine="google")

        if not phones and not linkedin and not twitter:
            self.result_box.insert(tk.END, "⚠️ Google found nothing useful. Trying DuckDuckGo...\n\n")
            phones, linkedin, twitter = search_web(email, engine="duckduckgo")

        self.result_box.insert(tk.END, "\n📱 Phone Numbers Found:\n")
        if phones:
            for phone in phones:
                self.result_box.insert(tk.END, f"- {phone}\n")
        else:
            self.result_box.insert(tk.END, "None found.\n")

        self.result_box.insert(tk.END, "\n🔗 LinkedIn Profiles Found:\n")
        if linkedin:
            for link in linkedin:
                self.result_box.insert(tk.END, f"- {link}\n")
        else:
            self.result_box.insert(tk.END, "None found.\n")

        self.result_box.insert(tk.END, "\n🐦 Twitter Profiles Found:\n")
        if twitter:
            for link in twitter:
                self.result_box.insert(tk.END, f"- {link}\n")
        else:
            self.result_box.insert(tk.END, "None found.\n")


if __name__ == "__main__":
    root = tk.Tk()
    app = OSINTApp(root)
    root.mainloop()
