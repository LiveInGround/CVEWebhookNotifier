from datetime import timedelta
import requests
import os
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

API_BASE = "https://vuln.mlab.sh"
VERSION = "0.1"
LIMIT = 20
DEBUG = False
DEBUG_LIMIT = 1
FILE = "reviewed_cves.txt"
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL").strip()
PRODUCTS = ["nginx", "java", "docker", "php", "php-fpm"]

reviewed = []
date_start = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d")

def load_saved_cve_file():
    with open(FILE, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                reviewed.append(line)
def save_cve_data():
    with open(FILE, "w") as f:
        for i in reviewed:
            f.write(i + "\n")

def retreive_cve_list(product): 
    return requests.get(f"{API_BASE}/api/v1/cve", params={"q": product, "limit": DEBUG_LIMIT if DEBUG else LIMIT, "sort": "severity", "dateStart": date_start}, headers={"User-Agent": f"CVE-Watchlist/{VERSION}"}).json()

def process_cves(cve_list):
    cves = []
    total_score = 0
    for cve in cve_list["cves"]:
        if cve["id"] in reviewed:
            print(f"Skipping {cve["id"]} as it already got reported")
            continue
        cves.append({
            "id": cve["id"],
            "score": cve["cvss_score"],
            "severity": cve["cvss_severity"],
            "link": f"{API_BASE}/cve/{cve["id"]}",
            "published": cve["published"]
        })
        total_score += float(cve["cvss_score"])
        reviewed.append(cve["id"])
    return cves, total_score/len(cves) if cves else 0

def post_on_discord(product, cves, average):
    if len(cves) == 0:
        return
    content = ""
    for cve in cves:
        date = datetime.fromisoformat(cve["published"])
        timestamp = int(date.timestamp())
        discord_timestamp = f"<t:{timestamp}:R>"
        content += f"- [{cve["score"]}] [{cve["severity"]}] [{cve["id"]}]({cve["link"]}) ({discord_timestamp})\n"

    embed = {
            "title": f"Results for {product} (average score {round(average, 1)} for {len(cves)} vulnerabilities)",
            "description": content[:-1],
            "color": 0xFF0000 if average >= 8 else 0XFC8700 if average >= 6 else 0xF4FC00 if average >= 4 else 0xB5FC00,
            "fields": [],
            "footer": {"text": "Based on Vuln.mlab.sh API"},
    }
    response = requests.post(
            DISCORD_WEBHOOK_URL,
            json={"embeds": [embed]}
    )
    response.raise_for_status()

if __name__ == "__main__":
    load_saved_cve_file()
    for product in PRODUCTS:
        plist, average = process_cves(retreive_cve_list(product))
        post_on_discord(product, plist, average)
        save_cve_data()
    print("Done")