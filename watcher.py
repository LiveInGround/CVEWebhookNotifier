"""
An application to retreives every recent CVEs 
for specified products, and post them in a discord webhook.

API Documentation: https://doc.mlab.sh/docs/vuln.mlab.sh/developer/documentation
"""

# DEPENDENCIES
from datetime import timedelta
import requests
import os
import os.path
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

# CONFIG
API_BASE = "https://vuln.mlab.sh"   # Base URL of the API used to retrieve CVE data
VERSION = "1.0"                     # Application version, included in the User-Agent header
LIMIT = 20                          # Maximum number of CVEs retrieved per product
DEBUG = False                       # Debug mode: reduces the CVE limit and skips CVE storage
DEBUG_LIMIT = 1                     # CVE limit applied when debug mode is enabled
FILE = "reviewed_cves.txt"          # File containing CVE IDs already sent to the webhook, to prevent duplicate notifications
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL").strip()
PRODUCTS = ["nginx", "java", "docker", "php", "php-fpm"]  # Products to monitor for new CVEs
DATE_START = 7                                            # Number of days to look back when retrieving CVEs

reviewed = []
date_start = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d")

def load_saved_cve_file():
    """Opens the CVEs storage and stores each entry as a global list.
    If the file doesn't exist, it is created automatically.
    Doesn't check for duplicates, to call only once per run.
    """

    if not(os.path.exists(FILE)):
        with open(FILE, "w") as f:
            f.write()
    with open(FILE, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                reviewed.append(line)

def save_cve_data():
    """Saves each entry in the 'reviewed' list into the CVEs storage"""

    with open(FILE, "w") as f:
        for i in reviewed:
            f.write(i + "\n")

def retreive_cve_list(product:str) -> list[any]|dict[any]:
    """Retrieve recent CVEs for a specified product.

    Requests the CVE API to retrieve vulnerabilities
    associated with the specified product.

    Args:
        product: The product to retrieve CVEs for.

    Returns:
        The JSON response containing the CVE data.

    Raises:
        requests.exceptions.HTTPError: If the API returns an unsuccessful HTTP status code.
        requests.exceptions.ConnectionError: If a connection error occurs.
        requests.exceptions.Timeout: If the request times out.
    """

    ans = requests.get(f"{API_BASE}/api/v1/cve", params={"q": product, "limit": DEBUG_LIMIT if DEBUG else LIMIT, "sort": "severity", "dateStart": date_start}, headers={"User-Agent": f"CVE-Webhook-Notifier/{VERSION}"}, timeout=10)
    ans.raise_for_status()
    return ans.json()


def process_cves(cve_list: dict) -> tuple[list[dict], float]:
    """Process CVEs and calculate their average severity score.

    Filters out CVEs that have already been reported and extracts
    relevant information for each remaining CVE.

    Args:
        cve_list: A dictionary containing CVEs in the API format.

    Returns:
        A tuple containing:
            - A list of dictionaries with each CVE's ID, CVSS score,
              severity, link and publication date.
            - The average CVSS score of the remaining CVEs.

    Side Effects:
        Adds the IDs of processed CVEs to the global reviewed list.
    """

    cves = []
    total_score = 0
    for cve in cve_list["cves"]:
        if cve["id"] in reviewed:
            print(f"Skipping {cve['id']} as it has already been reported")
            continue
        cves.append({
            "id": cve["id"],
            "score": cve["cvss_score"],
            "severity": cve["cvss_severity"],
            "link": f"{API_BASE}/cve/{cve['id']}",
            "published": cve["published"]
        })
        total_score += float(cve["cvss_score"])
        reviewed.append(cve["id"])
    return cves, total_score/len(cves) if cves else 0

def post_on_discord(product: str, cves: list[dict], average: float) -> None:
    """Post CVE results to a Discord webhook.

    Formats the CVE information into a Discord embed, including
    severity scores, publication dates and the average CVSS score.

    Args:
        product: The name of the monitored product.
        cves: A list of CVE dictionaries returned by process_cves().
        average: The average CVSS score of the reported CVEs.

    Raises:
        requests.exceptions.HTTPError: If Discord returns an unsuccessful HTTP status code.
        requests.exceptions.ConnectionError: If a connection error occurs.
        requests.exceptions.Timeout: If the request times out.

    Side Effects:
        Sends a message to the configured Discord webhook.
    """

    if len(cves) == 0:
        return
    content_lines = []
    for cve in cves:
        date = datetime.fromisoformat(cve["published"])
        timestamp = int(date.timestamp())
        discord_timestamp = f"<t:{timestamp}:R>"
        content_lines.append(f"- [{cve['score']}] [{cve['severity']}] [{cve['id']}]({cve['link']}) ({discord_timestamp})")

    embed = {
            "title": f"Results for {product} (average score {round(average, 1)} for {len(cves)} vulnerabilities)",
            "description": "\n".join(content_lines),
            "color": 0xFF0000 if average >= 8 else 0XFC8700 if average >= 6 else 0xF4FC00 if average >= 4 else 0xB5FC00,
            "fields": [],
            "footer": {"text": "Based on Vuln.mlab.sh API"},
    }
    response = requests.post(
            DISCORD_WEBHOOK_URL,
            json={"embeds": [embed]},
            timeout=10
    )
    response.raise_for_status()

def run_once():
    """Run a complete CVE monitoring cycle.

    Loads previously saved CVE data, retrieves recent vulnerabilities
    for each monitored product, filters already reported CVEs,
    publishes new findings to Discord and saves the updated data.

    Side Effects:
        - Loads and updates the local CVE data file.
        - Sends Discord webhook notifications for new CVEs.
    """

    load_saved_cve_file()
    for product in PRODUCTS:
        plist, average = process_cves(retreive_cve_list(product))
        post_on_discord(product, plist, average)
        save_cve_data()

if __name__ == "__main__":
    run_once()
    print("Done")