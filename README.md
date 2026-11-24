# CVE-Watchlist

A lightweight Python application that retrieves recent CVEs from the [mlab.sh API](https://vuln.mlab.sh/) for specified products and sends notifications to a Discord channel through a webhook.

## Configuration

The application requires the following environment variable:

| Variable | Description |
|---|---|
| `DISCORD_WEBHOOK_URL` | The Discord webhook URL used to send CVE notifications. |

## Features

- Fetches recent CVEs for specified products.
- Filters out previously reported vulnerabilities.
- Calculates the average CVSS score of new findings.
- Sends vulnerability reports to Discord with severity levels, CVE links and publication dates.
- Saves previously reported CVEs to avoid duplicate notifications.
