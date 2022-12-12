# abuse_checker_bot

This Discord bot allows users to check IP addresses, domains, and URLs for potential threats and malicious activity. It uses the following APIs and libraries:
- [discord.py](https://discordpy.readthedocs.io/en/latest/index.html) to interact with the Discord API
- [IPWhois](https://pypi.org/project/ipwhois/) to get information about IP addresses
- [pydig](https://pypi.org/project/pydig/) to perform DNS lookups
- [urlscan.io](https://urlscan.io/) to scan URLs for malicious content
- [AbuseIPDB](https://www.abuseipdb.com/) to check the abuse score of IP addresses
- [VirusTotal](https://www.virustotal.com/gui/home/upload) to scan URLs for malicious content

## Installation

To use this bot, you will need to have Python 3.8 and pip installed on your system.

Clone the repository and navigate to the project directory:
```bash
git clone https://github.com/timrenken/abuse_checker_discord_bot
cd abuse_checker_discord_bot
```
Install the required libraries using pip:
```bash
pip install -r requirements.txt
```
Create a .env file and add your Discord bot token and API keys for urlscan.io, AbuseIPDB, and VirusTotal.
```
DISCORD_TOKEN=<your_discord_bot_token>
URLSCAN_KEY=<your_urlscan_api_key>
ABUSEIPDB_KEY=<your_abuseipdb_api_key>
VIRUSTOTAL_KEY=<your_virustotal_api_key>
```
## Usage
To start the bot, run the bot.py

## Commands

List of available commands:
- `/check ip host <ip_address>` - Get the hostname for the given IP address.
- `/check ip score <ip_address>` - Get the abuse score for the given IP address.
- `/check domain host <domain>` - Get the IP address and hostname for the given domain.
- `/check url urlscan [uuid=<report_uuid>] <url>` - Get the URLScan.io verdict of the given URL or report UUID.
- `/check url vt <url>` - Scan the given URL with VirusTotal and get the analysis results.
