import requests
import os
import asyncio
from dotenv import load_dotenv

load_dotenv()

apikey = os.getenv("VIRUSTOTAL_KEY")

class VT:
    def __init__(self,address):

        # Set the URL for scanning a URL with VirusTotal
        scan_url = "https://www.virustotal.com/api/v3/urls"

        # Set the payload and headers for the request
        payload = f"url={address}"
        headers = {
            "accept": "application/json",
            "x-apikey": apikey,
            "content-type": "application/x-www-form-urlencoded"
        }

        # Make the request to VirusTotal to scan the URL
        response = requests.post(url=scan_url, data=payload, headers=headers)

        # Get the scan results
        scan_results = response.json()

        # Parse the scan results to get the id and results URL
        self.id = scan_results['data']['id'].split('-')[1]
        self.results_url = f"https://www.virustotal.com/gui/url/{self.id}"

        # Wait for 20 seconds before getting the analysis results
        asyncio.sleep(20)
        self.analysis_results()

    def analysis_results(self):
        # Set the URL for getting the analysis results
        analysis_url = f"https://www.virustotal.com/api/v3/urls/{self.id}"

        # Set the headers for the request
        headers = {"accept": "application/json", "x-apikey": apikey}

        # Make the request to get the analysis results
        response = requests.get(url=analysis_url, headers=headers)

        # Get the analysis results
        analysis_results = response.json()

        # Parse the analysis results to get the malicious statistics and results
        self.malicious_stats = analysis_results['data']['attributes']['last_analysis_stats']['malicious']
        last_results = analysis_results['data']['attributes']['last_analysis_results']
        self.results = {}
        for key in last_results.keys():
            if last_results[key]['category'] == 'malicious':
                result = last_results[key]
                self.results[result['engine_name']] = result['result'].title()
        