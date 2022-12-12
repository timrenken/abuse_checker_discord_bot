import requests
import os
from dotenv import load_dotenv


load_dotenv()
key = os.getenv('ABUSEIPDB_KEY')


class AbuseIPDB:

    def __init__(self,ip):
        self.ip = ip
        
    def get_results(self):
        url = 'https://api.abuseipdb.com/api/v2/check'
        params = {'ipAddress': self.ip}
        headers = {'Accept': 'application/json','Key': self.key}
        response = requests.get(url=url, headers=headers, params=params)
        results = response.json()
        self.score = results['data']['abuseConfidenceScore']
        self.users_reported = results['data']['numDistinctUsers']
        self.total_reports = results['data']['totalReports']
        self.isp = results['data']['isp']
        self.usage = results['data']['usageType']
