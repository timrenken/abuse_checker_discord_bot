import requests
import json
import os
from dotenv import load_dotenv
import time

# Load environment variables from .env file
load_dotenv()

# Get URLSCAN_KEY from environment variable
apikey = os.getenv("URLSCAN_KEY")

class UrlScan:

    # Constructor method to initialize an instance of the class
    def __init__(self, address=None, result_uuid=None):

        # Save the given address to the object's address attribute
        self.address = address

        # If a result UUID is provided, save it to the object's result_uuid attribute
        # Otherwise, get a new UUID by calling __get_uuid()
        if result_uuid:
            self.result_uuid = result_uuid
        else:
            self.result_uuid = self.__get_uuid()

        # Generate the result URL using the UUID
        self.result_url = f"https://urlscan.io/api/v1/result/{self.result_uuid}"

        # Call get_results() to retrieve the results from the URL
        self.get_results()

    # Method to get a new UUID for the given address
    def __get_uuid(self):
        # Set up the request headers
        headers = {'API-Key':apikey,'Content-Type':'application/json'}
        # Set up the request data
        data = {"url": self.address}

        # Send a POST request to the /scan/ endpoint to get a new UUID
        response = requests.post('https://urlscan.io/api/v1/scan/',headers=headers, data=json.dumps(data))

        # If the request is successful, return the UUID
        if response.status_code == 200:
            return response.json()['uuid']

    # Method to retrieve the scan results
    def get_results(self):
        # Set up the request headers
        headers = {'API-Key':apikey,'Content-Type':'application/json'}

        # Keep sending GET requests to the result URL until the request is successfula
        while requests.get(self.result_url,headers=headers).status_code != 200:
            time.sleep(10)
        # Once the request is successful, get the results
        response = requests.get(self.result_url,headers=headers)

        # Save the results to the object's results attribute
        self.results = response.json()
        # Save the verdict_score
        self.verdict_score = self.results['verdicts']['overall']['score']
        # Save the report_url
        self.report_url = self.results['task']['reportURL']



        