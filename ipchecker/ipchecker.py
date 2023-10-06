import requests
import json
from openpyxl import Workbook

# Set the VirusTotal API key
VT_API_KEY = '6d20f0d4c9d8b0859dfea71e5937c6372e72813a617e10c582ad78215a74a017'

apifile = open('api.txt', 'r')
VT_API_KEY = apifile.readline()

# Create a new workbook
wb = Workbook()
ws = wb.active
ws.append(['IP Address', 'Country', 'Network Owner', 'Reputation'])

# Open the input file
with open('input.txt', 'r') as f:
    for line in f:
        # Strip any leading/trailing whitespace from the IP address
        ip_address = line.strip()
        
        # Construct the API URL
        url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
        
        # Set the request headers
        headers = {
            'x-apikey': VT_API_KEY
        }

        params = {
            'include': 'whois,country'
        }
        
        # Send the request
        response = requests.get(url, headers=headers, params=params)
        outs = json.loads(response.text)
        stats = outs["data"]["attributes"]["last_analysis_stats"]
        
        # Check the response status code
        if response.status_code == 200:
            response_json = response.json()
            # If the response was successful, add the IP address and reputation to the worksheet
            data = response.json()['data']
            reputation = data['attributes']['reputation']
            country = data['attributes']['country']
            if stats["malicious"] > 0:
                result = "MALICIOUS"
            elif stats["suspicious"] > 0:
                result = "SUSPICIOUS"
            else:
                result = "CLEAN"
            #asn = data['attributes']['asn_owner']
            owner = response_json["data"]["attributes"]["as_owner"]
            ws.append([ip_address, country, owner, result])
        elif response.status_code == 404:
            # If the IP address was not found in the VirusTotal database, add a message to the worksheet
            ws.append([ip_address, 'Not found in VirusTotal database'])
        else:
            # If the request failed for some other reason, add the status code to the worksheet
            ws.append([ip_address, f'Request failed with status code {response.status_code}'])

# Save the workbook
wb.save('output.xlsx')
