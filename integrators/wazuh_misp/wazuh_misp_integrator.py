#!/usr/bin/env python

import sys
import json
import requests
from requests.auth import HTTPBasicAuth

# Read configuration parameters
alert_file = open(sys.argv[1])
user = sys.argv[2].split(':')[0]
api_key = sys.argv[2].split(':')[1]
hook_url = sys.argv[3]

# Read the alert file
alert_json = json.loads(alert_file.read())
alert_file.close()

# Extract issue fields
alert_level = alert_json['rule']['level']
description = alert_json['rule']['description']
path = alert_json['syscheck']['path']

# Generate request
msg_data = {}

headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}

# Send the request
requests.post(hook_url, data=json.dumps(msg_data), headers=headers, auth=(user, api_key))
 
sys.exit(0)