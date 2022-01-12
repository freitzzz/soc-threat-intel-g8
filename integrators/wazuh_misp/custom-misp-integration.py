#!/usr/bin/env python

import sys
import json
import requests
from requests.auth import HTTPBasicAuth
import uuid
import time

# Read configuration parameters
alert_file = open(sys.argv[1])
user = sys.argv[4].split(':')[0]
api_key = sys.argv[4].split(':')[1]
hook_url = sys.argv[3]

request_url = hook_url + "/events/add"

# Read the alert file
alert_json = json.loads(alert_file.read())
alert_file.close()

# Extract issue fields
date = alert_json['timestamp']
current_date = date.split("T")[0]

alert_level = alert_json['rule']['level']
description = alert_json['rule']['description']

#Get ip src addr from alert json
ipaddr = alert_json['data']['srcip']
comment = alert_json['full_log']

#Mapping Wazuh level to MISP threat_level_id [0-3] -> 1 [4-6] -> 2 [7-10] -> 3 {else corresponds to 4 (undefined)}
if alert_level >= 0 and alert_level <= 3 :
	threat_level_id = 1
elif alert_level >= 4 and alert_level <= 6:
	threat_level_id = 2
elif alert_level >= 7 and alert_level <= 10 :	
	threat_level_id = 3
else:
	threat_level_id = 4

# Generate request to create event
creating_event_data = {
	"Event":
		{
		"date": current_date,
		"threat_level_id": str(threat_level_id),
		"info": description,
		"published": False,
		"analysis":"0", #Initial
		"distribution":"0", #My organization
		"Attribute":[
			{
			"type":"ip-src",
			"category": "Network activity",
			"to_ids": False,
			"distribution":"0",
			"comment": comment,
			"value": ipaddr
			}
		]
		}
	}

headers = {'Accept': 'application/json', 'content-type': 'application/json', 'Accept-Charset': 'UTF-8', 'Authorization': api_key}

# Send the request
create_event_result = requests.post(request_url, data=json.dumps(creating_event_data), headers=headers)
 
sys.exit(0)