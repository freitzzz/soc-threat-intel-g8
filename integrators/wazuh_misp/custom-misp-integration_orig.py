#!/usr/bin/env python

import sys
import json
import requests
from requests.auth import HTTPBasicAuth
import uuid
import time

# Read configuration parameters
#alert_file = open(sys.argv[1])
#user = sys.argv[4].split(':')[0]
#api_key = sys.argv[4].split(':')[1]
#hook_url = sys.argv[3]
alert_file = open("sample_alert.json")
user = "group_8@socteam.com"
api_key = "T9V1gzrDtuY7VW0VjtBJ3FeTfJV4880XNUMpd5vn"
hook_url = "http://localhost:8001"

request_url = hook_url + "/events/add"

print(request_url)

# Read the alert file
alert_json = json.loads(alert_file.read())
alert_file.close()

# Extract issue fields
date = alert_json['timestamp']
current_date = date.split("T")[0]

alert_level = alert_json['rule']['level']
description = alert_json['rule']['description']
attribute_count = alert_json['rule']['firedtimes']

#Get ip src addr from alert json
ipaddr = alert_json['data']['srcip']
comment = alert_json['full_log']

create_event_uuid = str(uuid.uuid4())
timestamp_millis = int(round(time.time() * 1000))

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
#creating_event_data = {
#    "org_id": "24", #?? 1 ORGNAME (criar uma?)
#    "distribution": "0", #Who can see it? My organization |Discutir com  o Freitas
#    "info": description, #"logged source ip",
#    "uuid": create_event_uuid,
#    "date": str(date), #"1991-01-15",
#    "published": "false",
#    "analysis": "0", #Initial
#    "attribute_count": str(attribute_count), #??
#    "timestamp": str(timestamp_millis),#"1617875568", #Qual ´e este? gerado por n´os?
#    "threat_level_id": str(threat_level_id), #"1",
#    "extends_uuid": "", #"c99506a6-1255-4b71-afa5-7b8ba48c3b1b",
#    "event_creator_email": user} #"user@example.com"}

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

print("Event JSON : ")     
print(creating_event_data)

headers = {'Accept': 'application/json', 'content-type': 'application/json', 'Accept-Charset': 'UTF-8', 'Authorization': api_key}

# Send the request
create_event_result = requests.post(request_url, data=json.dumps(creating_event_data), headers=headers)

print("Event Result: ")
print(create_event_result.text)
 
sys.exit(0)