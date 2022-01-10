#!/usr/bin/env python

import sys
import json
import requests
from requests.auth import HTTPBasicAuth
import uuid

# Read configuration parameters
alert_file = open(sys.argv[1])
user = sys.argv[4].split(':')[0]
api_key = sys.argv[4].split(':')[1]
hook_url = sys.argv[3]

# Read the alert file
alert_json = json.loads(alert_file.read())
alert_file.close()

# Extract issue fields
date = alert_json['timestamp']

alert_level = alert_json['rule']['level']
description = alert_json['rule']['description']

uuid = str(uuid.uuid4())

# Generate request
msg_data = {
    "org_id": "12345", #?? 1 ORGNAME (criar uma?)
    "distribution": "0", #Who can see it? My organization |Discutir com  o Freitas
    "info": description, #"logged source ip",
    "orgc_id": "12345", #?? 1 ORGNAME (criar uma?)
    "uuid": uuid, #"c99506a6-1255-4b71-afa5-7b8ba48c3b1b",
    "date": date, #"1991-01-15",
    "published": false,
    "analysis": "0",
    "attribute_count": "321", #??
    "timestamp": "1617875568", #Qual ´e este? gerado por n´os?
    "sharing_group_id": "1", #??
    "proposal_email_lock": true, #??
    "locked": true, #??
    "threat_level_id": alert_level, #"1",
    "publish_timestamp": "1617875568",
    "sighting_timestamp": "1617875568",
    "disable_correlation": false, #??
    "extends_uuid": uuid, #"c99506a6-1255-4b71-afa5-7b8ba48c3b1b",
    "event_creator_email": user} #"user@example.com"}

headers = {'Accept': 'application/json', 'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}

# Send the request
requests.post(hook_url, data=json.dumps(msg_data), headers=headers, auth=(api_key))
 
sys.exit(0)