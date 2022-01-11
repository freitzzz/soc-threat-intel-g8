import base64
from logging import log
import logging
import requests
import urllib3

# Disable insecure https warnings (for self-signed SSL certificates)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


misp_api_config = {
    'host': 'localhost',
    'port': '80',
    'secure': False,
    'auth': 'k2kQW7r2Gtffe1vHwVJYER7pZdmQ4tfcwqb1QIjA'
}

wazuh_api_config = {
    'host': '192.168.201.160',
    'port': '55000',
    'secure': True,
    'pre-auth': {'username': 'wazuh-wui', 'password': 'wazuh-wui'},
    'auth': None
}

already_published_events = []


def exec_http_request(host: str, port: str, ssl: bool, endpoint: str, verb: str,
                      headers: dict = None, body: dict = None, verify_ssl=True):
    http_proto = 'https' if ssl else 'http'

    url = '{}://{}:{}/{}'.format(http_proto, host, port, endpoint)

    return requests.request(method=verb, url=url, headers=headers, data=body, verify=verify_ssl)


def exec_misp_api_request(mapiconfig: dict, endpoint: str, verb: str,
                          headers: dict = None, body: dict = None):

    _headers = headers.copy() if headers != None else dict()

    _headers['Accept'] = 'application/json'
    _headers['Authorization'] = mapiconfig.get('auth')

    return exec_http_request(body=body, endpoint=endpoint, headers=_headers,
                             host=mapiconfig['host'], port=mapiconfig['port'],
                             ssl=mapiconfig['secure'], verb=verb
                             )


def exec_wazuh_api_request(wazuhapiconfig: dict, endpoint: str, verb: str,
                           headers: dict = None, body: dict = None):

    _headers = headers.copy() if headers != None else dict()

    _headers['Accept'] = 'application/json'

    _headers['Content-Type'] = 'application/json'

    if wazuh_api_config['auth'] != None:
        _headers['Authorization'] = wazuh_api_config['auth']

    return exec_http_request(body=body, endpoint=endpoint, headers=_headers,
                             host=wazuh_api_config['host'], port=wazuh_api_config['port'],
                             ssl=wazuh_api_config['secure'], verb=verb, verify_ssl=False
                             )


def get_last_events(mapiconfig: dict, count: int = 50):

    headers = {'X-Result-Count': count.__str__()}

    request_exec = exec_misp_api_request(endpoint='events', headers=headers,
                                         verb='GET', mapiconfig=mapiconfig)

    response_body = request_exec.json()

    if type(response_body) is list:
        return response_body
    else:
        return []


def get_wazuh_auth_token(wazuhapiconfig: dict):
    pre_auth = wazuhapiconfig['pre-auth']
    headers = {'Authorization': 'Basic {}'.format(
        base64.b64encode('{}:{}'.format(pre_auth['username'], pre_auth['password']).encode()).decode())
    }

    request_exec = exec_wazuh_api_request(endpoint='security/user/authenticate', headers=headers,
                                          verb='GET', wazuhapiconfig=wazuh_api_config
                                          )

    response_body = request_exec.json()

    print(response_body)

    if request_exec.status_code == 200:
        return response_body['data']['token']
    else:
        return None


def publish_events(wazuhapiconfig: dict, events: list):
    new_events = [x for x in events if x not in already_published_events]

    already_published_events.extend(new_events)


def main():
    # events = get_last_events(mapiconfig=misp_api_config)

    # publish_events(events=events)

    wazuh_token = get_wazuh_auth_token(wazuhapiconfig=wazuh_api_config)

    if wazuh_token == None:
        logging.error('Could not get auth-token for wazuh-api!')
        exit(-1)

    wazuh_api_config['auth'] = wazuh_token


if __name__ == "__main__":
    main()
