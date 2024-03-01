"""
This script is based on EKFiddle https://github.com/malwareinfosec/EKFiddle

It is used to inspect web traffic (flows) captured by mitmproxy
and look for malicious indicators from on a list of regexes.

Usage:
    mitmproxy --scripts fiddleitm.py
    mitmweb --scripts fiddleitm.py

"""

import requests
import re

print('EKFiddle v.0.1')

""" Load regexes """
print('Loading regexes...')
session = requests.Session()
session.trust_env = False
response = session.get('https://raw.githubusercontent.com/malwareinfosec/EKFiddle/master/Regexes/MasterRegexes.txt')

URI_data = []
SourceCode_data = []

if (response.status_code):
    data = response.text
    for line in (data.split('\r\n')):
        # Add URI regexes
        if (line.startswith("URI")):
            URI_data.append(line.split('\t')[1] + ('\t') + line.split('\t')[2])
        # Add SourceCode regexes
        if (line.startswith("SourceCode")):
            SourceCode_data.append(line.split('\t')[1] + ('\t') + line.split('\t')[2])

""" Check each incoming flow against regexes """

""" Request """
def request(flow):
    for regex in URI_data:
        request_match = re.search(regex.split('\t')[1], flow.request.path)
        if request_match:
            flow.marked = ":red_circle:"
            flow.comment = regex.split('\t')[0] + " [URI]"
            print(regex.split('\t')[0])

""" Response """
def response(flow):
    if flow.response and flow.response.content:
        for regex in SourceCode_data:
            response_match = re.search(regex.split('\t')[1], flow.response.content.decode('utf-8', 'ignore'))
            if response_match:
                flow.marked = ":red_circle:"
                flow.comment = regex.split('\t')[0] + " [HTML/JS]"
                print(regex.split('\t')[0])

