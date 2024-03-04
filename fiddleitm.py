"""
This is an addon for mitmproxy based on EKFiddle (Fiddler extension)

It is used to inspect web traffic (flows) captured by mitmproxy
and look for malicious indicators from on a list of regexes.

Usage:
    mitmproxy --scripts fiddleitm.py
    mitmweb --scripts fiddleitm.py
"""

import requests
import re

print('fiddleitm v.0.1')

class fiddleitm:

    def __init__(self):
        """ Load regexes """
        print('Loading regexes...')
        session = requests.Session()
        session.trust_env = False
        self.regexes_url = 'https://raw.githubusercontent.com/malwareinfosec/fiddleitm/main/regexes.txt'
        response = session.get(self.regexes_url)

        self.URI_data = []
        self.SourceCode_data = []

        if (response.status_code):
            data = response.text
            for line in (data.split('\r\n')):
                # Add URI regexes
                if (line.startswith("URI")):
                    self.URI_data.append(line.split('\t')[1] + ('\t') + line.split('\t')[2])
                # Add SourceCode regexes
                if (line.startswith("SourceCode")):
                    self.SourceCode_data.append(line.split('\t')[1] + ('\t') + line.split('\t')[2])

    """ Check each incoming flow against regexes """

    """ Request """
    def request(self, flow):
        for regex in self.URI_data:
            request_match = re.search(regex.split('\t')[1], flow.request.url)
            if request_match:
                flow.marked = ":red_circle:"
                flow.comment = regex.split('\t')[0] + " [URI]"
                print(regex.split('\t')[0])

    """ Response """
    def response(self, flow):
        if flow.response and flow.response.content and flow.request.url != self.regexes_url:
            for regex in self.SourceCode_data:
                response_match = re.search(regex.split('\t')[1], flow.response.text)
                if response_match:
                    flow.marked = ":red_circle:"
                    flow.comment = regex.split('\t')[0] + " [HTML/JS]"
                    print(regex.split('\t')[0])


addons = [fiddleitm()]