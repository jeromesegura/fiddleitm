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
import mitmproxy
from mitmproxy import http

print('fiddleitm v.0.1')

class fiddleitm:

    def __init__(self):
        """ Load regexes """
        print('Loading regexes...')
        session = requests.Session()
        session.trust_env = False
        self.regexes_url = 'https://raw.githubusercontent.com/malwareinfosec/fiddleitm/main/regexes.txt'
        response = session.get(self.regexes_url)

        self.IP_data = []
        self.URI_data = []
        self.SourceCode_data = []

        if (response.status_code):
            data = response.text
            for line in (data.split('\r\n')):
                line = line.rstrip('\n')
                # Add IP regexes
                if (line.startswith("IP")):
                    self.IP_data.append(line.split('\t')[1] + ('\t') + line.split('\t')[2])
                # Add URI regexes
                if (line.startswith("URI")):
                    self.URI_data.append(line.split('\t')[1] + ('\t') + line.split('\t')[2])
                # Add SourceCode regexes
                if (line.startswith("SourceCode")):
                    self.SourceCode_data.append(line.split('\t')[1] + ('\t') + line.split('\t')[2])

    """ Check each incoming flow against regexes """

    """ flow request """
    def request(self, flow):
        for regex in self.URI_data:
            request_match = re.search(regex.split('\t')[1], flow.request.pretty_url)
            if request_match:
                """ Call mark_flow function """
                self.mark_flow(flow, regex, "[URI]")

    """ flow response """
    def response(self, flow):
        """ Check IP address """
        for regex in self.IP_data:
            ip_match = re.search(regex.split('\t')[1], flow.server_conn.peername[0])
            if ip_match:
                """ Call mark_flow function """
                self.mark_flow(flow, regex, "[IP]")
        """ Check response content """
        if flow.response and flow.response.content and "Content-Type" in flow.response.headers and \
           flow.request.pretty_url != self.regexes_url:
            if "text" in flow.response.headers["Content-Type"] or "javascript" in flow.response.headers["Content-Type"]:
                for regex in self.SourceCode_data:
                    response_match = re.search(regex.split('\t')[1], flow.response.text)
                    if response_match:
                        """ Call mark_flow function """
                        self.mark_flow(flow, regex, "[HTML/JS]")
                        
    def mark_flow(self, flow, regex, type):
        """ Play sound """
        print('\a')
        """ Print detection name in console """
        print(regex.split('\t')[0] + " " + type)
        """ Mark flow in web UI """
        flow.marked = ":red_circle:"
        flow.comment = regex.split('\t')[0] + " " + type

addons = [fiddleitm()]