"""
This is an addon for mitmproxy based on EKFiddle (Fiddler extension).

It is used to inspect web traffic (flows) captured by mitmproxy
and look for malicious indicators from on a list of regexes.

Usage:
    mitmproxy --scripts fiddleitm.py
    mitmweb --scripts fiddleitm.py
"""

import os
import requests
import re
import mitmproxy
from mitmproxy import http
from mitmproxy.addonmanager import Loader
import random

print('fiddleitm v.0.1')

class Fiddleitm:

    def __init__(self):
        """ Initialize variables """
        self.IP_data = []
        self.URI_data = []
        self.SourceCode_data = []
        self.anti_vm_list = [
            "VMware", "vmtoolsd", "VMwareService", "Vmwaretray", "vm3dservice",
            "VGAuthService", "Vmwareuser", "TPAutoConnSvc", "VirtualBox", "VBoxService"
            "VBoxTray", "Fiddler", "FSE2"
        ]
        self.do_anti_vm = False #
        """ Load regexes """
        """ master regexes """
        print('Loading master regexes...')
        session = requests.Session()
        session.trust_env = False
        self.regexes_url = 'https://raw.githubusercontent.com/malwareinfosec/fiddleitm/main/regexes.txt'
        response = session.get(self.regexes_url)

        if (response.status_code):
            data = response.text.split('\r\n')
            self.add_regex_list(data)
        print(' -> master regexes loaded successfully')

        """ local regexes """
        if os.path.isfile('local_regexes.txt'):
            print('Loading local regexes...')
            with open('local_regexes.txt', 'r') as file:
                data = file.read().splitlines()
                self.add_regex_list(data)
                print(' -> local regexes loaded successfully')

    def add_regex_list(self, data):
        for line in data:
            line = line.rstrip('\n')
            ## Add IP regexes
            if (line.startswith("IP")):
                self.IP_data.append(line.split('\t')[1] + ('\t') + line.split('\t')[2])
            # Add URI regexes
            if (line.startswith("URI")):
                self.URI_data.append(line.split('\t')[1] + ('\t') + line.split('\t')[2])
            # Add SourceCode regexes
            if (line.startswith("SourceCode")):
                self.SourceCode_data.append(line.split('\t')[1] + ('\t') + line.split('\t')[2])

    ## Get remote server IP address
    def get_serverIP(self, flow):
        try:
            server_IP = flow.server_conn.peername[0]
        except:
            server_IP = None
        return server_IP

    ## anti-vm
    def anti_vm(self, flow):
        request_response = flow.request.text
        modified_request_response = request_response
        """ Loop through list of keywords to replace """
        for keyword in self.anti_vm_list:
            if keyword in request_response:
                # Replace with random word from list
                session = requests.Session()
                session.trust_env = False
                word_site = "https://www.mit.edu/~ecprice/wordlist.10000"
                response = session.get(word_site)
                bytelist = response.content.splitlines()
                stringlist = [x.decode('utf-8') for x in bytelist]
                random_word = random.choice(stringlist)
                print('Fingerprinting detected, replacing data in POST request with keyword: ' + random_word)
                modified_request_response = request_response.replace(keyword, random_word)
                break
        return modified_request_response

    ## Mark flows
    def mark_flow(self, flow, regex, type):
        """ Play sound """
        print('\a')
        """ Print detection name in console """
        print(regex.split('\t')[0] + " " + type)
        """ Mark flow in web UI """
        flow.marked = ":red_circle:"
        flow.comment = regex.split('\t')[0] + " " + type
        """ Check if anti-vm detection was detected """
        if "Fingerprinting" in flow.comment:
            self.do_anti_vm = True
        else:
            self.do_anti_vm = False

    ## flow request
    def request(self, flow):
        """ Do anti-vm """
        if self.do_anti_vm:
            flow.request.text = self.anti_vm(flow)
            # Setting setting to false
            self.do_anti_vm = False
        for regex in self.URI_data:
            request_match = re.search(regex.split('\t')[1], flow.request.pretty_url)
            if request_match:
                """ Call mark_flow function """
                self.mark_flow(flow, regex, "[URI]")

    ## flow response
    def response(self, flow):
        """ Check IP address """
        server_IP = self.get_serverIP(flow)
        if server_IP is not None:
            for regex in self.IP_data:
                if (server_IP):
                    ip_match = re.search(regex.split('\t')[1], server_IP)
                    if ip_match:
                        """ Call mark_flow function """
                        self.mark_flow(flow, regex, "[IP]")

        """ Check response content """
        if flow.response and flow.response.content and "Content-Type" in flow.response.headers and \
           flow.request.pretty_url != self.regexes_url:
            if "text" in flow.response.headers["Content-Type"] or "javascript" in flow.response.headers["Content-Type"]:
                response_match = False
                for regex in self.SourceCode_data:
                    """ Check regex type """
                    # regex contains *AND*
                    if (" *AND* " in regex):
                        # split regex into subregexes #
                        subregexesList = regex.split('\t')[1].split(" *AND* ")
                        for subregex in subregexesList:
                            if subregex not in flow.response.text:
                                # Not all search terms were found
                                response_match = False
                                break
                            response_match = True
                    # regex contains *OR*
                    elif (" *OR* " in regex):
                        # split regex into subregexes #
                        subregexesList = regex.split('\t')[1].split(" *OR* ")
                        for subregex in subregexesList:
                            if subregex in flow.response.text:
                                # At least one term was found
                                response_match = True
                                break
                            response_match = False
                    else:
                        # simple regex #
                        response_match = re.search(regex.split('\t')[1], flow.response.text)

                    # check if we have a match
                    if response_match:
                        """ Call mark_flow function """
                        self.mark_flow(flow, regex, "[HTML/JS]")

addons = [Fiddleitm()]