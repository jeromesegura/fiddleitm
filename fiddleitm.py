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
        self.do_anti_vm = False
        rule_type = ""
        """ Load regexes """
        """ master regexes """
        print('Loading master regexes...')
        session = requests.Session()
        session.trust_env = False
        self.regexes_url = 'https://raw.githubusercontent.com/malwareinfosec/fiddleitm/main/regexes.txt'
        response = session.get(self.regexes_url)

        if response.status_code:
            data = response.text.split('\r\n')
            self.add_regex_list(data)
        print(' -> master regexes loaded successfully')

        """ local rules """
        if os.path.isfile('local_rules.txt'):
            print('Loading local rules...')
            with open('local_rules.txt', 'r') as file:
                data = file.read().splitlines()
                self.add_regex_list(data)
                print(' -> local rules loaded successfully')

    def add_regex_list(self, data):
        for line in data:
            line = line.rstrip('\n')
            # Add IP regexes
            if line.startswith("IP"):
                self.IP_data.append(line.split('\t')[1] + '\t' + line.split('\t')[2])
            # Add URI regexes
            if line.startswith("URI"):
                self.URI_data.append(line.split('\t')[1] + '\t' + line.split('\t')[2])
            # Add SourceCode regexes
            if line.startswith("SourceCode"):
                self.SourceCode_data.append(line.split('\t')[1] + '\t' + line.split('\t')[2])

    # Get remote server IP address
    def get_serverip(self, flow):
        try:
            server_ip = flow.server_conn.peername[0]
        except Exception:
            server_ip = None
        return server_ip

    def check_conditiontype(self, flow, condition):
        if condition.startswith('$string='):
            condition_type = "string"
        elif condition.startswith('$regex='):
            condition_type = "regex"
        return condition_type

    # anti-vm
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

    # Mark flows
    def mark_flow(self, flow, regex, flow_type):
        """ Play sound """
        print('\a')
        """ Print detection name in console """
        print(regex.split('\t')[0] + " " + flow_type)
        """ Mark flow in web UI """
        flow.marked = ":red_circle:"
        flow.comment = regex.split('\t')[0] + " " + flow_type
        """ Check if anti-vm detection was detected """
        if "Fingerprinting" in flow.comment:
            self.do_anti_vm = True
        else:
            self.do_anti_vm = False

    # flow request
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

    # flow response
    def response(self, flow):
        """ Check IP address """
        server_ip = self.get_serverip(flow)
        if server_ip is not None:
            for regex in self.IP_data:
                if server_ip:
                    ip_match = re.search(regex.split('\t')[1], server_ip)
                    if ip_match:
                        """ Call mark_flow function """
                        self.mark_flow(flow, regex, "[IP]")

        """ Check response content """
        if flow.response and flow.response.content and "Content-Type" in flow.response.headers and \
                flow.request.pretty_url != self.regexes_url:
            if "text" in flow.response.headers["Content-Type"] or "javascript" in flow.response.headers["Content-Type"]:
                response_match = False

                for rule in self.SourceCode_data:
                    condition_type = ""
                    """ Check rule complexity """
                    # rule contains *AND*
                    if " *AND* " in rule:
                        # split rule into multiple conditions
                        conditions_list = rule.split('\t')[1].split(" *AND* ")
                        for condition in conditions_list:
                            # check condition type (string or regex)
                            condition_type = self.check_conditiontype(flow, condition)
                            # string condition
                            if condition_type == "string":
                                condition_string = condition.replace('$string="', '')[:-1]
                                if condition_string not in flow.response.text:
                                    # Not all search terms were found
                                    response_match = False
                                    break
                                response_match = True
                            # regex condition
                            elif condition_type == "regex":
                                condition_string = condition.replace('$regex="', '')[:-1]
                                response_match = re.search(condition_string, flow.response.text)
                    # rule contains *OR*
                    elif " *OR* " in rule:
                        # split rule into multiple conditions
                        conditions_list = rule.split('\t')[1].split(" *OR* ")
                        for condition in conditions_list:
                            # check condition type (string or regex)
                            condition_type = self.check_conditiontype(flow, condition)
                            # string condition
                            if condition_type == "string":
                                condition_string = condition.replace('$string="', '')[:-1]
                                if condition_string in flow.response.text:
                                    # At least one term was found
                                    response_match = True
                                    break
                                response_match = False
                            # regex condition
                            elif condition_type == "regex":
                                condition_string = condition.replace('$regex="', '')[:-1]
                                response_match = re.search(condition_string, flow.response.text)
                                if response_match:
                                    # At least one term was found
                                    response_match = True
                                    break
                                response_match = False
                    else:
                        # simple rule #
                        # check rule type (string or regex)
                        condition = rule.split('\t')[1]
                        condition_type = self.check_conditiontype(flow, condition)
                        if condition_type == "string":
                            condition_string = condition.replace('$string="', '')[:-1]
                            if condition_string in flow.response.text:
                                response_match = True
                        elif condition_type == "regex":
                            condition_string = condition.replace('$regex="', '')[:-1]
                            response_match = re.search(condition_string, flow.response.text)

                    # check if we have a match
                    if response_match:
                        """ Call mark_flow function """
                        self.mark_flow(flow, rule, "[HTML/JS]")


addons = [Fiddleitm()]
