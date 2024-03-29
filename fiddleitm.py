"""
This is an addon for mitmproxy based on EKFiddle (Fiddler extension).

It is used to inspect web traffic (flows) captured by mitmproxy
and look for malicious indicators from on a list of rules.

Usage:
    mitmproxy --scripts fiddleitm.py
    mitmweb --scripts fiddleitm.py

Predefined rules (rules.txt) are loaded from the GitHub repository.

You can add your own rules to a file called local_rules.txt placed in the same
directory as fiddleitm.py

Syntax for rules:

 rule_name:"rule name"; "condition 1"; "condition 2"; "condition n"

 List of conditions:
    hostname:"string"
    server_ip:"string"
    content:"string"
    url_regex:"regex"
    response_body_regex:"regex"

You can add multiple conditions of the same type (i.e. content:"text1"; content"text2").

"""

import os
import requests
import re
import mitmproxy
from mitmproxy import http
from mitmproxy.addonmanager import Loader
import random

class Fiddleitm:
    def __init__(self):
        print('#################')
        print(' fiddleitm v.0.1')
        print('#################')
        # Initialize variables
        self.rules = []
        self.anti_vm_list = [
            "VMware", "vmtoolsd", "VMwareService", "Vmwaretray", "vm3dservice",
            "VGAuthService", "Vmwareuser", "TPAutoConnSvc", "VirtualBox", "VBoxService",
            "VBoxTray", "Fiddler", "FSE2"
        ]
        self.do_anti_vm = False
        # Load main rules
        print('Loading main rules...')
        session = requests.Session()
        session.trust_env = False
        self.rules_url = 'https://raw.githubusercontent.com/malwareinfosec/fiddleitm/main/rules.txt'
        response = session.get(self.rules_url)
        if response.status_code:
            rules = response.text.split('\r\n')
            self.add_rules_list(rules)
        print(' -> master rules loaded successfully')
        # Load local rules
        print('Loading local rules...')
        if os.path.isfile('local_rules.txt'):
            with open('local_rules.txt', 'r') as file:
                rules = file.read().splitlines()
                self.add_rules_list(rules)
                print(' -> local rules loaded successfully')

    """ Add remote and local rules """
    def add_rules_list(self, rules):
        for rule in rules:
            rule = rule.rstrip('\n')
            # Add rules
            if not rule.startswith("#"):
                self.rules.append(rule)

    """ anti-vm """
    def anti_vm(self, flow):
        request_response = flow.request.text
        modified_request_response = request_response
        # Loop through list of keywords to replace """
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

    """ Check conditions """
    def check_rules(self, flow):
        # Loop through rules
        for rule in self.rules:
            matched_condition = False
            # split rule into multiple conditions
            conditions_list = rule.split("; ")
            for condition in conditions_list:
                #rule_name = conditions_list[0].strip("rulename:").strip('"')
                if "rule_name:" in condition:
                    rule_name = condition.strip("rule_name:").strip('"')
                if "hostname:" in condition:
                    hostname = condition.strip("hostname:").strip('"')
                    matched_condition = self.check_hostname(flow, rule_name, hostname)
                    if matched_condition == False:
                        break
                if "server_ip:" in condition:
                    server_ip = condition.strip("server_ip:").strip('"')
                    matched_condition = self.check_ip(flow, rule_name, server_ip)
                    if matched_condition == False:
                        break
                if "content:" in condition:
                    content = condition.strip("content:").strip('"')
                    matched_condition = self.check_content(flow, rule_name, content)
                    if matched_condition == False:
                        break
                if "url_regex:" in condition:
                    url_regex = condition.strip("url_regex:").strip('"')
                    matched_condition = self.check_url_regex(flow, rule_name, url_regex)
                    if matched_condition == False:
                        break
                if "response_body_regex:" in condition:
                    response_body_regex = condition.strip("response_body_regex:").strip('"')
                    matched_condition = self.check_response_body_regex(flow, rule_name, response_body_regex)
                    if matched_condition == False:
                        break
            # check if we have a match for all conditions
            if matched_condition:
                # Call mark_flow function
                self.mark_flow(flow, rule_name)

    """ Check for hostname condition """
    def check_hostname(self, flow, rule_name, hostname):
        if hostname in flow.request.host:
            return True
        else:
            return False

    """ Check for IP address condition """
    def check_ip(self, flow, rule_name, server_ip):
        try:
            if server_ip in flow.server_conn.peername[0]:
                return True
            else:
                return False
        except Exception:
            return False

    """ Check for content in response body condition """
    def check_content(self, flow, rule_name, content):
        # Only check if response exists and matches content-type
        if flow.response and flow.response.content and "Content-Type" in flow.response.headers and \
            "malwareinfosec/fiddleitm/" not in flow.request.pretty_url and \
            ("text" in flow.response.headers["Content-Type"] or "javascript" in flow.response.headers["Content-Type"]):

            if content in flow.response.text:
                return True
            else:
                return False

    """ Check for regex in URL condition """
    def check_url_regex(self, flow, rule_name, url_regex):
        if re.search(url_regex, flow.request.pretty_url):
            return True
        else:
            return False

    """ Check for regex in response content condition """
    def check_response_body_regex(self, flow, rule_name, response_body_regex):
        if re.search(response_body_regex, flow.response.text):
            return True
        else:
            return False

    """ Mark flows """
    def mark_flow(self, flow, rule_name):
        # Play sound
        print('\a')
        # Print detection name in console
        print(rule_name)
        # Mark flow in web UI
        flow.marked = ":red_circle:"
        flow.comment = rule_name
        # Check if anti-vm was detected
        if "Fingerprinting" in flow.comment:
            self.do_anti_vm = True
        else:
            self.do_anti_vm = False

    """ flow request """
    def request(self, flow: http.HTTPFlow) -> None:
        # Do anti-vm
        if self.do_anti_vm:
            flow.request.text = self.anti_vm(flow)
            # Setting setting to false
            self.do_anti_vm = False

    """ flow response """
    def response(self, flow: http.HTTPFlow) -> None:
        # call function to check for rules
        self.check_rules(flow)

addons = [Fiddleitm()]