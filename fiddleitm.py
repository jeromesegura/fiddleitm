"""
This is an addon for mitmproxy that inspects flows and
identifies malicious web traffic.

Usage:
    mitmproxy -s fiddleitm.py
    mitmweb -s fiddleitm.py
    mitmdump -s fiddleitm.py

Options:

 modify default user-agent with your own --set custom_user_agent=""

 modify default accept-language with your own --set custom_accept_language=""

 log events for rules that match flows (writes to rules.log) --set log_events=true

 add upstream proxy --mode upstream:http://proxyhost:port --upstream-auth username:password

Predefined rules (rules.txt) are loaded from the GitHub repository.

You can add your own rules to a file called localrules.txt placed in the same
directory as fiddleitm.py

Syntax for rules:

 rule_name = "rule name"; condition 1 = "string" ; condition 2 = /regex/; condition n = ...

 List of conditions:
  host_name
  host_ip
  full_url
  response_body

 Example:
 rule_name = "My first rule"; full_url = /[a-z]{5}[0-9]{2}/; response_body = "DevTools"; response_body = /function[0-9]{2}/
"""

import os
import requests
import re
import mitmproxy
from mitmproxy import http
from mitmproxy.addonmanager import Loader
from mitmproxy import ctx
import random
from datetime import datetime
import logging

class Fiddleitm:
    def __init__(self):
        version_local = "0.1"
        print('#################')
        print(' fiddleitm v.' + version_local)
        print('#################')
        # Initialize variables
        self.rules = []
        self.anti_vm_list = [
            "VMware", "vmtoolsd", "VMwareService", "Vmwaretray", "vm3dservice",
            "VGAuthService", "Vmwareuser", "TPAutoConnSvc", "VirtualBox", "VBoxService",
            "VBoxTray", "Fiddler", "FSE2"
        ]
        self.do_anti_vm = False
        # Check for update
        session = requests.Session()
        session.trust_env = False
        read_version = 'https://raw.githubusercontent.com/jeromesegura/fiddleitm/main/fiddleitm.py'
        response = session.get(read_version)
        if response.status_code:
            try:
                version_online = re.findall(r'version_local\s=\s.+', response.text)[0][17:20]
                if version_local != version_online:
                    # Play sound
                    print('\a', end = '')
                    print('->> A new version of fiddleitm is available (v.' + version_online + ')!')
            except Exception:
                logging.error("Failed to read fiddleitm version")
        # Load main rules
        logging.info("Loading main rules...")
        session = requests.Session()
        session.trust_env = False
        self.rules_url = 'https://raw.githubusercontent.com/jeromesegura/fiddleitm/main/rules.txt'
        response = session.get(self.rules_url)
        if response.status_code:
            rules = response.text.split('\r\n')
            # Get rules date
            rules_date = re.findall(r'Last updated:\s.+', response.text)[0][-11:].strip()
            # Count number of rules
            rules_counter = self.add_rules_list(rules)
        logging.info(" -> " + str(rules_counter) + " main rules loaded successfully (" + rules_date + ")")
        # Load local rules (if file present)
        logging.info("Loading local rules...")
        if os.path.isfile('localrules.txt'):
            with open('localrules.txt', 'r') as local_rules:
                rules = local_rules.read().splitlines()
                # Count number of rules
                rules_counter = self.add_rules_list(rules)
                if rules_counter == 0:
                    logging.info(" -> no rules found!")
                else:
                    logging.info(" -> " + str(rules_counter) + " local rules loaded successfully")
        else:
            logging.info("No local rules found (localrules.txt)")

    def load(self, loader):
        loader.add_option(
            name="log_events",
            typespec=bool,
            default=False,
            help="log events from rules that match",
        )
        loader.add_option(
            name="custom_user_agent",
            typespec=str,
            default="",
            help="use a custom user-agent from command line",
        )
        loader.add_option(
            name="custom_accept_language",
            typespec=str,
            default="",
            help="use a custom accept-language from command line",
        )

    """ Add remote and local rules """
    def add_rules_list(self, rules):
        rules_counter = 0
        for rule in rules:
            rule = rule.rstrip('\n')
            # Add rules
            if not rule.startswith("#"):
                self.rules.append(rule)
                rules_counter += 1
        return rules_counter

    """ anti-vm """
    def anti_vm(self, flow):
        request_response = flow.request.text
        modified_request_response = request_response
        # Loop through list of keywords to replace """
        for keyword in self.anti_vm_list:
            if keyword in request_response:
                # Replace with random word from list
                random_list = ["Intel", "svchost", "svchost.exe", "Dell,INC.", "nVidia", "GeForce"]
                random_word = random.choice(random_list)
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
                if "rule_name = \"" in condition:
                    rule_name = condition.strip("rule_name = ").strip('"')
                if "host_name = \"" in condition:
                    host_name_string = condition.strip("host_name = ").strip('"')
                    matched_condition = self.check_hostname_string(flow, rule_name, host_name_string)
                    if matched_condition == False:
                        break
                if "host_name = /" in condition:
                    host_name_regex = condition.strip("host_name = /").strip('"')
                    matched_condition = self.check_hostname_regex(flow, rule_name, host_name_regex)
                    if matched_condition == False:
                        break
                if "host_ip = \"" in condition:
                    host_ip_string = condition.strip("host_ip = ").strip('"')
                    matched_condition = self.check_host_ip_string(flow, rule_name, host_ip_string)
                    if matched_condition == False:
                        break
                if "host_ip = /" in condition:
                    host_ip_regex = condition.strip("host_ip = /").strip('"')
                    matched_condition = self.check_host_ip_regex(flow, rule_name, host_ip_regex)
                    if matched_condition == False:
                        break
                if "response_body = \"" in condition:
                    response_body_string = condition.strip("response_body = ").strip('"')
                    matched_condition = self.check_response_body_string(flow, rule_name, response_body_string)
                    if matched_condition == False:
                        break
                if "response_body = /" in condition:
                    response_body_regex = condition.strip("response_body = /").strip('"')
                    matched_condition = self.check_response_body_regex(flow, rule_name, response_body_regex)
                    if matched_condition == False:
                        break
                if "full_url = \"" in condition:
                    full_url_string = condition.strip("full_url = ").strip('"')
                    matched_condition = self.check_full_url_string(flow, rule_name, full_url_string)
                    if matched_condition == False:
                        break
                if "full_url = /" in condition:
                    full_url_regex = condition.strip("full_url = /").strip('"')
                    matched_condition = self.check_full_url_regex(flow, rule_name, full_url_regex)
                    if matched_condition == False:
                        break

            # check if we have a match for all conditions
            if matched_condition:
                # Call mark_flow function
                self.mark_flow(flow, rule_name)

    """ Check for hostname condition (string) """
    def check_hostname_string(self, flow, rule_name, host_name_string):
        if host_name_string in flow.request.host:
            return True
        else:
            return False

    """ Check for hostname condition (regex) """
    def check_hostname_regex(self, flow, rule_name, host_name_regex):
        if re.search(host_name_regex, flow.request.pretty_url):
            return True
        else:
            return False

    """ Check for IP address condition (string) """
    def check_host_ip_string(self, flow, rule_name, host_ip_string):
        try:
            if host_ip_string in flow.server_conn.peername[0]:
                return True
            else:
                return False
        except Exception:
            return False

    """ Check for IP address condition (regex) """
    def check_host_ip_regex(self, flow, rule_name, host_ip_regex):
        try:
            if re.search(host_ip_regex, flow.server_conn.peername[0]):
                return True
            else:
                return False
        except Exception:
            return False

    """ Check for response body condition (string) """
    def check_response_body_string(self, flow, rule_name, response_body_string):
        # Only check if response exists and matches content-type
        try:
            if flow.response and flow.response.content and "Content-Type" in flow.response.headers and \
                "jeromesegura/fiddleitm/" not in flow.request.pretty_url and \
                 ("text" in flow.response.headers["Content-Type"] or "javascript" in flow.response.headers["Content-Type"]):
                if response_body_string in flow.response.text:
                    return True
                else:
                    return False
        except Exception:
            logging.error("error while decoding content (string) " + flow.request.pretty_url)

    """ Check for response body condition (regex) """
    def check_response_body_regex(self, flow, rule_name, response_body_regex):
        # Only check if response exists and matches content-type
        try:
            if flow.response and flow.response.content and "Content-Type" in flow.response.headers and \
                "jeromesegura/fiddleitm/" not in flow.request.pretty_url and \
                 ("text" in flow.response.headers["Content-Type"] or "javascript" in flow.response.headers["Content-Type"]):
                if re.search(response_body_regex, flow.response.text):
                    return True
                else:
                    return False
        except Exception:
            logging.error("error while decoding content (regex) " + flow.request.pretty_url)

    """ Check for full URL condition (string) """
    def check_full_url_string(self, flow, rule_name, full_url_string):
        if full_url_string in flow.request.pretty_url:
            return True
        else:
            return False

    """ Check for full URL condition (regex) """
    def check_full_url_regex(self, flow, rule_name, full_url_regex):
        if re.search(full_url_regex, flow.request.pretty_url):
            return True
        else:
            return False

    """ Mark flows """
    def mark_flow(self, flow, rule_name):
        # Play sound
        print('\a', end = '')
        # Print detection name in console
        print(rule_name)
        # Mark flow in web UI
        flow.marked = ":red_circle:"
        flow.comment = rule_name
        # Log events to file
        if ctx.options.log_events:
            get_referer = flow.request.headers.get("referer")
            if get_referer is not None:
                referer = get_referer
            else:
                referer = 'N/A'
            with open("rules.log", 'a') as rules_log:
                date_time = datetime.now().strftime("%m/%d/%Y %H:%M")
                rules_log.write(date_time + ',' + rule_name + ',' + flow.request.pretty_url + ',' + referer + '\n')
        # Check if anti-vm was detected
        if "Fingerprinting" in flow.comment:
            self.do_anti_vm = True
        else:
            self.do_anti_vm = False

    """ flow request """
    def request(self, flow: http.HTTPFlow) -> None:
        # Override user-agent if needed
        if ctx.options.custom_user_agent:
            flow.request.headers["user-agent"] = ctx.options.custom_user_agent
        # Override accept-language if needed
        if ctx.options.custom_accept_language:
            flow.request.headers["accept-language"] = ctx.options.custom_accept_language
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