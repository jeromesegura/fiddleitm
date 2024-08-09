"""
This is an addon for mitmproxy that inspects flows and
identifies malicious web traffic.

GitHub: https://github.com/malwareinfosec/fiddleitm

Usage:
    mitmproxy -s fiddleitm.py
    mitmweb -s fiddleitm.py
    mitmdump -s fiddleitm.py

Options:

 modify default user-agent with your own --set custom_user_agent=""
 
 modify default referer with your own --set custom_referer=""

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

 Optional:
  emoji_name
  (Displays an emoji to mark the flow. List of emojis: https://api.github.com/emojis)

 Example:
 rule_name = "My first rule"; full_url = /[a-z]{5}[0-9]{2}/; response_body = "DevTools"; response_body = /function[0-9]{2}/; emoji_name = ":grapes:"
"""

import os
import requests
import re
import random
import time
from datetime import datetime
from time import strftime, localtime
import logging
import typing
import pyperclip
from collections.abc import Sequence
import tempfile
import shutil
import mitmproxy

from mitmproxy import http
from mitmproxy import ctx
from mitmproxy import command
from mitmproxy import flow
from mitmproxy import http
from mitmproxy import hooks
from mitmproxy.addonmanager import Loader
from mitmproxy.ctx import master
from mitmproxy.log import ALERT

class Fiddleitm:
    def __init__(self):
        version_local = "0.2.2"
        print('#################')
        print('fiddleitm v.' + version_local)
        print('#################')
        # Initialize variables
        self.rules = []
        self.filters = []
        self.anti_vm_list = [
            "VMware", "vmtoolsd", "VMwareService", "Vmwaretray", "vm3dservice",
            "VGAuthService", "Vmwareuser", "TPAutoConnSvc", "VirtualBox", "VBoxService",
            "VBoxTray", "Fiddler", "FSE2"
        ]
        self.do_anti_vm = False        
        # Call check internet connection function
        if self.internet_connection():
            # Call check for latest mitmproxy version
            self.check_mitmproxy_version()
            # Call check for fiddleitm update function
            self.check_fiddleitm_update(version_local)
            # Call load main rules function
            self.load_main_rules()
            # Call filters function
            self.load_filters()
        else:
            logging.info('Offline mode')       
        # Call load local rules function
        self.load_local_rules()

    """ These are the command-line arguments"""
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
            name="custom_referer",
            typespec=str,
            default="",
            help="use a custom referer from command line",
        )
        loader.add_option(
            name="custom_accept_language",
            typespec=str,
            default="",
            help="use a custom accept-language from command line",
        )
        loader.add_option(
            name = "web_columns",
            typespec=typing.Sequence[str],
            default=['index', 'icon', 'path', 'method', 'status', 'size', 'comment', 'time'],
            help="use custom columns",
        )
        
    """ Check for internet connection"""
    def internet_connection(self):
        try:
            os.environ['no_proxy'] = '*'
            response = requests.get("https://google.com", timeout=5)
            return True
        except requests.ConnectionError:
            return False

    """ Check for the latest version of mitmproxy """
    def check_mitmproxy_version(self):
        response = requests.get("https://github.com/mitmproxy/mitmproxy/releases/latest")
        if response.status_code:
            try:
                mitmproxy_version = response.url.split("/").pop()
                print('->> The latest version for mitmproxy is: ' + mitmproxy_version)
            except Exception:
                logging.error("Failed to read latest mitmproxy version")                
    
    """ Check for fiddleitm update """
    def check_fiddleitm_update(self, version_local):
        session = requests.Session()
        session.trust_env = False
        read_version = 'https://raw.githubusercontent.com/malwareinfosec/fiddleitm/main/fiddleitm.py'
        response = session.get(read_version)
        if response.status_code:
            try:
                for item in response.text.split("\n"):
                    if "version_local =" in item:
                        version_online = item.strip().replace("version_local = \"", "")[:-1]
                        break
                if version_local != version_online:
                    # Play sound
                    print('\a', end = '')
                    print('->> A new version of fiddleitm is available from the GitHub repo: v' + version_online + '!')
                    answer = input('Would you like to install it now? (y/n)\n') 
                    if answer == "y":
                        print(f"Installing v." + version_online + "...")
                        url = "https://raw.githubusercontent.com/malwareinfosec/fiddleitm/main/fiddleitm.py"
                        filename = "fiddleitm.py"
                        try:
                            # Download to a temporary file
                            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                                response = requests.get(url)
                                response.raise_for_status()  # Raise an exception for non-2xx status codes
                                temp_file.write(response.content)

                            # Replace the original file with the downloaded content
                            shutil.copy2(temp_file.name, filename)

                            print(f"Downloaded and replaced {filename} successfully!")
                        except requests.exceptions.RequestException as e:
                            print(f"Error downloading {filename}: {e}")
                        finally:
                            # Clean up the temporary file
                            if temp_file.name and os.path.exists(temp_file.name):
                                os.remove(temp_file.name)
            except Exception:
                logging.error("Failed to read fiddleitm version")
    
    """ Main rules are those stored in the GitHub repository """
    def load_main_rules(self):
        logging.info("Loading main rules...")
        session = requests.Session()
        session.trust_env = False
        self.rules_url = 'https://raw.githubusercontent.com/malwareinfosec/fiddleitm/main/rules.txt'
        response = session.get(self.rules_url)
        if response.status_code:
            rules = response.text.split('\r\n')
            # Get rules date
            rules_date = re.findall(r'Last updated:\s.+', response.text)[0][-11:].strip()
            # Count number of rules
            rules_counter = self.add_rules_list(rules)
            logging.info(" -> " + str(rules_counter) + " main rules loaded successfully (" + rules_date + ")")
            
    """ Filters stored in the GitHub repository """
    def load_filters(self):
        logging.info("Loading filters...")
        session = requests.Session()
        session.trust_env = False
        self.rules_url = 'https://raw.githubusercontent.com/malwareinfosec/fiddleitm/main/filters.txt'
        response = session.get(self.rules_url)
        if response.status_code:
            filters = response.text.split('\r\n')
            # Count number of filters
            filters_counter = self.add_filters_list(filters)
            logging.info(" -> " + str(filters_counter) + " filters loaded successfully")

    """ Function to check for filters """
    def check_filters(self, flow):
        # Check filters
        if flow.request.pretty_url == "https://github.com/malwareinfosec/fiddleitm/blob/main/rules.txt" or \
           flow.request.pretty_url == "https://raw.githubusercontent.com/malwareinfosec/fiddleitm/main/rules.txt":
            return True
        for filter in self.filters:
            if filter == flow.request.host:
                return True
                break
        return False
    
    """ Local rules are your own, stored locally, on the same path as this script """
    def load_local_rules(self):
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

    """ Add remote and local rules """
    def add_rules_list(self, rules):
        rules_counter = 0
        for rule in rules:
            rule = rule.rstrip('\n')
            # Add rules
            if rule.startswith("rule_name"):
                self.rules.append(rule)
                rules_counter += 1
        return rules_counter
        
    """ Add filters """
    def add_filters_list(self, filters):
        filters_counter = 0
        for filter in filters:
            filter = filter.rstrip('\n')
            # Add filters
            self.filters.append(filter)
            filters_counter += 1
        return filters_counter

    """ Convert epoch time to friendly format """
    def convert_epoch(self,epoch_time):
        seconds = int(epoch_time)
        milliseconds = int((epoch_time - seconds) * 1000)  # convert to milliseconds
        temp_timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(seconds))  # format in UTC
        formatted_timestamp = f"{temp_timestamp}.{milliseconds:03d}"
        return formatted_timestamp


    """ Anti-vm replaces certain keywords used for VM detection """
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

    """ Check conditions based on both main and local rules """
    def check_rules(self, flow):
        # Loop through rules
        for rule in self.rules:
            # Create list of elements for each rule
            elements_list = rule.split("; ")
            # get rule name
            rule_name = elements_list[0].replace("rule_name = \"", "")[:-1]
            # remove rule name from elements_list
            elements_list.pop(0)
            # get emoji_name if it's there by finding its index in the list
            emoji_index_list = [elements_list.index(l) for l in elements_list if l.startswith('emoji_name = ')]
            if emoji_index_list:
                # convert it to an integer
                emoji_index = int(''.join(map(str, emoji_index_list)))
                # get emoji_name value
                emoji_name = elements_list[emoji_index].replace("emoji_name = \"", "")[:-1]
                # remove emoji name from elements_list
                elements_list.pop(emoji_index)
            else:
                emoji_name = None
            # loop through conditions
            matched_condition = False
            for condition in elements_list:
                if "host_name = \"" in condition:
                    host_name_string = condition.replace("host_name = \"", "")[:-1]
                    matched_condition = self.check_hostname_string(flow, rule_name, host_name_string)
                    if matched_condition == False:
                        break
                if "host_name = /" in condition:
                    host_name_regex = condition.replace("host_name = /", "")[:-1]
                    matched_condition = self.check_hostname_regex(flow, rule_name, host_name_regex)
                    if matched_condition == False:
                        break
                if "host_ip = \"" in condition:
                    host_ip_string = condition.replace("host_ip = \"", "")[:-1]
                    matched_condition = self.check_host_ip_string(flow, rule_name, host_ip_string)
                    if matched_condition == False:
                        break
                if "host_ip = /" in condition:
                    host_ip_regex = condition.replace("host_ip = /", "")[:-1]
                    matched_condition = self.check_host_ip_regex(flow, rule_name, host_ip_regex)
                    if matched_condition == False:
                        break
                if "response_body = \"" in condition:
                    response_body_string = condition.replace("response_body = \"", "")[:-1].replace("\\\"", "\"").replace("\\'", "'").replace("\\\\", "\\")
                    matched_condition = self.check_response_body_string(flow, rule_name, response_body_string)
                    if matched_condition == False:
                        break
                if "response_body = /" in condition:
                    response_body_regex = condition.replace("response_body = /", "")[:-1]
                    matched_condition = self.check_response_body_regex(flow, rule_name, response_body_regex)
                    if matched_condition == False:
                        break
                if "full_url = \"" in condition:
                    full_url_string = condition.replace("full_url = \"", "")[:-1]
                    matched_condition = self.check_full_url_string(flow, rule_name, full_url_string)
                    if matched_condition == False:
                        break
                if "full_url = /" in condition:
                    full_url_regex = condition.replace("full_url = /", "")[:-1]
                    matched_condition = self.check_full_url_regex(flow, rule_name, full_url_regex)
                    if matched_condition == False:
                        break

            # check if we have a match for all conditions
            if matched_condition:
                # Call mark_flow function
                self.mark_flow(flow, rule_name, emoji_name)
    
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
            if "malwareinfosec/fiddleitm/" not in flow.request.pretty_url:
                if flow.response:
                    if flow.response.content:
                        if "Content-Type" in flow.response.headers:
                            if "text" in flow.response.headers["Content-Type"] or \
                               "javascript" in flow.response.headers["Content-Type"] or \
                               "json" in flow.response.headers["Content-Type"]:
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
            if "malwareinfosec/fiddleitm/" not in flow.request.pretty_url:
                if flow.response:
                    if flow.response.content:
                        if "Content-Type" in flow.response.headers:
                            if "text" in flow.response.headers["Content-Type"] or \
                               "javascript" in flow.response.headers["Content-Type"] or \
                               "json" in flow.response.headers["Content-Type"]:
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
    def mark_flow(self, flow, rule_name, emoji_name):
        # Play sound
        print('\a', end = '')
        try:
            # Print detection name in console
            print(f"{rule_name} found in flow #{str(master.view.index(flow)+1)}")
        except Exception:
            logging.error("No view attribute in mitmdump")
        # Mark flow in web UI
        if emoji_name is not None:
            flow.marked = emoji_name
        else:
            flow.marked = ":red_circle:"
        flow.comment = rule_name
        # Log events to file
        if ctx.options.log_events:
            # Assign default values
            epochtime, comment, referer, ipaddress, servername = (value for value in ["", "", "", "", ""])
            if flow.timestamp_created is not None:
                epochtime = str(int(flow.timestamp_created))
                if epochtime is None:
                    epochtime = "N/A"
                
            if flow.server_conn.peername is not None:
                ipaddress = flow.server_conn.peername[0]
                if ipaddress is None:
                    ipaddress = "N/A"
                
            if flow.response is not None and flow.response.headers:            
                servername = flow.response.headers.get("server")
                if servername is None:
                    servername = "N/A"
            if flow.response is not None and flow.response.headers:
                    referer = flow.request.headers.get("referer")
                    if referer is None:
                        referer = "N/A"
            # Write to file
            with open("rules.log", 'a') as rules_log:
                rules_log.write(epochtime + "," + ipaddress + "," + servername + "," + flow.request.pretty_url + "," + referer + "," + flow.comment + "\n")
        # Check if anti-vm was detected
        if "Fingerprinting" in flow.comment:
            self.do_anti_vm = True
        else:
            self.do_anti_vm = False

    """ flow request """
    def request(self, flow: http.HTTPFlow) -> None:
        # Check filters
        if not self.check_filters(flow):
            # Override user-agent if needed
            if ctx.options.custom_user_agent:
                flow.request.headers["user-agent"] = ctx.options.custom_user_agent
            # Override referer if needed
            if ctx.options.custom_referer:
                flow.request.headers["Referer"] = ctx.options.custom_referer
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
        # Check filters
        if not self.check_filters(flow):
            self.check_rules(flow)

    """ Begin commands """
    """ For mitmweb, go to Options and select Display Command Bar.
        It will add a command line at the bottom of the browser window.
        Type commands like this: fiddleitm.commandname @all/@shown/@focus/@hidden/@marked/@unmarked
    """

    """ This command copies to the clipboard any URL that had a detection """
    @command.command("fiddleitm.printurls")
    def printurls(self, flows: Sequence[flow.Flow]) -> None:
        self.traffic_summary = []
        for f in flows:
            if isinstance(f, http.HTTPFlow):
                if f.comment != "":
                    self.traffic_summary.append(f.request.pretty_url + "," + f.comment)
        """ Check list is not empty """
        if len(self.traffic_summary) > 0:
            pyperclip.copy('\n'.join(self.traffic_summary))
            logging.log(ALERT, "Copied detected flows to clipboard")
        else:
            logging.log(ALERT, "There was nothing to copy")
        return None
    
    """ This command runs rules against the current flows"""
    @command.command("fiddleitm.runrules")
    def runrules(self, flows: Sequence[flow.Flow]) -> None:
        # call function to reload rules
        self.rules = []
        self.load_main_rules()
        self.load_local_rules()
        for f in flows:
            if isinstance(f, http.HTTPFlow):
                # Check filters
                if not self.check_filters(f):
                    self.check_rules(f)
        ctx.master.addons.trigger(hooks.UpdateHook(flows)) 
    
    """ This command updates both main and local rules """
    @command.command("fiddleitm.updaterules")
    def updaterules(self) -> None:
        # call function to reload rules
        self.rules = []
        self.load_main_rules()
        self.load_local_rules()
    
    """ This command searches through flows using a regex expression """
    @command.command("fiddleitm.search")
    def search(
        self,
        flows: Sequence[flow.Flow],
        searchquery: str,
    ) -> None:
        for f in flows:
            if isinstance(f, http.HTTPFlow):
                # Search within the flow's response headers
                try:
                    if f.response is not None and f.response.headers:            
                        location = f.response.headers.get("location")
                        if re.search(searchquery, location, flags=re.IGNORECASE):
                            print(f"{searchquery} found in response headers for flow #{master.view.index(f)+1}")
                            f.marked = ":purple_circle:"
                            f.comment = "Found: " + searchquery
                except Exception:
                    logging.error("error while searching response headers")
                        
                # Search within the flow's response body
                try:
                    if "malwareinfosec/fiddleitm/" not in f.request.pretty_url:
                        if f.response:
                            if f.response.content:
                                if "Content-Type" in f.response.headers:
                                    if "text" in f.response.headers["Content-Type"] or \
                                       "javascript" in f.response.headers["Content-Type"] or \
                                       "json" in f.response.headers["Content-Type"]:
                                        if re.search(searchquery, f.response.text, flags=re.IGNORECASE):
                                            print(f"{searchquery} found in response body for flow #{master.view.index(f)+1}")
                                            f.marked = ":purple_circle:"
                                            f.comment = "Found: " + searchquery
                except Exception:
                    logging.error("error while searching response body")
        print("Done searching")
        ctx.master.addons.trigger(hooks.UpdateHook(flows))
        
    """ This command runs connect-the-dots"""
    @command.command("fiddleitm.connect")
    def connectdots(self, flows: Sequence[flow.Flow], last_flow: int) -> None:
        print("Running connect-the-dots...")
        connect_index = []
        current_hostname = ''
        for f in reversed(flows):
            if isinstance(f, http.HTTPFlow):
                flow_index = master.view.index(f)+1
                # Get last flow hostname
                if flow_index == last_flow:
                    current_hostname = f.request.host
                    # Add to list
                    connect_index.append(flow_index)
                
                # Search previous sessions
                
                # Search within the flow's hostname
                try:
                    if current_hostname:
                        if re.search(current_hostname, f.request.host, flags=re.IGNORECASE):
                            # Add to list
                            connect_index.append(flow_index)
                except Exception:
                    logging.error("error connect-the-dots flow's hostname: " + f.request.pretty_url)
                
                # Search within the flow's response headers
                try:
                    if f.response:
                        if "location" in f.response.headers:           
                            location = f.response.headers.get("location")
                            if re.search(current_hostname, location, flags=re.IGNORECASE):
                                # Assign new hostname to look for
                                current_hostname = f.request.host
                                # Add to list
                                connect_index.append(flow_index)                       
                except Exception:
                    logging.error("error connect-the-dots response headers: " + f.request.pretty_url)
                # Search within the flow's response body
                try:
                    if "malwareinfosec/fiddleitm/" not in f.request.pretty_url:
                        if f.response:
                            if f.response.content:
                                if "Content-Type" in f.response.headers:
                                    if "text" in f.response.headers["Content-Type"] or \
                                       "javascript" in f.response.headers["Content-Type"] or \
                                       "json" in f.response.headers["Content-Type"]:
                                        if re.search(current_hostname, f.response.text, flags=re.IGNORECASE):
                                            # Assign new hostname to look for
                                            current_hostname = f.request.host
                                            # Add to list
                                            connect_index.append(flow_index)
                except Exception:
                    logging.error("error connect-the-dots response body: " + f.request.pretty_url)
                    
        # Loop through flows again to assign numbers
        number = 1
        for f in flows:
            # Check if the current flow index matches with the flow from our list
            if isinstance(f, http.HTTPFlow):
                flow_index = master.view.index(f)+1
                if flow_index in connect_index:
                    pattern = r'\(\d+\)'
                    f.comment = f"({number}) {re.sub(pattern, '', f.comment)}"
                    number +=1 
        ctx.master.addons.trigger(hooks.UpdateHook(flows))
        print("Done!")
        
    """ This command clears comments for all flows"""
    @command.command("fiddleitm.clear")
    def clear(self, flows: Sequence[flow.Flow]) -> None:
        for f in flows:
            if isinstance(f, http.HTTPFlow):
                f.comment = ''
        ctx.master.addons.trigger(hooks.UpdateHook(flows)) 
        
addons = [Fiddleitm()]