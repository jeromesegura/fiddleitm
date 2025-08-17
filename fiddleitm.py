"""
This is mitmproxy addon designed to identify malicious web traffic

GitHub: https://github.com/jeromesegura/fiddleitm

Usage:
    mitmweb -s fiddleitm.py
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
from collections.abc import Sequence
import tempfile
import shutil
import sys
import json
import mitmproxy

from mitmproxy import http
from mitmproxy import ctx
from mitmproxy import command
from mitmproxy import flow
from mitmproxy import hooks
from mitmproxy.addonmanager import Loader
from mitmproxy.ctx import master
from mitmproxy.log import ALERT
from mitmproxy import io
from hashlib import sha256

# --- Configuration ---
# This is your current local version
CURRENT_LOCAL_VERSION = "1.0.3"

# GitHub repository details for update checking
GITHUB_REPO_OWNER = "jeromesegura"
GITHUB_REPO_NAME = "fiddleitm"

RULES_URL = "https://raw.githubusercontent.com/jeromesegura/fiddleitm/main/rules.json"
LOCAL_RULES_FILE = "localrules.json" # Name of your local rules file

# --- Content Filtering Configuration ---
# Only content types explicitly listed here will be processed by rules.
# If this list is empty, ALL content types will be processed (no content type filtering).
INCLUDED_CONTENT_TYPES = [
    "text/html",
    "text/plain",
    "text/css",
    "application/javascript",
    "text/javascript",          # Variation
    "application/x-javascript", # Older variation
    "application/json",
    "application/xml",
    "text/xml",                 # Explicit XML
    "application/xhtml+xml",    # XHTML
    "application/x-www-form-urlencoded", # Form data
    "multipart/form-data",      # Form data with files
    "application/graphql",      # GraphQL APIs
    "application/ld+json",      # JSON-LD
    "text/csv",                 # CSV files
]

# File Extensions for Traffic Lite Mode ---
# If traffic_lite option is enabled, requests with these extensions will be dropped.
DROPPED_EXTENSIONS = (
    ".gif",
    ".jpg",
    ".jpeg",
    ".png",
    ".webp",
    ".wav",
    ".mp4",
    ".svg",     # SVG images
    ".ico",     # Favicons
    ".bmp",     # Bitmap images
    ".tiff",    # TIFF images
    ".tif",     # TIFF images
    ".avif",    # AVIF images
    ".heif",    # HEIF images
    ".heic",    # HEIC images
    ".mp3",     # MP3 audio
    ".ogg",     # Ogg audio/video
    ".oga",     # Ogg audio
    ".flac",    # FLAC audio
    ".aac",     # AAC audio
    ".webm",    # WebM video/audio
    ".mov",     # QuickTime video
    ".avi",     # AVI video
    ".mkv",     # MKV video
    ".flv",     # Flash Video
    ".3gp",     # 3GPP video
    ".ogv",     # Ogg Video
    ".ts",      # MPEG Transport Stream
    ".woff",    # Web Open Font Format
    ".woff2",   # Web Open Font Format 2
    ".ttf",     # TrueType Font
    ".otf",     # OpenType Font
    ".eot",     # Embedded OpenType
)

def _simple_version_to_tuple(version_str: str) -> tuple:
    """
    Parses a version string (e.g., '1.0.0', 'v0.5') into a tuple of integers
    for comparison.
    """
    # Remove 'v' prefix if present (common in GitHub release tags)
    if version_str.lower().startswith('v'):
        version_str = version_str[1:]
    
    parts = []
    for part in version_str.split('.'):
        try:
            parts.append(int(part))
        except ValueError:
            # If a part isn't an integer (e.g., 'beta', 'alpha'),
            # treat it as 0 to ensure numeric parts are prioritized.
            parts.append(0)
    return tuple(parts)

# --- Helper function to get latest GitHub version ---
def get_latest_github_version(owner: str, repo: str) -> str | None:
    """
    Fetches the latest *release tag name* from a GitHub repository using the API.
    """
    session = requests.Session()
    # Crucial for mitmproxy environments to avoid inheriting system proxy
    session.trust_env = False

    # Use the /releases/latest endpoint
    api_url = f'https://api.github.com/repos/{owner}/{repo}/releases/latest'

    try:
        response = session.get(api_url, timeout=10)
        response.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)
        data = response.json()
        
        # The 'tag_name' field holds the version tag
        return data.get('tag_name')
    except requests.exceptions.RequestException as e:
        ctx.log.warn(f"fiddleitm: Failed to fetch latest GitHub release for {owner}/{repo}: {e}")
        return None
    except json.JSONDecodeError:
        ctx.log.warn(f"fiddleitm: Failed to parse GitHub API response for {owner}/{repo} (invalid JSON).")
        return None
    except Exception as e:
        ctx.log.error(f"fiddleitm: An unexpected error occurred while fetching GitHub release: {e}")
        return None


class Fiddleitm:
    version_local = CURRENT_LOCAL_VERSION # Use the global constant

    def __init__(self):
        """Initializes the Fiddleitm addon."""
        ctx.log.info('#################')
        ctx.log.info(f'fiddleitm v.{self.version_local}')
        ctx.log.info('#################')

        self.parsed_rules = []
        
        # Initialize options to their defaults (will be updated by configure hook)
        self.custom_user_agent = None
        self.custom_referer = None
        self.custom_accept_language = None
        self.log_events_enabled = False
        self.traffic_lite_enabled = False

        # Determine internet connection status once for __init__ lifecycle
        self._has_internet_connection = self.internet_connection()

        if self._has_internet_connection:
            ctx.log.info('Internet connection detected.')
            self.check_mitmproxy_version()
            self.check_fiddleitm_update(self.version_local)
        else:
            ctx.log.info('Offline mode: No internet connection detected.')

        ctx.log.info("Fiddleitm addon initialized")

        self.load_rules() # load_rules will handle all rule loading, including main and local

    def load(self, loader: Loader):
        """
        Mitmproxy addon hook: Called when the addon is loaded.
        Used to register options.
        """
        loader.add_option(
            name = "web_columns",
            typespec=typing.Sequence[str],
            default=['index', 'icon', 'method', 'status', 'path', 'size', 'comment'],
            help="use custom columns",
        )
        loader.add_option(
            name = "log_events",
            typespec=bool,
            default=False,
            help="Log matched rule events to rules.log file.",
        )
        loader.add_option(
            name = "custom_user_agent",
            typespec=typing.Optional[str],
            default=None,
            help="Set a custom User-Agent header for all requests.",
        )
        loader.add_option(
            name = "custom_referer",
            typespec=typing.Optional[str],
            default=None,
            help="Set a custom Referer header for all requests.",
        )
        loader.add_option(
            name = "custom_accept_language",
            typespec=typing.Optional[str],
            default=None,
            help="Set a custom Accept-Language header for all requests.",
        )
        loader.add_option(
            name = "traffic_lite",
            typespec=bool,
            default=False,
            help="Enable 'traffic lite' mode to drop common image/video requests.",
        )

    def configure(self, updated: typing.Set[str]):
        """
        Mitmproxy addon hook: Called when options change.
        Updates internal state based on changed mitmproxy options.
        """
        if "custom_user_agent" in updated:
            self.custom_user_agent = ctx.options.custom_user_agent
            ctx.log.info(f"fiddleitm: Custom User-Agent set to: {self.custom_user_agent}")
        if "custom_referer" in updated:
            self.custom_referer = ctx.options.custom_referer
            ctx.log.info(f"fiddleitm: Custom Referer set to: {self.custom_referer}")
        if "custom_accept_language" in updated:
            self.custom_accept_language = ctx.options.custom_accept_language
            ctx.log.info(f"fiddleitm: Custom Accept-Language set to: {self.custom_accept_language}")       
        if "log_events" in updated:
            self.log_events_enabled = ctx.options.log_events
            ctx.log.info(f"fiddleitm: Event logging {'enabled' if self.log_events_enabled else 'disabled'}.")      
        if "traffic_lite" in updated:
            self.traffic_lite_enabled = ctx.options.traffic_lite
            ctx.log.info(f"fiddleitm: Traffic Lite mode {'enabled' if self.traffic_lite_enabled else 'disabled'}.")

    def check_mitmproxy_version(self):
        """ Check for the latest version of mitmproxy """
        session = requests.Session()
        session.trust_env = False
        try:
            response = session.get("https://github.com/mitmproxy/mitmproxy/releases/latest", timeout=5)
            response.raise_for_status()
            mitmproxy_version = response.url.split("/").pop()
            ctx.log.info(f'->> The latest version for mitmproxy is: {mitmproxy_version}')
        except requests.exceptions.RequestException as e:
            ctx.log.warn(f"Failed to check mitmproxy version: {e}")

    def internet_connection(self) -> bool:
        """ Check for internet connection """
        try:
            os.environ['no_proxy'] = '*' # Temporarily bypass any proxy for this check
            response = requests.get("https://google.com", timeout=5)
            response.raise_for_status()
            return True
        except requests.exceptions.RequestException as e:
            ctx.log.debug(f"Internet connection check failed: {e}")
            return False
        finally:
            if 'no_proxy' in os.environ:
                del os.environ['no_proxy'] # Clean up

    def check_fiddleitm_update(self, version_local: str):
        """ Check for fiddleitm update using the shared get_latest_github_version function. """
        ctx.log.info(f"fiddleitm: Checking for updates (current version: {version_local})...")

        version_online_str = get_latest_github_version(GITHUB_REPO_OWNER, GITHUB_REPO_NAME)
        session = requests.Session() # Needs a session for the download later
        session.trust_env = False

        if version_online_str:
            try:
                # Use the custom simple parser
                parsed_version_local = _simple_version_to_tuple(version_local)
                parsed_version_online = _simple_version_to_tuple(version_online_str)

                if parsed_version_online > parsed_version_local:
                    ctx.log.alert('\a') # Bell sound for attention (now back to ALERT for purple)
                    ctx.log.alert(f'---')
                    ctx.log.alert(f'### NEW fiddleitm UPDATE AVAILABLE! ###')
                    ctx.log.alert(f'Your version: {version_local}')
                    ctx.log.alert(f'Latest version: {version_online_str}')
                    ctx.log.alert('Fiddleitm will attempt to auto-reload after update. If issues persist, please restart mitmproxy.')
                    ctx.log.alert(f'---')

                    # Prompt for download - this will block mitmproxy until answered
                    answer = input('Would you like to install it now? (y/n)\n')
                    if answer.lower() == "y":
                        ctx.log.info(f"Installing v.{version_online_str}...")
                        # Construct the raw file URL using the tag name
                        url = f"https://raw.githubusercontent.com/{GITHUB_REPO_OWNER}/{GITHUB_REPO_NAME}/{version_online_str}/fiddleitm.py"
                        filename = os.path.basename(__file__)

                        try:
                            # Use a temporary file to download, then replace the original
                            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                                download_response = session.get(url, timeout=10)
                                download_response.raise_for_status()
                                temp_file.write(download_response.content)

                            shutil.copy2(temp_file.name, filename)
                            ctx.log.info(f"Downloaded and replaced {filename} successfully!")
                            ctx.log.info("Mitmproxy should auto-reload the new version. If not, please restart.")
                        except requests.exceptions.RequestException as e:
                            ctx.log.error(f"Failed to download update from {url}: {e}")
                        except shutil.Error as e:
                            ctx.log.error(f"Failed to replace {filename}: {e}. You might need to manually replace it.")
                        except Exception as e:
                            ctx.log.error(f"An unexpected error occurred during update: {e}")
                        finally:
                            # Clean up the temporary file
                            if os.path.exists(temp_file.name):
                                os.remove(temp_file.name)
                    else:
                        ctx.log.info("Update deferred by user.")
                else:
                    ctx.log.info(f"fiddleitm: You are running the latest version ({version_local}).")
            except Exception as e:
                ctx.log.warn(f"fiddleitm: Error comparing versions ('{version_local}' vs '{version_online_str}'): {e}")
        else:
            ctx.log.warn("fiddleitm: Could not retrieve online version for update check.")

    def _compile_regexes(self, rules_list):
        """
        Helper method to compile regex strings within the loaded rules.
        """
        for rule in rules_list:
            if "conditions" in rule and isinstance(rule["conditions"], list):
                # Iterate through each inner array (AND group)
                for and_group in rule["conditions"]:
                    if isinstance(and_group, list):
                        # Iterate through each single condition within the AND group
                        for condition in and_group:
                            if condition.get("type") == "regex":
                                value_str = condition.get("value")
                                if value_str:
                                    try:
                                        condition["value"] = re.compile(value_str)
                                    except re.error as e:
                                        rule_name = rule.get("rule_name", "Unnamed Rule")
                                        ctx.log.error(f"Fiddleitm: Invalid regex '{value_str}' in rule '{rule_name}': {e}")
                                        condition["value"] = None # Invalidate the regex
                                else:
                                    rule_name = rule.get("rule_name", "Unnamed Rule")
                                    ctx.log.warn(f"Fiddleitm: Empty regex value in rule '{rule_name}'. Skipping condition.")
                    else:
                        rule_name = rule.get("rule_name", "Unnamed Rule")
                        ctx.log.warn(f"Fiddleitm: Rule '{rule_name}' conditions not properly nested. Skipping compilation.")

    def load_rules(self):
        """Loads both main and local rules into memory."""
        self.parsed_rules = [] # Clear existing rules before loading

        # Conditionally load main rules based on internet connection status
        if self._has_internet_connection: # Use the status determined in __init__
            self.load_main_rules()
        else:
            ctx.log.info('Fiddleitm: Skipping main rules load (offline).')

        self.load_local_rules()
        ctx.log.info(f"Fiddleitm: Total rules loaded: {len(self.parsed_rules)}")

    def load_main_rules(self):
        """Downloads and loads main rules from a specified URL."""
        ctx.log.info(f"Fiddleitm: Loading main rules from {RULES_URL}...")
        session = requests.Session()
        session.trust_env = False # Ensure this is active for the session
        try:
            response = session.get(RULES_URL, timeout=10) # Uses the session
            response.raise_for_status()

            rules_data = json.loads(response.text)

            if not isinstance(rules_data, list):
                ctx.log.error("Fiddleitm: Main rules file is not a list/array of rules. Skipping.")
                return

            self._compile_regexes(rules_data) # Compile regexes in the loaded data
            self.parsed_rules.extend(rules_data) # Add them to the main list
            ctx.log.info(f"Fiddleitm: -> {len(rules_data)} main rules loaded successfully.")
        except requests.exceptions.RequestException as e:
            ctx.log.error(f"Fiddleitm: Failed to download main rules from {RULES_URL}: {e}. Ensure URL is correct and accessible.")
        except json.JSONDecodeError as e:
            ctx.log.error(f"Fiddleitm: Failed to parse main rules (invalid JSON format): {e}")
        except Exception as e:
            ctx.log.error(f"Fiddleitm: An unexpected error occurred loading main rules: {e}")


    def load_local_rules(self):
        """Loads rules from a local file (e.g., localrules.json)."""
        ctx.log.info(f"Fiddleitm: Loading local rules from {LOCAL_RULES_FILE}...")
        if os.path.isfile(LOCAL_RULES_FILE):
            try:
                with open(LOCAL_RULES_FILE, 'r', encoding='utf-8') as f:
                    rules_data = json.load(f)

                    if not isinstance(rules_data, list):
                        ctx.log.error(f"Fiddleitm: Local rules file is not a list/array of rules. Skipping.")
                        return

                    self._compile_regexes(rules_data) # Compile regexes in the loaded data
                    self.parsed_rules.extend(rules_data) # Add them to the main list
                    ctx.log.info(f"Fiddleitm: -> {len(rules_data)} local rules loaded successfully.")
            except FileNotFoundError:
                # This should ideally not happen due to os.path.isfile check, but good for robustness
                ctx.log.error(f"Fiddleitm: Local rules file '{LOCAL_RULES_FILE}' not found. This indicates a logic error.")
            except json.JSONDecodeError as e:
                ctx.log.error(f"Fiddleitm: Failed to parse local rules (invalid JSON format): {e}")
            except Exception as e:
                ctx.log.error(f"Fiddleitm: An unexpected error occurred loading local rules: {e}")
        else:
            ctx.log.info(f"Fiddleitm: No local rules file found at {LOCAL_RULES_FILE}. Skipping local rules load.")

    def _get_target_data(self, key: str, flow: http.HTTPFlow):
        """Helper to extract data from flow based on key."""
        # Categorize keys by whether they need request or response
        request_keys = {"full_url", "url_path", "url_host", "request_body", "host_ip"}
        response_keys = {"response_body", "response_body_sha256", "status_code", "response_body_size"}

        if key in request_keys or key.startswith("request_header_"):
            # These are always available once a request object exists
            pass
        elif key in response_keys or key.startswith("response_header_"):
            # These require a response to be present
            if not flow.response:
                return None # Data not available yet
        
        # Now, proceed with data extraction as before
        if key == "full_url":
            return flow.request.url
        elif key == "url_path":
            return flow.request.path
        elif key == "url_host":
            return flow.request.host
        elif key == "host_ip":
            return flow.server_conn.peername[0] if flow.server_conn and flow.server_conn.peername else "N/A"
        elif key == "response_body":
            if flow.response and flow.response.raw_content:
                try:
                    return flow.response.content.decode('utf-8', errors='ignore')
                except Exception as e:
                    ctx.log.warn(f"Failed to decode response_body for rule check: {e}")
                    return None
            return None
        elif key == "request_body":
            if flow.request and flow.request.raw_content:
                try:
                    return flow.request.content.decode('utf-8', errors='ignore')
                except Exception as e:
                    ctx.log.warn(f"Failed to decode request_body for rule check: {e}")
                    return None
            return None
        elif key == "response_body_sha256":
            if flow.response and flow.response.raw_content:
                return sha256(flow.response.raw_content).hexdigest()
            return None
        elif key.startswith("request_header_"):
            header_name = key.replace("request_header_", "")
            return flow.request.headers.get(header_name, "")
        elif key.startswith("response_header_"):
            header_name = key.replace("response_header_", "")
            return flow.response.headers.get(header_name, "")
        elif key == "status_code":
            return str(flow.response.status_code) if flow.response else None
        elif key == "response_body_size":
            if flow.response and flow.response.raw_content is not None:
                return len(flow.response.raw_content) # Returns size in bytes
            return 0 # Return 0 if no response or no content
        else:
            ctx.log.warn(f"Fiddleitm: Unknown condition key '{key}'.")
            return None

    def _evaluate_single_condition(self, condition, flow: http.HTTPFlow):
        """
        Evaluates a single condition against the HTTP flow data.
        Returns True if condition matches, False otherwise.
        """
        key = condition.get("key")
        value = condition.get("value")
        condition_type = condition.get("type")

        if value is None:
            ctx.log.debug(f"Condition value is None for key '{key}'. Skipping.")
            return False # Invalid condition

        target_data = self._get_target_data(key, flow)

        if target_data is None:
            # Data source for this key was not available in the flow at this hook stage.
            # E.g., trying to get response_body in a request hook.
            return False

        if condition_type == "string":
            # Direct substring check. Case-sensitive
            return value in target_data
        elif condition_type == "regex":
            # 'value' should already be a compiled regex object from _compile_regexes
            if isinstance(value, re.Pattern):
                return value.search(target_data) is not None
            else:
                ctx.log.error(f"Fiddleitm: Regex for key '{key}' was not compiled. Rule might be malformed.")
                return False
        elif condition_type == "numeric_equals":
            try:
                # Ensure both are numeric for comparison
                return float(target_data) == float(value) # Changed to '==' for equals
            except (ValueError, TypeError):
                ctx.log.warn(f"Fiddleitm: Invalid numeric comparison for key '{key}'.")
                return False
        elif condition_type == "numeric_greater_than":
            try:
                # Ensure both are numeric for comparison
                return float(target_data) > float(value)
            except (ValueError, TypeError):
                ctx.log.warn(f"Fiddleitm: Invalid numeric comparison for key '{key}'.")
                return False
        elif condition_type == "numeric_lesser_than":
            try:
                # Ensure both are numeric for comparison
                return float(target_data) < float(value) # Changed to '<' for lesser than
            except (ValueError, TypeError):
                ctx.log.warn(f"Fiddleitm: Invalid numeric comparison for key '{key}'.")
                return False
        else:
            ctx.log.warn(f"Fiddleitm: Unknown condition type '{condition_type}' for key '{key}'.")
            return False

    def check_rules(self, flow: http.HTTPFlow, phase: str):
        """
        Checks a given HTTP flow against all loaded rules,
        If a rule matches, a message is printed to the mitmproxy console.
        """
        # Only process if the flow hasn't been marked by a rule already
        if flow.comment: # Check if flow already has a comment (indicating it's been processed)
            return

        for rule in self.parsed_rules:
            rule_name = rule.get("rule_name", "Unnamed Rule")
            emoji_name = rule.get("emoji_name")
            reference_url = rule.get("reference")
            conditions_groups = rule.get("conditions", [])

            # Skip rules that don't match the current phase.
            # This prevents the function from attempting to evaluate
            # response-based rules in the request phase, and vice-versa.
            has_request_condition = any(
                c.get("key").startswith(("full_url", "url_path", "url_host", "request_body", "host_ip", "request_header_"))
                for and_group in conditions_groups
                for c in and_group
            )
            has_response_condition = any(
                c.get("key").startswith(("response_body", "response_body_sha256", "response_header_")) or c.get("key") == "status_code"
                for and_group in conditions_groups
                for c in and_group
            )

            if phase == 'request' and has_response_condition:
                continue
            if phase == 'response' and has_request_condition and not has_response_condition:
                continue

            rule_matched = False
            # Iterate through each 'OR' group
            for and_group in conditions_groups:
                if not isinstance(and_group, list):
                    ctx.log.warn(f"Fiddleitm: Rule '{rule_name}' has malformed condition group. Skipping.")
                    continue

                # Assume this AND group matches until a condition fails
                group_matches_all_conditions = True
                for condition in and_group:
                    # Evaluate each single condition within this AND group
                    if not self._evaluate_single_condition(condition, flow):
                        group_matches_all_conditions = False
                        break # If one condition in an AND group fails, the whole group fails

                if group_matches_all_conditions:
                    rule_matched = True
                    break # If any AND group matches, the whole rule matches (OR logic)

            if rule_matched:
                ctx.log.alert('\a') # Bell sound for attention
                # Construct the message including the reference URL if it exists
                msg = f"Fiddleitm: Matched rule '{rule_name}' for {flow.request.pretty_url}"
                if reference_url:
                    msg += f"\nref:{reference_url}"

                flow.comment = rule_name
                if emoji_name:
                    flow.marked = emoji_name
                    ctx.log.info(f"{msg}")
                else:
                    flow.marked = ":red_circle:"
                    ctx.log.info(msg)
                
                self._log_matched_rule(flow, rule_name)
                # IMPORTANT: Break after the first match to prevent multiple marks/logs for one flow
                break 

    def _log_matched_rule(self, flow: http.HTTPFlow, rule_name: str):
        """
        Logs details of a matched rule to rules.log if the log_events option is enabled.
        Opens the file, writes, and closes it for each entry to prevent locking.
        """
        if not self.log_events_enabled: # Use the instance variable updated by configure
            return # Don't log if the option is not enabled

        try:
            epochtime = str(int(time.time()))
            friendlytime = strftime("%Y-%m-%d %H:%M:%S", localtime())
            ipaddress = flow.server_conn.peername[0] if flow.server_conn and flow.server_conn.peername else "N/A"

            # Safely access response headers and other response-dependent data
            servername = "N/A"
            if flow.response and flow.response.headers:
                servername = flow.response.headers.get("Server", "N/A")
            
            hostname = flow.request.host
            referer = flow.request.headers.get("referer", "N/A")

            # Replace commas in potentially problematic fields to avoid breaking CSV format
            cleaned_servername = servername.replace(",", " ")
            cleaned_url = flow.request.url.replace(",", "_comma_")
            cleaned_referer = referer.replace(",", "_comma_")
            # Ensure flow.comment is treated as a string before replacing
            cleaned_comment = str(flow.comment).replace(",", "_comma_") if flow.comment else ""

            # --- Critical Change: Open, Write, and Close here ---
            with open("rules.log", "a", encoding="utf-8") as log_file:
                log_file.write(
                    f"{epochtime},{friendlytime},{ipaddress},{cleaned_servername},"
                    f"{hostname},{cleaned_url},{cleaned_referer},{cleaned_comment}\n"
                )
            # The 'with' statement automatically flushes and closes the file,
            # releasing the lock immediately after writing.
            ctx.log.debug(f"Logged event to rules.log for rule '{rule_name}'")
        except Exception as e:
            ctx.log.error(f"Fiddleitm: Failed to write to rules.log for rule '{rule_name}': {e}")
            
    def request(self, flow: http.HTTPFlow) -> None:
        """
        Mitmproxy event hook: Called when the proxy receives a request.
        Used to modify requests based on configured options and check request-based rules.
        """
        # Ensure the flow is an HTTP flow before proceeding
        if not isinstance(flow, http.HTTPFlow):
            return
        
        # Override user-agent if needed
        if self.custom_user_agent: # Use instance variable updated by configure
            flow.request.headers["user-agent"] = self.custom_user_agent

        # Override referer if needed
        if self.custom_referer: # Use instance variable updated by configure
            flow.request.headers["referer"] = self.custom_referer

        # Override accept-language if needed
        if self.custom_accept_language: # Use instance variable updated by configure
            flow.request.headers["accept-language"] = self.custom_accept_language

        # Drop images, videos and other large content (if option is enabled)
        if self.traffic_lite_enabled: # Use instance variable updated by configure
            if any(ext in flow.request.pretty_url.lower() for ext in DROPPED_EXTENSIONS):
                ctx.log.info(f"Traffic Lite: Killing flow for {flow.request.pretty_url}")
                flow.kill()
                return # No need to check rules if flow is killed

        # Call check_rules in the request hook for request-based rules
        self.check_rules(flow, phase='request')

    def response(self, flow: http.HTTPFlow) -> None:
        """
        Mitmproxy event hook: Called when the proxy receives a response.
        This is where we trigger our rule checking for response-based rules, with content-type filtering.
        """
        # Ensure the flow is an HTTP flow before proceeding
        if not isinstance(flow, http.HTTPFlow):
            return
        
        # Ensure there's a response and content before proceeding
        if not flow.response or not flow.response.content:
            return

        # If INCLUDED_CONTENT_TYPES is configured, only process flows matching those types.
        if INCLUDED_CONTENT_TYPES:
            content_type_full = flow.response.headers.get("Content-Type", "").lower()

            # Extract only the MIME type part (e.g., "application/javascript" from "application/javascript; charset=utf-8")
            content_type_base = content_type_full.split(';')[0].strip()

            if content_type_base not in INCLUDED_CONTENT_TYPES:
                return # Stop processing this flow

        # Call check_rules in the response hook.
        # The `check_rules` function has a safeguard (flow.comment)
        # to prevent re-processing if a rule already matched in the request hook.
        self.check_rules(flow, phase='response')

    @command.command("fiddleitm.runrules")
    def runrules(self, flows: Sequence[flow.Flow]) -> None:
        """
        Reloads rules and re-evaluates them against the currently selected flows.
        Usage: `:fiddleitm.runrules @tracked` (to run on all flows) or select flows
        """
        ctx.log.info("Fiddleitm: Reloading rules and re-running checks on selected flows...")
        # Call load_rules, which now clears and reloads both main and local rules
        self.load_rules()

        rechecked_flows = 0
        
        # First pass: check for request-based rules
        ctx.log.info("Fiddleitm: Running request-based rules...")
        for f in flows:
            if isinstance(f, http.HTTPFlow):
                # Clear previous marks and comments to allow a fresh evaluation
                f.comment = None
                f.marked = False
                # Call check_rules for the 'request' phase
                self.check_rules(f, phase='request')
                rechecked_flows += 1

        # Second pass: check for response-based rules
        ctx.log.info("Fiddleitm: Running response-based rules...")
        for f in flows:
            if  isinstance(f, http.HTTPFlow) and f.response and f.response.content:
                # If INCLUDED_CONTENT_TYPES is configured, only process flows matching those types.
                if INCLUDED_CONTENT_TYPES:
                    print(f"Checking {f.request.url}...")
                    content_type_full = f.response.headers.get("Content-Type", "").lower()

                    # Extract only the MIME type part (e.g., "application/javascript" from "application/javascript; charset=utf-8")
                    content_type_base = content_type_full.split(';')[0].strip()
                    print(content_type_base)

                    if content_type_base in INCLUDED_CONTENT_TYPES:                
                        print(f"Processing {f.request.url} with restricted content types")
                        # This second call is only for flows that were NOT matched in the first pass
                        self.check_rules(f, phase='response')
                    else:
                        print(f"Ignore this flow")
                
                else:
                    print(f"Processing {f.request.url}")
                    # This second call is only for flows that were NOT matched in the first pass
                    self.check_rules(f, phase='response') 

        ctx.log.info(f"Fiddleitm: Rechecked {rechecked_flows} HTTP flows.")
        # Trigger an update hook to refresh the mitmproxy UI (web and console)
        ctx.master.addons.trigger(hooks.UpdateHook(flows))

    """ This command clears comments for all flows"""
    @command.command("fiddleitm.clear")
    def clear(self, flows: Sequence[flow.Flow]) -> None:
        for f in flows:
            if isinstance(f, http.HTTPFlow):
                f.comment = ''
                f.marked = ''
        ctx.master.addons.trigger(hooks.UpdateHook(flows))
    
    @command.command("fiddleitm.save")
    def save_flows(self, flows: Sequence[flow.Flow], filename: str):
        """
        Saves the given flows to a file
        Usage: fiddleitm.save [flows] <filename>
        """
        if not filename:
            ctx.log.info("Usage: fiddleitm.save [flows] <filename>")
            ctx.log.info("Example: :fiddleitm.save @all my_session.mitm")
            ctx.log.info("Example: :fiddleitm.save my_selected_flows.mitm")
            return

        if not flows:
            ctx.log.info("Fiddleitm: No flows provided. Please select flows or use '@all'.")
            return

        try:
            # Use os.path.expanduser to resolve '~' in filenames
            with open(os.path.expanduser(filename), "wb") as f:
                writer = io.FlowWriter(f) 
                
                for flow_obj in flows:
                    writer.add(flow_obj)
            ctx.log.info(f"Fiddleitm: Successfully saved {len(flows)} flows to '{filename}'")
        except IOError as e:
            ctx.log.error(f"Fiddleitm: Could not write to file '{filename}': {e}")
        except Exception as e:
            ctx.log.error(f"Fiddleitm: An unexpected error occurred while saving flows: {e}")
    
    def done(self):
        """Mitmproxy event hook: Called when the addon is unloaded."""
        ctx.log.info("Fiddleitm addon unloaded.")

addons = [Fiddleitm()]