This document describes **`fiddleitm`**, a mitmproxy addon designed to identify malicious web traffic. It provides detailed information on its features, installation, usage, and configuration options.

![image](https://github.com/user-attachments/assets/e34d4836-88aa-413b-b5b9-748ff2f763c2)

---

## Features

`fiddleitm` offers the following functionalities:

* **Malicious Traffic Detection**: Inspects HTTP flows against a set of predefined and local rules to identify suspicious patterns.
* **Rule Management**: Supports loading rules from a remote GitHub repository and a local JSON file (`localrules.json`).
* **Real-time Alerts**: Notifies the user in the mitmproxy console when a rule matches a flow.
* **Event Logging**: Option to log details of matched rules to a file named **`rules.log`** for later analysis.
* **Custom Headers**: Allows modification of **`User-Agent`**, **`Referer`**, and **`Accept-Language`** headers for all requests.
* **Traffic Filtering**: Includes a "traffic lite" mode to drop requests for common image and video file extensions, reducing noise.
* **Self-Update**: Checks for and offers to install updates for `fiddleitm` directly from GitHub.
* **On-demand Rule Re-evaluation**: Provides a mitmproxy command to reload rules and re-evaluate them against selected flows.

---

## Installation

To use `fiddleitm`, you need to have `mitmproxy` installed.

1.  **Save the Addon**: Save the provided code as a Python file (e.g., `fiddleitm.py`) in a location accessible to `mitmproxy`.
2.  **Install Dependencies**: Ensure you have the `requests` library installed:
    ```bash
    pip install requests
    ```

---

## Usage

Run `mitmweb`with the `-s` flag followed by the path to the `fiddleitm.py` file:

* **Open fiddleitm**:
    ```bash
    mitmweb -s fiddleitm.py
    ```
* **Open fiddleitm and autosave flows**:
    ```bash
    mitmweb -s .\fiddleitm.py --save-stream-file traffic.mitm
    ```

* **Open saved flows in viewer mode (capture disabled)**:
    ```bash
    mitmweb -s .\fiddleitm.py --no-server --rfile traffic.mitm
    ```
* **Open fiddleitm and replay saved flows**:
    ```bash
    mitmweb --scripts .\fiddleitm.py --server-replay [saved_flows] --server-replay-reuse --set connection_strategy=lazy
    ```

---

## Configuration Options

You can customize `fiddleitm`'s behavior using `mitmproxy`'s `--set` option:

* **`--set custom_user_agent="YourCustomUserAgent"`**:
    Overrides the default User-Agent header for all requests.
* **`--set custom_referer="http://your.custom.referer"`**:
    Overrides the default Referer header for all requests.
* **`--set custom_accept_language="en-US,en;q=0.9"`**:
    Overrides the default Accept-Language header for all requests.
* **`--set log_events=true`**:
    Enables logging of matched rule events to a file named `rules.log` in the current directory.
* **`--set traffic_lite=true`**:
    Activates "traffic lite" mode, which automatically drops requests for common image and video file extensions (e.g., `.jpg`, `.mp4`, `.gif`).
* **`--mode upstream:http://proxyhost:port --upstream-auth username:password`**:
    Configures an upstream proxy for `mitmproxy` itself, allowing `fiddleitm` to operate through another proxy.

---

## Rule Management

`fiddleitm` uses a JSON-based rule system. Rules are loaded from two sources:

1.  **Remote Rules**: Automatically downloaded from `https://raw.githubusercontent.com/jeromesegura/fiddleitm/main/rules.json` if an internet connection is available.
2.  **Local Rules**: Loaded from **`localrules.json`** in the same directory as `fiddleitm.py`. This file allows you to add your own custom rules without modifying the addon's source code.

### Rule Structure

Each rule in the JSON file is an object with the following structure:

```json
[
  {
    "rule_name": "Rule example",
    "emoji_name": ":sparkles:",
    "reference": "https://github.com/",
    "conditions": [
      [
        { "key": "full_url", "type": "string", "value": "example.com" },
        { "key": "response_body", "type": "regex", "value": "dom[a-z]in" },
        { "key": "response_body_size", "type": "numeric_greater_than", "value": 100 }
      ],
      [
        { "key": "full_url", "type": "string", "value": "mitmproxy.org" },
        { "key": "response_body", "type": "string", "value": "free and open source" }
      ]
    ]
  }
]
```
<img width="916" alt="image" src="https://github.com/user-attachments/assets/e17d0ae7-60af-43b7-ae88-54447926a996" />

* **`rule_name`**: A descriptive name for the rule.
* **`emoji_name`**: (Optional) An emoji to display in mitmproxy's flow list when the rule matches (e.g., `:skull:`).
* **`reference`**: (Optional) A URL providing more context or information about the detected threat.
* **`conditions`**: A list of condition groups.
    * **Outer List (OR Logic)**: Each inner list represents an "AND" group of conditions. If *any* of these inner "AND" groups evaluate to true, the entire rule matches.
    * **Inner List (AND Logic)**: All conditions within a single inner list must evaluate to true for that group to match.

### Condition Types

* **`key`**: Specifies the part of the HTTP flow to inspect:
    * `full_url`: The complete URL of the request.
    * `url_path`: The path component of the URL.
    * `url_host`: The hostname of the URL.
    * `host_ip`: The IP address of the server.
    * `response_body`: The decoded content of the HTTP response body.
    * `request_body`: The decoded content of the HTTP request body.
    * `response_body_sha256`: SHA256 hash of the response body.
    * `request_header_HEADERNAME`: Any request header (e.g., `request_header_user-agent`).
    * `response_header_HEADERNAME`: Any response header (e.g., `response_header_content-type`).
    * `status_code`: The HTTP response status code (as a string).
    * `response_body_size`: The size of the response body in bytes.
* **`type`**: The type of comparison to perform:
    * **`string`**: Checks if the `value` is present as a substring within the key's data (case-sensitive).
    * **`regex`**: Checks if the `value` (a Python regular expression string) matches any part of the key's data.
    * **`numeric_equals`**: Checks if the key's data (expected to be numeric) is equal to the specified value.
    * **`numeric_greater_than`**: Checks if the key's data (expected to be numeric) is greater than the specified value.
    * **`numeric_lesser_than`**: Checks if the key's data (expected to be numeric) is lesser than the specified value.

## Commands

To run commands, go to Options and check Display Command Bar.

* **`:fiddleitm.runrules @all`**:
    Reloads all rules (both main and local) and re-evaluates them against all currentl HTTP flows. This is useful after modifying `localrules.json` to immediately see the effect without restarting mitmproxy.

* **`:fiddleitm.clear @all`**:
    Clears all comments and emojis.
