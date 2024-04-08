# fiddleitm v.0.1

This is an addon for [**mitmproxy**](https://github.com/mitmproxy/mitmproxy) that inspects flows and identifies malicious web traffic.

**Usage:**

To launch the mitmproxy interactive proxy:

`mitmproxy -s fiddleitm.py`

To launch the web interface:

`mitmweb -s fiddleitm.py`

To launch the command-line version of mitmproxy (useful for capturing a lot of traffic):

`mitmdump -s fiddleitm.py`

Options:

* modify default user-agent with your own (reads first line from *useragent.txt*) ``--set customuseragent=true``

* log events for rules that match flows (writes to *rules.log*) ``--set logevents=true``

* add upstream proxy ``--mode upstream:http://proxyhost:port --upstream-auth username:password``

# Features

## Malicious traffic detection based on rules

Currently, **fiddleitm** inspects the following:

* remote host name IP address
* remote host IP address
* remote host full URL
* response body

Predefined [rules](https://github.com/jeromesegura/fiddleitm/blob/main/rules.txt) are loaded from this GitHub repository.

You can add your own rules to a file called ``localrules.txt`` placed in the same directory as ``fiddleitm.py``.

**Syntax for rules:**

``rule_name = "rule name"; condition 1 = "string" ; condition 2 = /regex/; condition n = ...``

**List of conditions:**

* ``host_name``

* ``host_ip``

* ``full_url``

* ``response_body``

**Example:**

``rule_name = "My first rule"; full_url = /[a-z]{5}\.js/; response_body = "DevTools"; response_body = /function[0-9]{2}/``

![image](https://github.com/jeromesegura/fiddleitm/assets/162072386/a147ff98-91c8-47e4-8022-6ce58522a93d)

![image](https://github.com/jeromesegura/fiddleitm/assets/162072386/0383966b-0c94-4ff5-9836-38088e4be038)

## Anti-VM detection and evasion

Threat actors can use JavaScript code to fingerprint visitors and detect if they are running a virtual machine (VMware, VirtualBox). In some instances, this works by collecting information such as video drivers, renders, etc. and then sending that information backed to the server via a POST request.

fiddleitm intercepts such attempts and replaces certain keywords commonly used to detect virtual machines with random words.

![image](https://github.com/jeromesegura/fiddleitm/assets/162072386/3dab8c57-2c16-4485-ab37-f1a9acdb92aa)
