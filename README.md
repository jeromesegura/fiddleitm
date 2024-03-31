# fiddleitm v.0.1

This is an addon for [**mitmproxy**](https://github.com/mitmproxy/mitmproxy) based on [EKFiddle](https://github.com/malwareinfosec/EKFiddle/) (Fiddler extension)

It is used to inspect web traffic (flows) captured by mitmproxy
and look for malicious indicators from on a list of rules.

**Usage:**

To launch the command line interface:

`mitmproxy --scripts fiddleitm.py`

To launch the web interface:

`mitmweb --scripts fiddleitm.py`

# Features

## Malicious traffic detection based on rules

Currently, **fiddleitm** inspects the following:

* remote host name IP address
* remote host IP address
* remote host full URL
* response body

Predefined [rules](https://github.com/malwareinfosec/fiddleitm/blob/main/rules.txt) are loaded from this GitHub repository.

You can add your own rules to a file called ``local_rules.txt`` placed in the same directory as ``fiddleitm.py``.

**Syntax for rules:**

``rule_name = "rule name"; "condition 1"; "condition 2"; "condition n"``

**List of conditions:**

* ``host_name = "string"`` or ``host_name = /regex/``

* ``host_ip = "string"`` or ``host_ip = /regex/``

* ``full_url = "string"`` or ``full_url = /regex/``

* ``response_body = "string"`` or ``response_body = /regex/``

**Example**

``rule_name = "My first rule"; full_url = /[a-z]{5}\.js/; response_body = "DevTools"; response_body = /function[0-9]{2}/``

![image](https://github.com/malwareinfosec/fiddleitm/assets/25351665/2e6294e9-6282-4ab8-8e05-53a42720b4d6)

![image](https://github.com/malwareinfosec/fiddleitm/assets/25351665/ff8e17a0-5288-467f-a71c-4f5c5c49bde1)

## Anti-VM detection and evasion

Threat actors can use JavaScript code to fingerprint visitors and detect if they are running a virtual machine (VMware, VirtualBox). In some instances, this works by collecting information such as video drivers, renders, etc. and then sending that information backed to the server via a POST request.

fiddleitm intercepts such attempts and replaces certain keywords commonly used to detect virtual machines with random words.

![image](https://github.com/malwareinfosec/fiddleitm/assets/25351665/c7bca2df-d93d-4880-9a4f-803c74dae36e)

