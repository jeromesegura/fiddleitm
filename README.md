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

Currently, fiddleitm inspects the following:

* remote server IP address
* remote host URI
* response content

A list of rules ([regexes.txt](https://github.com/malwareinfosec/fiddleitm/blob/main/rules.txt)) is used to parse incoming flows and identify any match with existing rules.

You can use your own rules as well. Simply create a file called ``local_rules.txt`` in the same path as fiddleitm.py.

Accepted format: ``{Type} TAB {Rule name} TAB {Condition}``

where Type can be: ``IP/URI/SourceCode``
where Condition can be: ``$string="" or $regex=""``

Flows that match a rule are marked and commented in real time and a system sound will play.

*Advanced syntax:*

Match **all** of the conditions

``SourceCode TAB {Rule name} TAB {Condition 1} *AND* {Condition 2}``

Match **any** of the conditions

``SourceCode TAB {Rule name} TAB {Condition 1} *OR* {Condition 2}``

![image](https://github.com/malwareinfosec/fiddleitm/assets/25351665/2e6294e9-6282-4ab8-8e05-53a42720b4d6)

![image](https://github.com/malwareinfosec/fiddleitm/assets/25351665/ff8e17a0-5288-467f-a71c-4f5c5c49bde1)

## Anti-VM detection and evasion

Threat actors can use JavaScript code to fingerprint visitors and detect if they are running a virtual machine (VMware, VirtualBox). In some instances, this works by collecting information such as video drivers, renders, etc. and then sending that information backed to the server via a POST request.

fiddleitm intercepts such attempts and replaces certain keywords commonly used to detect virtual machines with random words.

![image](https://github.com/malwareinfosec/fiddleitm/assets/25351665/c7bca2df-d93d-4880-9a4f-803c74dae36e)

