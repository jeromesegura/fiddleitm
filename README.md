# fiddleitm v.0.2.2

This is an addon for [**mitmproxy**](https://github.com/mitmproxy/mitmproxy) that inspects flows and identifies malicious web traffic.

![Interface](interface.png)

If you'd like the flows to be highlighted (in addition to the comments and emojis), simply type ``~marked`` in the filter section:

![image](https://github.com/malwareinfosec/fiddleitm/assets/25351665/5a97e452-db7b-4444-82eb-2fa486895521)

**Usage:**

To launch the mitmproxy interactive proxy:

`mitmproxy -s fiddleitm.py`

To launch the web interface:

`mitmweb -s fiddleitm.py`

To launch the command-line version of mitmproxy (useful for capturing a lot of traffic):

`mitmdump -s fiddleitm.py`

Options:

* override default user-agent: ``--set custom_user_agent=""``

* override default referer: ``--set custom_referer=""``

* overrride default accept-language: ``--set custom_accept_language=""``

* log events for rules that match flows (writes to *rules.log*): ``--set log_events=true``

* add upstream proxy: ``--mode upstream:http://proxyhost:port --upstream-auth username:password``

# Features

## Malicious traffic detection based on rules

Currently, **fiddleitm** inspects the following:

* remote host name
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

**Optional:**
* ``emoji_name``
  (Displays an emoji to mark the flow. Please note that the `emoji_name` must be placed at the end of your rule. List of emojis: https://api.github.com/emojis)

**Example:**

``rule_name = "My first rule"; full_url = /[a-z]{5}\.js/; response_body = "DevTools"; emoji_name = ":grapes:"``

## Automatic updater

Since v.0.2, if a new version of fiddleitm is available, you will get prompted to install it whenever you run the script:

![image](https://github.com/user-attachments/assets/e4394475-d9e8-4d5e-98a2-ee4cc5dafd57)

The updater also displays the latest version of mitmproxy.

## Search within the body content of each flow

This feature is not currently supported in mitmweb, but fiddleitm provides a way to search using a regex via a command. You first need to enable the command line in the UI, by going to Options -> Display Command Bar.

![image](https://github.com/malwareinfosec/fiddleitm/assets/25351665/ece9bc20-a3db-45ac-a0c1-07b299338c4b)

Then type: ```fiddleitm.search @all regex here```

![image](https://github.com/malwareinfosec/fiddleitm/assets/25351665/fd80ae85-0d11-4126-aba7-da037f715106)

You can replace @all by @shown @focus @marked @unmarked @hidden

The search results will be printed in the CLI as well as marked in the UI:

![image](https://github.com/malwareinfosec/fiddleitm/assets/25351665/293d6fc1-afe3-4727-aaef-26657fc17892)

## Print (copy to clipboard) flow URLs that have been detected by a rule

This command allows you to print the flow URLs that matched your rules. See above on how to enter commands.

```fiddleitm.printurls @all```

## Run rules manually

This command executes rules (both ```rules.txt``` and ```localrules.txt```) on the selected traffic. This is useful if you are testing a new rule in your ```localrules.txt```.

```fiddleitm.runrules @all```

## Updates rules manually

This command lets you reload both ```rules.txt``` and ```localrules.txt``` without the need to restart fiddleitm:

```fiddleitm.updaterules```

## Connect-the-dots

This command helps you retrace each step that lead to a particular flow (requires mitmproxy v10.4.0):

```fiddleitm.connect @all [flow #]```

![image](https://github.com/user-attachments/assets/4124b61a-e11e-4de5-999c-4b10cfff4dfb)

## Clear comments

This command clears all comments from flow:

```fiddleitm.clear @all```

## Anti-VM detection and evasion

Threat actors can use JavaScript code to fingerprint visitors and detect if they are running a virtual machine (VMware, VirtualBox). In some instances, this works by collecting information such as video drivers, renders, etc. and then sending that information backed to the server via a POST request.

fiddleitm intercepts such attempts and replaces certain keywords commonly used to detect virtual machines with random words.

![image](https://github.com/jeromesegura/fiddleitm/assets/162072386/3dab8c57-2c16-4485-ab37-f1a9acdb92aa)

