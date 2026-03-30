```text
      _                _          __ 
     | | version 0.5  | |        / _|
   __| |_ __  ___  ___| |__   ___| |_ 
  / _` | '_ \/ __|/ __| '_ \ / _ \  _|
 | (_| | | | \__ \ (__| | | |  __/ |  
  \__,_|_| |_|___/\___|_| |_|\___|_|
```

## Documentation

## Fork notice

This repository is a maintained fork of the original DNSChef project.

- Fork version: 0.5
- Fork date: 2026-03-27

This README is actively maintained for the fork and kept current.  
See `CHANGELOG` for fork-specific changes and release history.

## Contributors

- @Kosmonit

---

## Project overview

DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example, a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet. 

There are several DNS Proxies out there. Most will simply point all DNS queries a single IP address or implement only rudimentary filtering. DNSChef was developed as part of a penetration test where there was a need for a more configurable system. As a result, DNSChef is cross-platform application capable of forging responses based on inclusive and exclusive domain lists, supporting multiple DNS record types, matching domains with wildcards, proxying true responses for nonmatching domains, defining external configuration files, IPv6 and many other features. You can find detailed explanation of each of the features and suggested uses below.

The use of DNS Proxy is recommended in situations where it is not possible to force an application to use some other proxy server directly. For example, some mobile applications completely ignore OS HTTP Proxy settings. In these cases, the use of a DNS proxy server such as DNSChef will allow you to trick that application into forwarding connections to the desired destination.

## Setting up a DNS Proxy

Before you can start using DNSChef, you must configure your machine to use a DNS nameserver with the tool running on it. You have several options based on the operating system you are going to use:

- **Linux**: Edit `/etc/resolv.conf` to include a line on the very top with your traffic analysis host (e.g add `nameserver 127.0.0.1` if you are running locally). Alternatively, you can add a DNS server address using tools such as Network Manager. Inside the Network Manager open IPv4 Settings, select *Automatic (DHCP) addresses only* or *Manual* from the *Method* drop down box and edit *DNS Servers* text box to include an IP address with DNSChef running.

- **Windows**: Select *Network Connections* from the *Control Panel*. Next select one of the connections (e.g. "Local Area Connection"), right-click on it and select properties. From within a newly appearing dialog box, select *Internet Protocol (TCP/IP)* and click on properties. At last select *Use the following DNS server addresses* radio button and enter the IP address with DNSChef running. For example, if running locally enter 127.0.0.1.

- **OS X**: Open *System Preferences* and click on the *Network* icon. Select the active interface and fill in the *DNS Server* field. If you are using Airport then you will have to click on *Advanced...* button and edit DNS servers from there. Alternatively, you can edit `/etc/resolv.conf` and add a fake nameserver to the very top there (e.g `nameserver 127.0.0.1`).

- **iOS**: Open *Settings* and select *General*. Next select on *Wi-Fi* and click on a blue arrow to the right of an active Access Point from the list. Edit DNS entry to point to the host with DNSChef running. Make sure you have disabled Cellular interface (if available).

- **Android**: Open *Settings* and select *Wireless and network*. Click on *Wi-Fi settings* and select *Advanced* after pressing the *Options* button on the phone. Enable *Use static IP* checkbox and configure a custom DNS server.

If you do not have the ability to modify device's DNS settings manually, then you still have several options involving techniques such as [ARP Spoofing](http://en.wikipedia.org/wiki/ARP_spoofing), [Rogue DHCP](http://www.yersinia.net/doc.htm) and other creative methods.

At last you need to configure a fake service where DNSChef will point all of the requests. For example, if you are trying to intercept web traffic, you must bring up either a separate web server running on port 80 or set up a web proxy (e.g. Burp) to intercept traffic. DNSChef will point queries to your proxy/server host with properly configured services.

## Running DNSChef

DNSChef is a cross-platform application developed in Python which should run on most platforms which have a Python interpreter. You can use the supplied *dnschef.exe* executable to run it on Windows hosts without installing a Python interpreter. This guide will concentrate on Unix environments; however, all of the examples below were tested to work on Windows as well.

Let's get a taste of DNSChef with its most basic monitoring functionality. Execute the following command as root (required to start a server on port 53):

```bash
./dnschef.py
```

```text
          _                _          __  
         | | version 0.5  | |        / _| 
       __| |_ __  ___  ___| |__   ___| |_ 
      / _` | '_ \/ __|/ __| '_ \ / _ \  _|
     | (_| | | | \__ \ (__| | | |  __/ |  
      \__,_|_| |_|___/\___|_| |_|\___|_|  
                   iphelix@thesprawl.org  

[*] DNSChef started on interface: 127.0.0.1 
[*] Using the following nameservers: 8.8.8.8
[*] No parameters were specified. Running in full proxy mode
```

Without any parameters, DNSChef will run in full proxy mode. This means that all requests will simply be forwarded to an upstream DNS server (8.8.8.8 by default) and returned back to the quering host. For example, let's query an "A" record for a domain and observe results:

```bash
host -t A thesprawl.org
```

DNSChef will print the following log line showing time, source IP address, type of record requested and most importantly which name was queried:

```text
[23:54:03] 127.0.0.1: proxying the response of type 'A' for thesprawl.org
```

This mode is useful for simple application monitoring where you need to figure out which domains it uses for its communications.

DNSChef has full support for IPv6 which can be activated using `-6` or `--ipv6` flags. It works exactly as IPv4 mode with the exception that default listening interface is switched to `::1` and default DNS server is switched to `2001:4860:4860::8888`. Here is a sample output:

```bash
./dnschef.py -6
```

```text
[*] Using IPv6 mode.
[*] DNSChef started on interface: ::1
[*] Using the following nameservers: 2001:4860:4860::8888
[*] No parameters were specified. Running in full proxy mode
[00:35:44] ::1: proxying the response of type 'A' for thesprawl.org
[00:35:44] ::1: proxying the response of type 'AAAA' for thesprawl.org
[00:35:44] ::1: proxying the response of type 'MX' for thesprawl.org
```

NOTE: By default, DNSChef creates a UDP listener. You can use TCP instead with the `--tcp` argument discussed later.

### Intercept all responses

Now, that you know how to start DNSChef let's configure it to fake all replies to point to 127.0.0.1 using the `--fakeip` parameter:

```bash
./dnschef.py --fakeip 127.0.0.1 -q
```

DNSChef supports multiple record types:

```text
+--------+--------------+-----------+--------------------------+
| Record |  Description |Argument   | Example                  |
+--------+--------------+-----------+--------------------------+
|  A     | IPv4 address |--fakeip   | --fakeip 192.0.2.1       |
|  AAAA  | IPv6 address |--fakeipv6 | --fakeipv6 2001:db8::1   |
|  MX    | Mail server  |--fakemail | --fakemail mail.fake.com |
|  CNAME | CNAME record |--fakealias| --fakealias www.fake.com |
|  NS    | Name server  |--fakens   | --fakens ns.fake.com     |
+--------+--------------+-----------+--------------------------+
```

NOTE: For usability not all DNS record types are exposed on the command line. Additional records such as PTR, TXT, SOA, etc. can be specified using the `--file` flag and an appropriate record header. See the [external definitions file](#external-definitions-file) section below for details.

### Filtering domains

Using the above example, consider you only want to intercept requests for *thesprawl.org* and leave queries to all other domains such as *webfaction.com* without modification. You can use the `--fakedomains` parameter.

### Reverse filtering

In another situation you may need to fake responses for all requests except a defined list of domains. You can accomplish this task using the `--truedomains` parameter.

## External definitions file

There may be situations where defining a single fake DNS record for all matching domains may not be sufficient. You can use an external file with a collection of `DOMAIN=RECORD` pairs defining exactly where you want the request to go.

For example, let create the following definitions file and call it `dnschef.template.ini`:

```ini
[A]
*.google.com=192.0.2.1
thesprawl.org=192.0.2.2
*.wordpress.*=192.0.2.3
```

Then run:

```bash
./dnschef.py --file dnschef.template.ini -q
```

You can specify section headers for other supported DNS record types including the ones not explicitly exposed on the command line: `[A]`, `[AAAA]`, `[MX]`, `[NS]`, `[CNAME]`, `[PTR]`, `[NAPTR]` and `[SOA]`. See sample `dnschef.template.ini` file for additional examples.

## Other configurations

For security reasons, DNSChef listens on a local 127.0.0.1 (or ::1 for IPv6) interface by default. You can make DNSChef listen on another interface using the `--interface` parameter.

DNS protocol can be used over UDP (default) or TCP. DNSChef implements a TCP mode which can be activated with the `--tcp` flag.

## JSON logging and statistics

This fork includes structured event logging and a companion statistics tool.

Use `--logfile-json <FILE>` to write DNSChef events in NDJSON format (one JSON object per line). The output can then be processed by `dnschefstat.py` to generate a human-readable summary report.

Example workflow:

1) Run DNSChef with NDJSON logging enabled:

```bash
./dnschef.py --logfile-json dnslog.json -q
```

2) Build a statistics report from the generated log:

```bash
./dnschefstat.py -i dnslog.json -o dnslog_stats.txt
```

Example report output:

```text
============================================================
================ DNSChef Statistics Report =================
============================================================

Total Queries: 91

Clients:
  - 192.168.200.3: 91 queries

Query Types:
  - A: 39
  - HTTPS: 24
  - AAAA: 23
  - PTR: 5

Query Types by Client:
  [Client: 192.168.200.3]
    - A: 39
    - HTTPS: 24
    - AAAA: 23
    - PTR: 5

Unique DNS Names and Resolutions (by Client):

  [Client: 192.168.200.3]
    - accounts.google.com -> 173.194.221.84
    - android.clients.google.com -> 142.250.74.14, android.l.google.com.
    - detectportal.firefox.com -> 34.107.221.82, detectportal.prod.mozaws.net.
    - google.com -> 216.58.201.238
    - mozilla.org -> 35.190.14.201
    - registry.npmjs.org -> 104.16.0.34, 104.16.1.34, ...
    - www.google.com -> 142.251.150.119, 142.251.151.119, ...
    - www.reddit.com -> 151.101.1.140, reddit.map.fastly.net.

============================================================
```

## Internal architecture

Here is some information on the internals in case you need to adapt the tool for your needs. DNSChef is built on top of the SocketServer module and uses threading to help process multiple requests simultaneously. The tool is designed to listen on TCP or UDP ports (default is port 53) for incoming requests and forward those requests when necessary to a real DNS server over UDP.

The excellent [dnslib library](https://bitbucket.org/paulc/dnslib/wiki/Home) is used to dissect and reassemble DNS packets. It is particularly useful when generating response packets based on queries.

DNSChef is capable of modifing queries for records of type "A", "AAAA", "MX", "CNAME", "NS", "TXT", "PTR", "NAPTR", "SOA", "ANY". It is very easy to expand or modify behavior for any record. Simply add another **if qtype == "RECORD TYPE")** entry and tell it what to reply with.

Enjoy the tool and forward all requests and comments to iphelix [at] thesprawl.org.

Happy hacking!  
 -Peter

