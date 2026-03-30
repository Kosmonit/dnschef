#!/usr/bin/env python3

#
# DNSChef is a highly configurable DNS Proxy for Penetration Testers 
# and Malware Analysts. Please visit http://thesprawl.org/projects/dnschef/
# for the latest version and documentation. Please forward all issues and
# concerns to iphelix [at] thesprawl.org.

DNSCHEF_VERSION = "0.5"

# Copyright (C) 2019 Peter Kacherginsky, Marcello Salvati
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met: 
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer. 
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
# 3. Neither the name of the copyright holder nor the names of its contributors
#    may be used to endorse or promote products derived from this software without 
#    specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from argparse import ArgumentParser
from configparser import ConfigParser

from dnslib import *
from ipaddress import ip_address

import logging
import threading
import random
import operator
import socketserver
import socket
import sys
import os
import time
import string
import base64
import json
from datetime import datetime, timezone
from struct import pack


class DNSChefFormatter(logging.Formatter):

    FORMATS = {
        logging.ERROR: "(%(asctime)s) [!] %(msg)s",
        logging.INFO: "(%(asctime)s) [*] %(msg)s",
        logging.WARNING: "WARNING: %(msg)s",
        logging.DEBUG: "DBG: %(module)s: %(lineno)d: %(msg)s",
        "DEFAULT": "%(asctime)s - %(msg)s"
    }

    def format(self, record):
        format_orig = self._style._fmt

        self._style._fmt = self.FORMATS.get(record.levelno, self.FORMATS['DEFAULT'])
        result = logging.Formatter.format(self, record)

        self._style._fmt = format_orig

        return result

class DNSChefJSONFormatter(logging.Formatter):
    """Formatter for writing structured events to an NDJSON file.

    Regular log.info/error calls are written as
    {"timestamp":..., "level":..., "message":...}.
    Calls with extra={"_json": {...}} enrich the record with structured fields.
    """

    def format(self, record):
        entry = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc)
                         .strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "level": record.levelname,
        }
        json_extra = getattr(record, "_json", None)
        if json_extra:
            entry.update(json_extra)
        else:
            entry["message"] = record.getMessage()
        return json.dumps(entry, ensure_ascii=False)


log = logging.getLogger("dnschef")
log.setLevel(logging.DEBUG)

log_ch = logging.StreamHandler()
log_ch.setLevel(logging.INFO)
log_ch.setFormatter(DNSChefFormatter(datefmt="%H:%M:%S"))
log.addHandler(log_ch)

# DNSHandler Mixin. The class contains generic functions to parse DNS requests and
# calculate an appropriate response based on user parameters.
class DNSHandler():

    @staticmethod
    def _build_rr(qname, qtype, fake_record):
        """Build a single RR answer from qtype and fake_record string."""
        if qtype == "AAAA":
            ipv6_hex_tuple = list(map(int, ip_address(fake_record).packed))
            return RR(qname, getattr(QTYPE, qtype), rdata=RDMAP[qtype](ipv6_hex_tuple))

        if qtype == "SOA":
            mname, rname, t1, t2, t3, t4, t5 = fake_record.split(" ")
            times = tuple(int(t) for t in [t1, t2, t3, t4, t5])
            if mname[-1] == ".": mname = mname[:-1]
            if rname[-1] == ".": rname = rname[:-1]
            return RR(qname, getattr(QTYPE, qtype), rdata=RDMAP[qtype](mname, rname, times))

        if qtype == "NAPTR":
            parts = fake_record.split(" ")
            order, preference = int(parts[0]), int(parts[1])
            flags, service, regexp = parts[2].encode(), parts[3].encode(), parts[4].encode()
            replacement = parts[5].encode()
            if replacement and replacement[-1:] == b".": replacement = replacement[:-1]
            return RR(qname, getattr(QTYPE, qtype),
                       rdata=RDMAP[qtype](order, preference, flags, service, regexp, DNSLabel(replacement)))

        if qtype == "SRV":
            priority, weight, port, target = fake_record.split(" ")
            priority, weight, port = int(priority), int(weight), int(port)
            if target[-1] == ".": target = target[:-1]
            return RR(qname, getattr(QTYPE, qtype), rdata=RDMAP[qtype](priority, weight, port, target))

        if qtype == "DNSKEY":
            flags, protocol, algorithm, key = fake_record.split(" ")
            flags, protocol, algorithm = int(flags), int(protocol), int(algorithm)
            key = base64.b64decode(("".join(key)).encode('ascii'))
            return RR(qname, getattr(QTYPE, qtype), rdata=RDMAP[qtype](flags, protocol, algorithm, key))

        if qtype == "RRSIG":
            covered, algorithm, labels, orig_ttl, sig_exp, sig_inc, key_tag, name, sig = fake_record.split(" ")
            covered = getattr(QTYPE, covered)
            algorithm, labels, orig_ttl = int(algorithm), int(labels), int(orig_ttl)
            sig_exp = int(time.mktime(time.strptime(sig_exp + 'GMT', "%Y%m%d%H%M%S%Z")))
            sig_inc = int(time.mktime(time.strptime(sig_inc + 'GMT', "%Y%m%d%H%M%S%Z")))
            key_tag = int(key_tag)
            if name[-1] == '.': name = name[:-1]
            sig = base64.b64decode(("".join(sig)).encode('ascii'))
            return RR(qname, getattr(QTYPE, qtype),
                       rdata=RDMAP[qtype](covered, algorithm, labels, orig_ttl, sig_exp, sig_inc, key_tag, name, sig))

        # Generic types (A, CNAME, MX, NS, TXT, etc.)
        if fake_record[-1] == ".": fake_record = fake_record[:-1]
        return RR(qname, getattr(QTYPE, qtype), rdata=RDMAP[qtype](fake_record))

    def parse(self, data):
        response = None

        try:
            d = DNSRecord.parse(data)

        except Exception as e:
            log.error(f"{self.client_address[0]}: ERROR: invalid DNS request: {e}",
                      extra={"_json": {"action": "error", "client": self.client_address[0],
                                       "message": f"invalid DNS request: {e}"}})

        else:
            # Only Process DNS Queries
            if QR[d.header.qr] != "QUERY":
                log.info(f"{self.client_address[0]}: received non-QUERY opcode ({QR[d.header.qr]}), ignoring",
                         extra={"_json": {"action": "ignored", "client": self.client_address[0],
                                          "reason": f"non-QUERY opcode: {QR[d.header.qr]}"}})

            elif QR[d.header.qr] == "QUERY":

                # NOTE: Do not lowercase qname here, because we want to see
                #       any case request weirdness in the logs.
                qname = str(d.q.qname)

                # Chop off the last period
                if qname[-1] == '.': qname = qname[:-1]

                qtype = QTYPE[d.q.qtype]

                log.info(f"Query: '{qname}' -> qtype: {qtype} ({d.q.qtype})",
                         extra={"_json": {"action": "query", "client": self.client_address[0],
                                          "qname": qname, "qtype": qtype}})

                # Find all matching fake DNS records for the query name or get False
                fake_records = dict()
                for record in self.server.nametodns:
                    fake_records[record] = self.findnametodns(qname, self.server.nametodns[record])

                # Check if there is a fake record for the current request qtype
                if qtype in fake_records and fake_records[qtype]:

                    fake_record = fake_records[qtype]

                    response = DNSRecord(DNSHeader(id=d.header.id, bitmap=d.header.bitmap, qr=1, aa=1, ra=1), q=d.q)

                    log.info(f"{self.client_address[0]}: cooking the response of type '{qtype}' for {qname} to {fake_record}",
                             extra={"_json": {"action": "spoof", "client": self.client_address[0],
                                              "qname": qname, "qtype": qtype, "value": fake_record}})

                    response.add_answer(self._build_rr(qname, qtype, fake_record))
                    response = response.pack()

                elif qtype == "*" and not None in list(fake_records.values()):
                    log.info(f"{self.client_address[0]}: cooking the response of type 'ANY' for {qname} with all known fake records",
                             extra={"_json": {"action": "spoof", "client": self.client_address[0],
                                              "qname": qname, "qtype": "*",
                                              "value": {k: v for k, v in fake_records.items() if v}}})

                    response = DNSRecord(DNSHeader(id=d.header.id, bitmap=d.header.bitmap, qr=1, aa=1, ra=1), q=d.q)

                    for rec_qtype, fake_record in fake_records.items():
                        if fake_record:
                            response.add_answer(self._build_rr(qname, rec_qtype, fake_record))

                    response = response.pack()

                # Proxy the request
                else:
                    log.info(f"{self.client_address[0]}: proxying the response of type '{qtype}' for {qname}")

                    nameserver_tuple = random.choice(self.server.nameservers).split('#')
                    nameserver_host = nameserver_tuple[0]
                    response = self.proxyrequest(data, *nameserver_tuple)

                    if response:
                        try:
                            dns_response = DNSRecord.parse(response)
                            answers = []
                            for rr in dns_response.rr:
                                rdata_str = str(rr.rdata)
                                answers.append(rdata_str)
                                log.info(f"{self.client_address[0]}: response of type '{QTYPE[rr.rtype]}' for {rr.rname}: {rr.rdata} ")
                            log.info("", extra={"_json": {"action": "proxy",
                                                          "client": self.client_address[0],
                                                          "qname": qname, "qtype": qtype,
                                                          "nameserver": nameserver_host,
                                                          "answers": answers}})
                        except Exception as e:
                            log.error(f"Failed parse response: {e}",
                                      extra={"_json": {"action": "error",
                                                       "client": self.client_address[0],
                                                       "message": f"Failed parse response: {e}"}})                    

        return response


    # Find appropriate ip address to use for a queried name. The function can
    def findnametodns(self,qname,nametodns):

        # Make qname case insensitive
        qname = qname.lower()

        # Split and reverse qname into components for matching.
        qnamelist = qname.split('.')
        qnamelist.reverse()

        # HACK: It is important to search the nametodns dictionary before iterating it so that
        # global matching ['*.*.*.*.*.*.*.*.*.*'] will match last. Use sorting for that.
        for domain,host in sorted(iter(nametodns.items()), key=operator.itemgetter(1)):

            # NOTE: It is assumed that domain name was already lowercased
            #       when it was loaded through --file, --fakedomains or --truedomains
            #       don't want to waste time lowercasing domains on every request.

            # Split and reverse domain into components for matching
            domain = domain.split('.')
            domain.reverse()

            # Compare domains in reverse.
            for a, b in zip(qnamelist, domain):
                if a != b and b != "*":
                    break
            else:
                # Could be a real IP or False if we are doing reverse matching with 'truedomains'
                return host
        else:
            return False

    @staticmethod
    def _recvall(sock, length):
        """Read exactly *length* bytes from a TCP socket."""
        buf = bytearray()
        while len(buf) < length:
            chunk = sock.recv(length - len(buf))
            if not chunk:
                break
            buf.extend(chunk)
        return bytes(buf)

    def proxyrequest(self, request, host, port="53", protocol="udp"):
        reply = None
        try:
            if protocol not in ("udp", "tcp"):
                log.error(f"Unsupported protocol: {protocol}")
                return None

            sock_family = socket.AF_INET6 if self.server.ipv6 else socket.AF_INET
            sock_type = socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM

            with socket.socket(sock_family, sock_type) as sock:
                sock.settimeout(3.0)

                if protocol == "udp":
                    sock.sendto(request, (host, int(port)))
                    reply = sock.recv(65535)
                else:
                    sock.connect((host, int(port)))
                    sock.sendall(pack("!H", len(request)) + request)
                    raw_len = self._recvall(sock, 2)
                    if len(raw_len) == 2:
                        msg_len = int.from_bytes(raw_len, "big")
                        reply = self._recvall(sock, msg_len)

        except Exception as e:
            log.error(f"[!] Could not proxy request: {e}")
        else:
            return reply

# UDP DNS Handler for incoming requests
class UDPHandler(DNSHandler, socketserver.BaseRequestHandler):

    def handle(self):
        (data, socket) = self.request
        response = self.parse(data)

        if response:
            socket.sendto(response, self.client_address)

# TCP DNS Handler for incoming requests
class TCPHandler(DNSHandler, socketserver.BaseRequestHandler):

    def handle(self):
        # Read the 2-byte length prefix used in TCP DNS protocol
        raw_len = self._recvall(self.request, 2)
        if len(raw_len) < 2:
            return

        msg_len = int.from_bytes(raw_len, "big")
        data = self._recvall(self.request, msg_len)
        if len(data) < msg_len:
            return

        response = self.parse(data)

        if response:
            # Add the 2-byte length prefix for TCP DNS response
            self.request.sendall(pack("!H", len(response)) + response)

class ThreadedUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):

    # Override SocketServer.UDPServer to add extra parameters
    def __init__(self, server_address, RequestHandlerClass, nametodns, nameservers, ipv6, log):
        self.nametodns  = nametodns
        self.nameservers = nameservers
        self.ipv6        = ipv6
        self.address_family = socket.AF_INET6 if self.ipv6 else socket.AF_INET
        self.log = log

        socketserver.UDPServer.__init__(self, server_address, RequestHandlerClass)

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):

    # Override default value
    allow_reuse_address = True

    # Override SocketServer.TCPServer to add extra parameters
    def __init__(self, server_address, RequestHandlerClass, nametodns, nameservers, ipv6, log):
        self.nametodns   = nametodns
        self.nameservers = nameservers
        self.ipv6        = ipv6
        self.address_family = socket.AF_INET6 if self.ipv6 else socket.AF_INET
        self.log = log

        socketserver.TCPServer.__init__(self, server_address, RequestHandlerClass)

# Initialize and start the DNS Server
def start_cooking(interface, nametodns, nameservers, tcp=False, ipv6=False, port="53", logfile=None, logfile_json=None):
    try:

        if logfile:
            fh = logging.FileHandler(logfile, encoding='UTF-8')
            fh.setLevel(logging.INFO)
            fh.setFormatter(DNSChefFormatter(datefmt="%d/%b/%Y:%H:%M:%S %z"))
            log.addHandler(fh)

            log.info("DNSChef is active.")

        if logfile_json:
            jh = logging.FileHandler(logfile_json, encoding='UTF-8')
            jh.setLevel(logging.INFO)
            jh.setFormatter(DNSChefJSONFormatter())
            log.addHandler(jh)

        if tcp:
            log.info("DNSChef is running in TCP mode")
            server = ThreadedTCPServer((interface, int(port)), TCPHandler, nametodns, nameservers, ipv6, log)
        else:
            server = ThreadedUDPServer((interface, int(port)), UDPHandler, nametodns, nameservers, ipv6, log)

        log.info(f"DNSChef started on {interface}:{port}",
                 extra={"_json": {"action": "start", "interface": interface,
                                  "port": int(port), "protocol": "tcp" if tcp else "udp",
                                  "version": DNSCHEF_VERSION}})

        # Serve requests directly in the main thread
        server.serve_forever()

    except (KeyboardInterrupt, SystemExit):
        server.shutdown()
        log.info("DNSChef is shutting down.",
                 extra={"_json": {"action": "stop"}})
        sys.exit()

    except Exception as e:
        log.error(f"Failed to start the server: {e}",
                  extra={"_json": {"action": "error", "message": f"Failed to start the server: {e}"}})


if __name__ == "__main__":
    header  = r"          _                _          __  " + "\n"
    header += r"         | | version %s  | |        / _|  " % DNSCHEF_VERSION + "\n" #% DNSCHEF_VERSION
    header += r"       __| |_ __  ___  ___| |__   ___| |_ " + "\n"
    header += r"      / _` | '_ \/ __|/ __| '_ \ / _ \  _|" + "\n"
    header += r"     | (_| | | | \__ \ (__| | | |  __/ |  " + "\n"
    header += r"      \__,_|_| |_|___/\___|_| |_|\___|_|  " + "\n"
    header += r"                   iphelix@thesprawl.org  " + "\n"
    header += r"                   @Kosmonit              " + "\n"

    # Parse command line arguments
    parser = ArgumentParser(usage = "dnschef.py [options]:\n" + header, description="DNSChef is a highly configurable DNS Proxy for Penetration Testers and Malware Analysts. It is capable of fine configuration of which DNS replies to modify or to simply proxy with real responses. In order to take advantage of the tool you must either manually configure or poison DNS server entry to point to DNSChef. The tool requires root privileges to run on privileged ports." )

    fakegroup = parser.add_argument_group("Fake DNS records:")
    fakegroup.add_argument('--fakeip', metavar="192.0.2.1", help='IP address to use for matching DNS queries. If you use this parameter without specifying domain names, then all \'A\' queries will be spoofed. Consider using --file argument if you need to define more than one IP address.')
    fakegroup.add_argument('--fakeipv6', metavar="2001:db8::1", help='IPv6 address to use for matching DNS queries. If you use this parameter without specifying domain names, then all \'AAAA\' queries will be spoofed. Consider using --file argument if you need to define more than one IPv6 address.')
    fakegroup.add_argument('--fakemail', metavar="mail.fake.com", help='MX name to use for matching DNS queries. If you use this parameter without specifying domain names, then all \'MX\' queries will be spoofed. Consider using --file argument if you need to define more than one MX record.')
    fakegroup.add_argument('--fakealias', metavar="www.fake.com", help='CNAME name to use for matching DNS queries. If you use this parameter without specifying domain names, then all \'CNAME\' queries will be spoofed. Consider using --file argument if you need to define more than one CNAME record.')
    fakegroup.add_argument('--fakens', metavar="ns.fake.com", help='NS name to use for matching DNS queries. If you use this parameter without specifying domain names, then all \'NS\' queries will be spoofed. Consider using --file argument if you need to define more than one NS record.')
    fakegroup.add_argument('--file', help="Specify a file containing a list of DOMAIN=IP pairs (one pair per line) used for DNS responses. For example: google.com=1.1.1.1 will force all queries to 'google.com' to be resolved to '1.1.1.1'. IPv6 addresses will be automatically detected. You can be even more specific by combining --file with other arguments. However, data obtained from the file will take precedence over others.")

    mexclusivegroup = parser.add_mutually_exclusive_group()
    mexclusivegroup.add_argument('--fakedomains', metavar="thesprawl.org,google.com", help='A comma separated list of domain names which will be resolved to FAKE values specified in the the above parameters. All other domain names will be resolved to their true values.')
    mexclusivegroup.add_argument('--truedomains', metavar="thesprawl.org,google.com", help='A comma separated list of domain names which will be resolved to their TRUE values. All other domain names will be resolved to fake values specified in the above parameters.')

    rungroup = parser.add_argument_group("Optional runtime parameters.")
    rungroup.add_argument("--logfile", metavar="FILE", help="Specify a log file to record all activity")
    rungroup.add_argument("--logfile-json", metavar="FILE", help="Specify a JSON log file to record structured events (NDJSON format, one event per line)")
    rungroup.add_argument("--nameservers", metavar="8.8.8.8#53 or 4.2.2.1#53#tcp or 2001:4860:4860::8888", default='8.8.8.8', help='A comma separated list of alternative DNS servers to use with proxied requests. Nameservers can have either IP or IP#PORT format. A randomly selected server from the list will be used for proxy requests when provided with multiple servers. By default, the tool uses Google\'s public DNS server 8.8.8.8 when running in IPv4 mode and 2001:4860:4860::8888 when running in IPv6 mode.')
    rungroup.add_argument("-i","--interface", metavar="127.0.0.1 or ::1", default="127.0.0.1", help='Define an interface to use for the DNS listener. By default, the tool uses 127.0.0.1 for IPv4 mode and ::1 for IPv6 mode.')
    rungroup.add_argument("-t","--tcp", action="store_true", default=False, help="Use TCP DNS proxy instead of the default UDP.")
    rungroup.add_argument("-6","--ipv6", action="store_true", default=False, help="Run in IPv6 mode.")
    rungroup.add_argument("-p","--port", metavar="53", default="53", help='Port number to listen for DNS requests.')
    rungroup.add_argument("-q", "--quiet", action="store_false", dest="verbose", default=True, help="Don't show headers.")

    options = parser.parse_args()

    #for row in QTYPE:
    #    print(row)
    #print(f"\nQTYPE = {QTYPE}\n")

    # Print program header
    if options.verbose:
        print(header)

    # Main storage of domain filters
    # NOTE: RDMAP is a dictionary map of qtype strings to handling classes
    nametodns = dict()
    for qtype in list(RDMAP.keys()):
        nametodns[qtype] = dict()

    if not (options.fakeip or options.fakeipv6) and (options.fakedomains or options.truedomains):
        log.error("You have forgotten to specify which IP to use for fake responses")
        sys.exit(0)

    # Notify user about alternative listening port
    if options.port != "53":
        log.info(f"Listening on an alternative port {options.port}")

    # Adjust defaults for IPv6
    if options.ipv6:
        log.info("Using IPv6 mode.")
        if options.interface == "127.0.0.1":
            options.interface = "::1"

        if options.nameservers == "8.8.8.8":
            options.nameservers = "2001:4860:4860::8888"

    log.info(f"DNSChef started on interface: {options.interface}")

    # Use alternative DNS servers
    if options.nameservers:
        nameservers = options.nameservers.split(',')
        log.info(f"Using the following nameservers: {', '.join(nameservers)}")

    # External file definitions
    if options.file:
        config = ConfigParser()
        config.read(options.file)
        for section in config.sections():

            if section in nametodns:
                for domain, record in config.items(section):

                    # Make domain case insensitive
                    domain = domain.lower()

                    nametodns[section][domain] = record
                    log.info(f"Cooking {section} replies for domain {domain} with '{record}'")
            else:
                log.warning(f"DNS Record '{section}' is not supported. Ignoring section contents.")

    # DNS Record and Domain Name definitions
    # NOTE: '*.*.*.*.*.*.*.*.*.*' domain is used to match all possible queries.
    if options.fakeip or options.fakeipv6 or options.fakemail or options.fakealias or options.fakens:
        fakeip     = options.fakeip
        fakeipv6   = options.fakeipv6
        fakemail   = options.fakemail
        fakealias  = options.fakealias
        fakens     = options.fakens

        if options.fakedomains:
            for domain in options.fakedomains.split(','):

                # Make domain case insensitive
                domain = domain.lower()
                domain = domain.strip()

                if fakeip:
                    nametodns["A"][domain] = fakeip
                    log.info(f"Cooking A replies to point to {options.fakeip} matching: {domain}")

                if fakeipv6:
                    nametodns["AAAA"][domain] = fakeipv6
                    log.info(f"Cooking AAAA replies to point to {options.fakeipv6} matching: {domain}")

                if fakemail:
                    nametodns["MX"][domain] = fakemail
                    log.info(f"Cooking MX replies to point to {options.fakemail} matching: {domain}")

                if fakealias:
                    nametodns["CNAME"][domain] = fakealias
                    log.info(f"Cooking CNAME replies to point to {options.fakealias} matching: {domain}")

                if fakens:
                    nametodns["NS"][domain] = fakens
                    log.info(f"Cooking NS replies to point to {options.fakens} matching: {domain}")

        elif options.truedomains:
            for domain in options.truedomains.split(','):

                # Make domain case insensitive
                domain = domain.lower()
                domain = domain.strip()

                if fakeip:
                    nametodns["A"][domain] = False
                    log.info(f"Cooking A replies to point to {options.fakeip} not matching: {domain}")
                    nametodns["A"]['*.*.*.*.*.*.*.*.*.*'] = fakeip

                if fakeipv6:
                    nametodns["AAAA"][domain] = False
                    log.info(f"Cooking AAAA replies to point to {options.fakeipv6} not matching: {domain}")
                    nametodns["AAAA"]['*.*.*.*.*.*.*.*.*.*'] = fakeipv6

                if fakemail:
                    nametodns["MX"][domain] = False
                    log.info(f"Cooking MX replies to point to {options.fakemail} not matching: {domain}")
                    nametodns["MX"]['*.*.*.*.*.*.*.*.*.*'] = fakemail

                if fakealias:
                    nametodns["CNAME"][domain] = False
                    log.info(f"Cooking CNAME replies to point to {options.fakealias} not matching: {domain}")
                    nametodns["CNAME"]['*.*.*.*.*.*.*.*.*.*'] = fakealias

                if fakens:
                    nametodns["NS"][domain] = False
                    log.info(f"Cooking NS replies to point to {options.fakens} not matching: {domain}")
                    nametodns["NS"]['*.*.*.*.*.*.*.*.*.*'] = fakens

        else:

            # NOTE: '*.*.*.*.*.*.*.*.*.*' domain is a special ANY domain
            #       which is compatible with the wildflag algorithm above.

            if fakeip:
                nametodns["A"]['*.*.*.*.*.*.*.*.*.*'] = fakeip
                log.info(f"Cooking all A replies to point to {fakeip}")

            if fakeipv6:
                nametodns["AAAA"]['*.*.*.*.*.*.*.*.*.*'] = fakeipv6
                log.info(f"Cooking all AAAA replies to point to {fakeipv6}")

            if fakemail:
                nametodns["MX"]['*.*.*.*.*.*.*.*.*.*'] = fakemail
                log.info(f"Cooking all MX replies to point to {fakemail}")

            if fakealias:
                nametodns["CNAME"]['*.*.*.*.*.*.*.*.*.*'] = fakealias
                log.info(f"Cooking all CNAME replies to point to {fakealias}")

            if fakens:
                nametodns["NS"]['*.*.*.*.*.*.*.*.*.*'] = fakens
                log.info(f"Cooking all NS replies to point to {fakens}")

    # Proxy all DNS requests
    if not options.fakeip and not options.fakeipv6 and not options.fakemail and not options.fakealias and not options.fakens and not options.file:
        log.info("No parameters were specified. Running in full proxy mode")

    # Launch DNSChef
    start_cooking(interface=options.interface, nametodns=nametodns, nameservers=nameservers, tcp=options.tcp, ipv6=options.ipv6, port=options.port, logfile=options.logfile, logfile_json=options.logfile_json)
