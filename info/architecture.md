# DNSChef — Technical Reference

**Version**: 0.5  
**Purpose**: A configurable DNS proxy for penetration testing and malware analysis.  
Intercepts DNS queries and either spoofs responses or transparently proxies them to upstream nameservers.

---

## Architecture

### Overview

```
                          ┌────────────────────────────────────┐
                          │           DNSChef Server           │
                          │                                    │
  DNS client ──────────►  │  ThreadedUDPServer / ThreadedTCP   │
  (UDP/TCP)               │         │                          │
                          │         ▼                          │
                          │  UDPHandler / TCPHandler           │
                          │         │                          │
                          │         ▼                          │
                          │    DNSHandler.parse()              │
                          │         │                          │
                          │    ┌────┴────┐                     │
                          │    │         │                     │
                          │  Spoof    Proxy                    │
                          │    │         │                     │
                          │    ▼         ▼                     │
                          │  Fake RR   proxyrequest() ──────►  Upstream NS
                          │    │         │                     │
                          └────┼─────────┼─────────────────────┘
                               ▼         ▼
                          Response to client
```

### Key Classes

| Class | Base Classes | Purpose |
|---|---|---|
| `DNSHandler` | — (mixin) | DNS query parsing, fake response construction, proxying |
| `UDPHandler` | `DNSHandler`, `BaseRequestHandler` | Handles incoming UDP DNS requests |
| `TCPHandler` | `DNSHandler`, `BaseRequestHandler` | Handles incoming TCP DNS requests (length-prefix protocol) |
| `ThreadedUDPServer` | `ThreadingMixIn`, `UDPServer` | Multi-threaded UDP server |
| `ThreadedTCPServer` | `ThreadingMixIn`, `TCPServer` | Multi-threaded TCP server |

### Logging Classes

| Class | Purpose |
|---|---|
| `DNSChefFormatter` | Formats output to console/file with level-specific styling (INFO, ERROR, DEBUG) |
| `DNSChefJSONFormatter` | Structured logging in NDJSON format for machine processing |

---

## Internal Rule Store (`nametodns`)

The central data structure is a **dict of dicts** `nametodns[qtype][domain] → value`:

```
nametodns = {
    "A":     {"example.com": "6.6.6.6", "*.*.*.*.*.*.*.*.*.*": "1.2.3.4"},
    "AAAA":  {"example.com": "2001:db8::1"},
    "MX":    {},
    "CNAME": {},
    ...      # keys — all types from RDMAP (dnslib)
}
```

- **Top-level key** — DNS record type (string from `RDMAP.keys()`)
- **Nested dict key** — domain pattern (lowercase)
- **Value** — string with the fake response, or `False` (for `--truedomains` — "proxy honestly")

---

## Request Processing

### Request Lifecycle

1. **Receive** — `UDPHandler.handle()` or `TCPHandler.handle()` reads data from the client
2. **Parse** — `DNSHandler.parse()` decodes the DNS packet via `dnslib.DNSRecord.parse()`
3. **Validate** — checks that the opcode is QUERY (not RESPONSE/STATUS/etc.); non-QUERY messages are logged and ignored
4. **Lookup** — for each record type (A, AAAA, MX, …) a match is searched in `nametodns`
5. **Build response** — one of three outcomes:
   - **Spoofing**: match found → fake response generated via `_build_rr()`
   - **ANY request**: type `*` → all available fake records are returned
   - **Proxy**: no match → request forwarded to upstream nameserver

### DNS Response Flags for Spoofed Replies

Fake responses are built with `DNSHeader(qr=1, aa=1, ra=1)`:

| Flag | Value | Reason |
|---|---|---|
| `qr=1` | Response | Marks the packet as a response |
| `aa=1` | Authoritative Answer | Server claims authority over the domain |
| `ra=1` | Recursion Available | Advertises recursion support |

### TCP Protocol

DNS over TCP prepends a 2-byte length-prefix before each message (RFC 1035 §4.2.2):

```
[2 bytes: length N][N bytes: DNS message]
```

#### Reading Fragmented TCP Packets (`_recvall`)

Unlike UDP, TCP is a stream protocol. A single `recv()` call may return only part of the data, especially for large messages or under network latency. The method `_recvall(sock, length)` guarantees reading **exactly `length` bytes**:

```python
def _recvall(sock, length):
    buf = bytearray()
    while len(buf) < length:
        chunk = sock.recv(length - len(buf))
        if not chunk:        # connection closed
            break
        buf.extend(chunk)
    return bytes(buf)
```

**Logic:**
1. An empty buffer `buf` is created
2. `recv()` is called in a loop requesting the remaining number of bytes (`length - len(buf)`)
3. Each received fragment (`chunk`) is appended to the buffer
4. The loop exits when the buffer reaches the required length or the connection is closed (`chunk` is empty)

**Example of fragmented reading:**
```
Need to read: 512 bytes

recv(512) → 200 bytes   buf = [200/512]
recv(312) → 312 bytes   buf = [512/512] ✓ done
```

#### TCP DNS Message Reading Flow in `TCPHandler.handle()`

```
TCP stream from client:
┌──────┬────────────────────────────────────┐
│ 0x02 │ 0x00 │  ... DNS packet (512 bytes) ...  │
│  00  │       │                                  │
└──┬───┴───────┴──────────────────────────────────┘
   │
   ▼
Step 1: _recvall(sock, 2)  →  read 2-byte length-prefix
        Result: b'\x02\x00' → length = 512

Step 2: Check len(raw_len) == 2; if not — return (incomplete prefix)

Step 3: _recvall(sock, 512) →  read exactly 512 bytes of DNS message
        (if TCP fragmented it — the loop reads until complete)

Step 4: Check len(data) == msg_len; if not — return (connection dropped)

Step 5: self.parse(data) → process the DNS query

Step 6: Send response:
        pack("!H", len(response)) + response
        ├── 2-byte prefix ──┤├── DNS response ──┤
```

The same `_recvall()` is used in `proxyrequest()` when TCP-proxying to an upstream nameserver.

### Proxying (`proxyrequest`)

- Upstream nameserver format: `IP`, `IP#PORT`, or `IP#PORT#PROTOCOL`
- When multiple servers are configured — **random selection** (`random.choice`)
- Supports both UDP and TCP upstream
- Timeout: **3 seconds**
- TCP upstream: full read via `_recvall()` with length-prefix

---

## Domain Matching Mechanism

### `findnametodns()` Algorithm

Matching is performed **component-by-component, right to left** (reverse-component matching):

```
Query:   mail.google.com  → ['com', 'google', 'mail']
Rule:    *.google.com     → ['com', 'google', '*']
Result:  match (wildcard '*' matches 'mail')
```

**Details:**
- `*` in a component is a wildcard (matches any value at that label level)
- Global wildcard `*.*.*.*.*.*.*.*.*.*` matches any domain
- The dict is sorted by value so that the global wildcard is matched **last**
- Case-insensitive comparison (`qname.lower()`)
- For `--truedomains`: a value of `False` means "proxy honestly"

### Rule Priority

1. Rules from file (`--file`) — loaded first, highest priority
2. Rules from CLI arguments (`--fakeip`, `--fakedomains`, etc.)
3. Global wildcard — matched last

---

## Supported Record Types

### Custom Parsing

| Type | Value Format | Example |
|---|---|---|
| `AAAA` | IPv6 address | `2001:db8::1` |
| `SOA` | `mname rname serial refresh retry expire minimum` | `ns1.example.com admin.example.com 2024010100 3600 900 604800 86400` |
| `NAPTR` | `order preference flags service regexp replacement` | `100 10 u sip+E2U !^.*$!sip:info@example.com! .` |
| `SRV` | `priority weight port target` | `0 5 5060 sipserver.example.com` |
| `DNSKEY` | `flags protocol algorithm base64key` | `256 3 8 AwEAAa...` |
| `RRSIG` | `covered algo labels ttl exp inc tag name sig` | full DNSSEC signature structure |

### Generic Handler

Types `A`, `CNAME`, `MX`, `NS`, `TXT`, and others are handled via `RDMAP[qtype](value)` from `dnslib`.

---

## Configuration

### Three Ways to Define Spoofing Rules

**1. CLI arguments:**
```bash
dnschef.py --fakeip 192.168.1.100 --fakedomains example.com,test.com
```

**2. Configuration file (INI format):**
```ini
[A]
example.com=192.168.1.100
*.test.com=10.0.0.1

[AAAA]
example.com=2001:db8::1

[MX]
example.com=mail.evil.com
```
Loaded via `--file dnschef.ini`. File rules take priority over CLI arguments.

**3. Domain filtering (mutually exclusive):**
- `--fakedomains` — spoof **only** the listed domains, proxy everything else
- `--truedomains` — proxy **only** the listed domains, spoof everything else

### Operating Modes

| Parameter | Description |
|---|---|
| `-t` / `--tcp` | TCP mode instead of UDP (default) |
| `-6` / `--ipv6` | IPv6 mode (automatically switches interface to `::1` and nameserver to Google IPv6) |
| `-p PORT` | Non-standard port (default 53, requires root) |
| `-i ADDR` | Interface to listen on |
| `--nameservers` | Upstream DNS servers (format: `IP#PORT#PROTOCOL`, comma-separated) |

### Logging

| Parameter | Format | Purpose |
|---|---|---|
| `--logfile FILE` | Plain text | Human-readable log of all events |
| `--logfile-json FILE` | NDJSON | Structured events for automated processing |

**JSON event types (`action`):**

| Action | Description |
|---|---|
| `start` | Server started (interface, port, protocol, version) |
| `stop` | Server stopped |
| `query` | Incoming DNS query (client, qname, qtype) |
| `spoof` | Response spoofed (client, qname, qtype, value) |
| `proxy` | Request proxied (client, qname, qtype, nameserver, answers) |
| `ignored` | Non-QUERY request ignored (client, reason) |
| `error` | Processing error (client, message) |

---

## Server Lifecycle (`start_cooking`)

```
start_cooking()
    │
    ├─ Configure logging (file, JSON)
    ├─ Create ThreadedUDPServer or ThreadedTCPServer
    ├─ server.serve_forever()  ← blocks the main thread
    │
    └─ KeyboardInterrupt (Ctrl+C)
        ├─ server.shutdown()
        ├─ Log: "DNSChef is shutting down."
        └─ sys.exit()
```

- `socketserver.ThreadingMixIn` — each incoming request is handled in a separate thread
- `serve_forever()` runs in the main thread, ensuring correct `Ctrl+C` handling

---

## Dependencies

| Package | Purpose |
|---|---|
| `dnslib` | DNS packet parsing and construction |

All other modules are from the Python 3 standard library.

---

## `dnschefstat.py` Utility

A companion script for analyzing JSON logs (`--logfile-json`). Parses NDJSON and reports:
- Total number of queries
- List of clients with query counts
- Statistics by record type
- Queried domains grouped by client
