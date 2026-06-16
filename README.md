# ORFX

> Offensive Recon Framework — modular OSINT and reconnaissance framework with a Metasploit-style interactive shell.

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![Shell](https://img.shields.io/badge/Shell-Bash-4EAA25?style=flat-square&logo=gnu-bash&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Kali-557C94?style=flat-square&logo=kalilinux&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

---

## Overview

ORFX is a modular reconnaissance framework built around an **interactive shell interface** — load a module, configure options, run. The workflow mirrors Metasploit's `msfconsole`, making it familiar to pentesters while covering the full recon phase of an engagement.

Each module is self-contained and independently extensible. Results persist in session memory and can be exported as TXT, JSON, or HTML reports.

---

## Features

- **Interactive shell** — `use`, `set`, `run`, `back` workflow identical to Metasploit
- **5 built-in modules** — subdomain enumeration, port scanning, WHOIS, DNS recon, HTTP fingerprinting
- **Session management** — results persist across modules within a session, with scan history
- **Report generation** — export findings as TXT, JSON, or styled HTML
- **Concurrent scanning** — threaded execution in subdomain and port scan modules
- **HTTP security audit** — checks for missing security headers (CSP, HSTS, X-Frame-Options, etc.)
- **Cloud & WAF fingerprinting** — detects AWS, Azure, GCP, Cloudflare from HTTP headers
- **Technology detection** — identifies server software, frameworks, and CMS from response headers
- **Zero required API keys** — all modules work out of the box

---

## Modules

| Module | Category | Description |
|---|---|---|
| `subdomain/enum` | Enumeration | Passive + active subdomain discovery via concurrent DNS brute-force |
| `recon/port_scan` | Scanning | TCP port scanner with service detection and banner grabbing |
| `recon/whois` | OSINT | WHOIS lookup with registrar and domain metadata |
| `recon/dns` | DNS | Full DNS record enumeration (A, MX, NS, TXT, CNAME, SOA, AAAA) |
| `recon/http_probe` | Web Recon | HTTP fingerprinting: headers, technology detection, security header audit |

---

## Requirements

| Dependency | Purpose | Install |
|---|---|---|
| `python 3.10+` | Runtime | `apt install python3` |
| `whois` (optional) | WHOIS module | `apt install whois` |
| `dig` (optional) | DNS module | `apt install dnsutils` |
| `python-whois` (optional) | WHOIS fallback | `pip install python-whois` |

```bash
sudo apt install python3 whois dnsutils
```

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/NeiveZ/ORFX.git
cd ORFX
```

### 2. Run the installer

```bash
chmod +x orfx.sh
./orfx.sh --install
```

### 3. Launch

```bash
./orfx.sh
```

---

## Usage

ORFX opens an interactive shell. All interaction happens through commands typed at the prompt.

```
orfx > use <module>
orfx > set <OPTION> <value>
orfx > run
```

### Core commands

```
use <module>            Load a module
set <OPTION> <value>    Set a module option
run                     Execute the loaded module
options                 Show current module options
info                    Show module description and options
back                    Unload current module

show modules            List all available modules
show results            View results from the current session
show sessions           Session statistics and scan history

report [txt|json|html]  Export session results to a file
history                 Show scan history
clear                   Clear the screen
exit                    Quit ORFX
```

---

## Examples

**Subdomain enumeration:**
```
orfx > use subdomain/enum
orfx (subdomain/enum) > set TARGET example.com
orfx (subdomain/enum) > set THREADS 100
orfx (subdomain/enum) > run
```

**Port scan with custom range:**
```
orfx > use recon/port_scan
orfx (recon/port_scan) > set TARGET 192.168.1.1
orfx (recon/port_scan) > set PORTS 22,80,443,8080,3306
orfx (recon/port_scan) > run
```

**DNS enumeration:**
```
orfx > use recon/dns
orfx (recon/dns) > set TARGET example.com
orfx (recon/dns) > set TYPES A,MX,NS,TXT
orfx (recon/dns) > run
```

**HTTP security audit:**
```
orfx > use recon/http_probe
orfx (recon/http_probe) > set TARGET https://example.com
orfx (recon/http_probe) > run
```

**Export session report:**
```
orfx > report html engagement_report
orfx > report json raw_data
```

---

## Output

```
orfx > use recon/port_scan
[+] Module loaded: recon/port_scan

orfx (recon/port_scan) > set TARGET 192.168.1.1
[+] TARGET => 192.168.1.1

orfx (recon/port_scan) > run

── Port Scan → 192.168.1.1 (192.168.1.1) ──────────────

[>] 22     SSH            OPEN
[>] 80     HTTP           OPEN   │ Apache/2.4.57
[>] 443    HTTPS          OPEN
[>] 3306   MySQL          OPEN

[+] Scan complete. 4 open port(s) on 192.168.1.1
```

---

## Adding Custom Modules

Create a file in `modules/` extending `BaseModule`:

```python
from modules.base import BaseModule
from utils.colors import print_status

class MyModule(BaseModule):
    NAME        = "custom/mymodule"
    DESCRIPTION = "Does something useful"

    def _define_options(self):
        self._add_option("TARGET", "", True, "Target host")

    def run(self):
        target = self.get_option("TARGET")
        print_status(f"Running against {target}", "run")
        # your logic here
        return {"target": target}
```

Register it in `orfx.py`:

```python
from modules.mymodule import MyModule
self.modules["custom/mymodule"] = MyModule
```

---

## Repository Structure

```
ORFX/
├── orfx.py               # Interactive shell entry point
├── orfx.sh               # Bash launcher and installer
├── modules/
│   ├── base.py           # Abstract base class for all modules
│   ├── subdomain_enum.py
│   ├── port_scanner.py
│   ├── whois_lookup.py
│   ├── dns_recon.py
│   ├── http_probe.py
│   └── report_gen.py
├── utils/
│   ├── colors.py         # Terminal color and UI system
│   └── session.py        # Session state manager
├── wordlists/            # Drop custom wordlists here
└── reports/              # Auto-saved scan reports
```

---

## Legal

For use only on systems you own or have explicit written authorization to test.
Unauthorized use against third-party systems is illegal.
