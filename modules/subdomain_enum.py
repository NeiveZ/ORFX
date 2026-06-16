#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
modules/subdomain_enum.py — Subdomain enumeration via DNS brute-force + passive sources.
"""

import socket
import concurrent.futures
import os
from modules.base import BaseModule
from utils.colors import Colors, print_status, loading_bar, print_section


# Built-in wordlist (expanded at runtime if wordlists/subdomains.txt exists)
DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
    "app", "portal", "vpn", "remote", "blog", "shop", "cdn", "static",
    "media", "images", "login", "auth", "dashboard", "internal", "corp",
    "intranet", "secure", "help", "support", "docs", "wiki", "git",
    "gitlab", "jenkins", "ci", "cd", "prometheus", "grafana", "jira",
    "confluence", "ldap", "smtp", "webmail", "exchange", "backup",
    "monitor", "status", "beta", "alpha", "demo", "sandbox", "db",
    "database", "mysql", "postgres", "redis", "elastic", "kibana",
    "ns1", "ns2", "mx", "mx1", "mx2", "vpn1", "vpn2", "proxy",
]


class SubdomainEnumerator(BaseModule):

    NAME        = "subdomain/enum"
    DESCRIPTION = "Passive + active subdomain discovery via DNS brute-force"
    AUTHOR      = "NeiveZ"
    REFERENCES  = [
        "https://github.com/danielmiessler/SecLists",
        "https://crt.sh",
    ]

    def _define_options(self):
        self._add_option("TARGET",   "",     True,  "Target domain (e.g. example.com)")
        self._add_option("THREADS",  "50",   False, "Number of concurrent threads")
        self._add_option("WORDLIST", "",     False, "Path to custom wordlist file")
        self._add_option("TIMEOUT",  "2",    False, "DNS resolution timeout in seconds")

    # ── Run ───────────────────────────────────────────────────────────────────

    def run(self) -> dict:
        if not self._validate():
            return {}

        target  = self.get_option("TARGET").strip().lower().lstrip("www.").lstrip("http://").lstrip("https://").split("/")[0]
        threads = int(self.get_option("THREADS") or 50)
        timeout = float(self.get_option("TIMEOUT") or 2)
        wl_path = self.get_option("WORDLIST") or ""

        wordlist = self._load_wordlist(wl_path)

        print_section(f"Subdomain Enumeration → {Colors.CYAN}{target}{Colors.RESET}")
        print_status(f"Wordlist size : {Colors.WHITE}{len(wordlist)}{Colors.RESET} subdomains", "info")
        print_status(f"Threads       : {Colors.WHITE}{threads}{Colors.RESET}", "info")
        print_status(f"Timeout       : {Colors.WHITE}{timeout}s{Colors.RESET}", "info")
        print()

        found: list[dict] = []
        total = len(wordlist)
        completed = 0

        socket.setdefaulttimeout(timeout)

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            future_map = {
                executor.submit(self._resolve, f"{sub}.{target}"): sub
                for sub in wordlist
            }
            for future in concurrent.futures.as_completed(future_map):
                completed += 1
                loading_bar("Scanning", total, completed)
                result = future.result()
                if result:
                    found.append(result)
                    sys.stdout.write("\r" + " " * 60 + "\r")
                    print_status(
                        f"{Colors.GREEN}{result['subdomain']:<40}{Colors.RESET}"
                        f"{Colors.WHITE}{result['ip']}{Colors.RESET}",
                        "found"
                    )

        import sys
        print()
        print_status(f"Scan complete. Found {Colors.GREEN}{len(found)}{Colors.RESET} subdomains.", "ok")
        print()

        return {"target": target, "subdomains": found, "total": len(found)}

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _resolve(self, fqdn: str) -> dict | None:
        """Attempt to resolve an FQDN; return dict if successful."""
        try:
            ip = socket.gethostbyname(fqdn)
            return {"subdomain": fqdn, "ip": ip}
        except (socket.gaierror, socket.timeout):
            return None

    def _load_wordlist(self, path: str) -> list:
        """Load wordlist from file or fall back to built-in list."""
        if path and os.path.isfile(path):
            try:
                with open(path) as f:
                    words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
                print_status(f"Loaded external wordlist: {len(words)} entries", "info")
                return words
            except Exception as e:
                print_status(f"Failed to load wordlist ({e}), using built-in.", "warn")

        # Also check bundled wordlists directory
        bundled = os.path.join(os.path.dirname(__file__), "..", "wordlists", "subdomains.txt")
        if os.path.isfile(bundled):
            try:
                with open(bundled) as f:
                    return [line.strip() for line in f if line.strip() and not line.startswith("#")]
            except Exception:
                pass

        return DEFAULT_WORDLIST
