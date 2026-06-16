#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
modules/http_probe.py — HTTP fingerprinting: headers, technologies, redirects, cookies.
"""

import urllib.request
import urllib.error
import urllib.parse
import ssl
import re
from modules.base import BaseModule
from utils.colors import Colors, print_status, print_section


# Technology fingerprints (header → tech name)
HEADER_FINGERPRINTS = {
    "server": {
        "nginx":           "Nginx",
        "apache":          "Apache",
        "microsoft-iis":   "IIS",
        "cloudflare":      "Cloudflare",
        "lighttpd":        "Lighttpd",
        "openresty":       "OpenResty",
        "litespeed":       "LiteSpeed",
        "gunicorn":        "Gunicorn",
        "express":         "Express.js",
        "jetty":           "Jetty",
        "tomcat":          "Tomcat",
        "kestrel":         "Kestrel (.NET)",
    },
    "x-powered-by": {
        "php":             "PHP",
        "asp.net":         "ASP.NET",
        "express":         "Express.js",
        "next.js":         "Next.js",
        "ruby":            "Ruby",
    },
    "x-generator": {
        "drupal":          "Drupal",
        "wordpress":       "WordPress",
        "joomla":          "Joomla",
    },
}

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "x-xss-protection",
    "referrer-policy",
    "permissions-policy",
]


class HTTPProbe(BaseModule):

    NAME        = "recon/http_probe"
    DESCRIPTION = "HTTP header analysis, technology fingerprinting & security header check"
    AUTHOR      = "NeiveZ"
    REFERENCES  = [
        "https://owasp.org/www-project-secure-headers/",
        "https://securityheaders.com",
    ]

    def _define_options(self):
        self._add_option("TARGET",     "",       True,  "Target URL (e.g. https://example.com)")
        self._add_option("FOLLOW",     "true",   False, "Follow redirects (true/false)")
        self._add_option("TIMEOUT",    "10",     False, "Request timeout in seconds")
        self._add_option("USER_AGENT", "ORFX/1.0 (Security Assessment)", False, "HTTP User-Agent string")

    # ── Run ───────────────────────────────────────────────────────────────────

    def run(self) -> dict:
        if not self._validate():
            return {}

        url     = self.get_option("TARGET").strip()
        follow  = self.get_option("FOLLOW").lower() == "true"
        timeout = int(self.get_option("TIMEOUT") or 10)
        ua      = self.get_option("USER_AGENT")

        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        print_section(f"HTTP Probe → {Colors.CYAN}{url}{Colors.RESET}")

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(url, headers={"User-Agent": ua})

        try:
            handler = urllib.request.HTTPSHandler(context=ctx)
            opener = urllib.request.build_opener(handler)
            if not follow:
                opener = urllib.request.build_opener(
                    urllib.request.HTTPSHandler(context=ctx),
                    NoRedirectHandler()
                )
            resp = opener.open(req, timeout=timeout)
            headers = dict(resp.headers)
            status  = resp.status
            final_url = resp.url
        except urllib.error.HTTPError as e:
            headers = dict(e.headers)
            status  = e.code
            final_url = url
        except Exception as e:
            print_status(f"Request failed: {e}", "error")
            return {}

        result = {
            "target":           url,
            "final_url":        final_url,
            "status_code":      status,
            "headers":          headers,
            "technologies":     [],
            "security_headers": {},
        }

        # ── Status ────────────────────────────────────────────────────────────
        sc = str(status)
        sc_color = Colors.GREEN if sc.startswith("2") else Colors.YELLOW if sc.startswith("3") else Colors.RED
        print_status(f"Status     : {sc_color}{Colors.BOLD}{status}{Colors.RESET}", "result")

        if final_url != url:
            print_status(f"Redirect   : {Colors.CYAN}{final_url}{Colors.RESET}", "result")

        # ── All Headers ───────────────────────────────────────────────────────
        print()
        print(f"  {Colors.BOLD}{Colors.WHITE}Response Headers{Colors.RESET}")
        for name, val in sorted(headers.items()):
            truncated = val[:100] + "…" if len(val) > 100 else val
            print(f"  {Colors.DARK_GRAY}{name:<35}{Colors.RESET}{Colors.WHITE}{truncated}{Colors.RESET}")

        # ── Technology Detection ──────────────────────────────────────────────
        techs = []
        lower_headers = {k.lower(): v.lower() for k, v in headers.items()}
        for header, patterns in HEADER_FINGERPRINTS.items():
            hval = lower_headers.get(header, "")
            for pattern, tech in patterns.items():
                if pattern in hval:
                    techs.append(tech)

        if techs:
            result["technologies"] = techs
            print()
            print(f"  {Colors.BOLD}{Colors.WHITE}Detected Technologies{Colors.RESET}")
            for t in techs:
                print(f"  {Colors.GREEN}[+]{Colors.RESET} {Colors.CYAN}{t}{Colors.RESET}")

        # ── Security Headers Audit ────────────────────────────────────────────
        print()
        print(f"  {Colors.BOLD}{Colors.WHITE}Security Header Audit{Colors.RESET}")
        for sh in SECURITY_HEADERS:
            present = sh in lower_headers
            status_str = f"{Colors.GREEN}PRESENT{Colors.RESET}" if present else f"{Colors.RED}MISSING{Colors.RESET}"
            icon = f"{Colors.GREEN}[✓]{Colors.RESET}" if present else f"{Colors.RED}[✗]{Colors.RESET}"
            print(f"  {icon} {Colors.DARK_GRAY}{sh}{Colors.RESET} : {status_str}")
            result["security_headers"][sh] = present

        print()
        print_status("HTTP probe complete.", "ok")
        return result


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Handler that suppresses all redirects."""
    def redirect_request(self, *args, **kwargs):
        return None
