#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ORFX - Offensive Recon Framework
Author: NeiveZ | github.com/NeiveZ/ORFX
For authorized security testing only.
"""

import cmd
import sys
import os
import json
import shutil
from datetime import datetime
from utils.colors import Colors, print_status
from utils.session import Session

from modules.subdomain_enum import SubdomainEnumerator
from modules.port_scanner import PortScanner
from modules.whois_lookup import WhoisLookup
from modules.dns_recon import DNSRecon
from modules.http_probe import HTTPProbe
from modules.report_gen import ReportGenerator


class ORFXShell(cmd.Cmd):
    """Interactive shell for ORFX - styled after Metasploit's console."""

    intro = ""
    prompt = f"{Colors.BOLD}{Colors.RED}orfx{Colors.RESET} {Colors.WHITE}>{Colors.RESET} "

    def __init__(self):
        super().__init__()
        self.session = Session()
        self.modules = {
            "subdomain/enum":   SubdomainEnumerator,
            "recon/port_scan":  PortScanner,
            "recon/whois":      WhoisLookup,
            "recon/dns":        DNSRecon,
            "recon/http_probe": HTTPProbe,
        }
        self.active_module = None
        self.active_module_name = None
        self._show_header()

    # ── Helpers ───────────────────────────────────────────────────

    def _show_header(self):
        stats = self.session.get_stats()
        print(f"\n  {Colors.BOLD}{Colors.RED}ORFX{Colors.RESET}  {Colors.DARK_GRAY}Offensive Recon Framework{Colors.RESET}  {Colors.WHITE}v1.0.0{Colors.RESET}")
        print(f"  {Colors.DARK_GRAY}Author: NeiveZ  |  For authorized testing only{Colors.RESET}")
        print(f"  {Colors.DARK_GRAY}Sessions: {Colors.WHITE}{stats['sessions']}"
              f"  {Colors.DARK_GRAY}Scans: {Colors.WHITE}{stats['scans']}"
              f"  {Colors.DARK_GRAY}Reports: {Colors.WHITE}{stats['reports']}{Colors.RESET}")
        print(f"\n  {Colors.DARK_GRAY}Type {Colors.CYAN}help{Colors.DARK_GRAY} to list commands.{Colors.RESET}\n")

    def _update_prompt(self):
        if self.active_module_name:
            self.prompt = (
                f"{Colors.BOLD}{Colors.RED}orfx{Colors.RESET}"
                f"{Colors.DARK_GRAY}({Colors.RESET}"
                f"{Colors.YELLOW}{self.active_module_name}{Colors.RESET}"
                f"{Colors.DARK_GRAY}){Colors.RESET} "
                f"{Colors.WHITE}>{Colors.RESET} "
            )
        else:
            self.prompt = f"{Colors.BOLD}{Colors.RED}orfx{Colors.RESET} {Colors.WHITE}>{Colors.RESET} "

    def default(self, line):
        print_status(f"Unknown command: '{line}'. Type 'help' for available commands.", "error")

    def emptyline(self):
        pass

    # ── Core Commands ─────────────────────────────────────────────

    def do_use(self, module_name):
        """Load a module.\n  Usage: use <module>\n  Example: use subdomain/enum"""
        module_name = module_name.strip()
        if not module_name:
            print_status("Usage: use <module_name>", "warn")
            return
        if module_name not in self.modules:
            print_status(f"Module '{module_name}' not found. Run 'show modules' to list available.", "error")
            return
        self.active_module_name = module_name
        self.active_module = self.modules[module_name]()
        self._update_prompt()
        print_status(f"Module loaded: {Colors.YELLOW}{module_name}{Colors.RESET}", "ok")
        print()
        self.active_module.show_info()

    def do_set(self, args):
        """Set a module option.\n  Usage: set <OPTION> <value>\n  Example: set TARGET example.com"""
        if not self.active_module:
            print_status("No module loaded. Use 'use <module>' first.", "warn")
            return
        parts = args.strip().split(None, 1)
        if len(parts) < 2:
            print_status("Usage: set <OPTION> <value>", "warn")
            return
        opt, val = parts[0].upper(), parts[1]
        if self.active_module.set_option(opt, val):
            print_status(f"{Colors.CYAN}{opt}{Colors.RESET} => {Colors.WHITE}{val}{Colors.RESET}", "ok")
        else:
            print_status(f"Unknown option: {opt}. Run 'options' to see available.", "error")

    def do_run(self, _):
        """Execute the loaded module.\n  Usage: run"""
        if not self.active_module:
            print_status("No module loaded. Use 'use <module>' first.", "warn")
            return
        print()
        try:
            results = self.active_module.run()
            if results:
                self.session.add_results(self.active_module_name, results)
                self._auto_save(results)
        except KeyboardInterrupt:
            print()
            print_status("Scan interrupted by user.", "warn")
        except Exception as e:
            print_status(f"Module error: {e}", "error")

    def do_options(self, _):
        """Show current module options.\n  Usage: options"""
        if not self.active_module:
            print_status("No module loaded.", "warn")
            return
        self.active_module.show_options()

    def do_info(self, _):
        """Show detailed info about loaded module.\n  Usage: info"""
        if not self.active_module:
            print_status("No module loaded.", "warn")
            return
        self.active_module.show_info()

    def do_back(self, _):
        """Unload the current module.\n  Usage: back"""
        if self.active_module:
            print_status(f"Unloaded module: {self.active_module_name}", "info")
            self.active_module = None
            self.active_module_name = None
            self._update_prompt()
        else:
            print_status("No module loaded.", "warn")

    # ── Show Commands ─────────────────────────────────────────────

    def do_show(self, args):
        """Show modules, results, or session info.\n  Usage: show modules | show results | show sessions"""
        arg = args.strip().lower()
        if arg == "modules":
            self._show_modules()
        elif arg == "results":
            self._show_results()
        elif arg in ("sessions", "session"):
            self._show_session()
        else:
            print_status("Usage: show [modules|results|sessions]", "warn")

    def _show_modules(self):
        col_w = shutil.get_terminal_size((80, 20)).columns
        print(f"\n  {Colors.BOLD}{Colors.WHITE}Available Modules{Colors.RESET}\n")
        print(f"  {'─' * (col_w - 4)}")
        print(f"{Colors.DARK_GRAY}  {'Name':<25} {'Category':<15} Description{Colors.RESET}")
        print(f"  {'─' * (col_w - 4)}")
        module_info = {
            "subdomain/enum":   ("Enumeration", "Passive + active subdomain discovery"),
            "recon/port_scan":  ("Scanning",    "TCP port scanner with banner grabbing"),
            "recon/whois":      ("OSINT",        "WHOIS lookup and registrar information"),
            "recon/dns":        ("DNS",          "DNS record enumeration (A, MX, NS, TXT...)"),
            "recon/http_probe": ("Web Recon",    "HTTP header & technology fingerprinting"),
        }
        for name, (cat, desc) in module_info.items():
            print(f"  {Colors.CYAN}{name:<25}{Colors.RESET}"
                  f"{Colors.DARK_GRAY}{cat:<15}{Colors.RESET}"
                  f"{Colors.WHITE}{desc}{Colors.RESET}")
        print(f"  {'─' * (col_w - 4)}\n")

    def _show_results(self):
        results = self.session.get_all_results()
        if not results:
            print_status("No results in session. Run a module first.", "warn")
            return
        print(f"\n  {Colors.BOLD}{Colors.WHITE}Session Results{Colors.RESET}\n")
        for module, data in results.items():
            print(f"  {Colors.YELLOW}[{module}]{Colors.RESET}")
            if isinstance(data, dict):
                for k, v in data.items():
                    print(f"    {Colors.DARK_GRAY}{k}:{Colors.RESET} {v}")
            elif isinstance(data, list):
                for item in data[:20]:
                    print(f"    {Colors.WHITE}• {item}{Colors.RESET}")
                if len(data) > 20:
                    print(f"    {Colors.DARK_GRAY}... and {len(data)-20} more{Colors.RESET}")
            print()

    def _show_session(self):
        stats = self.session.get_stats()
        print(f"\n  {Colors.BOLD}{Colors.WHITE}Current Session{Colors.RESET}\n")
        print(f"  {Colors.DARK_GRAY}Session ID {Colors.RESET}: {Colors.CYAN}{stats['id']}{Colors.RESET}")
        print(f"  {Colors.DARK_GRAY}Started    {Colors.RESET}: {stats['started']}")
        print(f"  {Colors.DARK_GRAY}Scans Run  {Colors.RESET}: {Colors.WHITE}{stats['scans']}{Colors.RESET}")
        print(f"  {Colors.DARK_GRAY}Results    {Colors.RESET}: {Colors.WHITE}{stats['results']}{Colors.RESET}")
        print(f"  {Colors.DARK_GRAY}Reports    {Colors.RESET}: {Colors.WHITE}{stats['reports']}{Colors.RESET}\n")

    # ── Report Commands ───────────────────────────────────────────

    def do_report(self, args):
        """Generate a report from session results.\n  Usage: report [json|txt|html] [filename]"""
        parts = args.strip().split()
        fmt   = parts[0].lower() if parts else "txt"
        fname = parts[1] if len(parts) > 1 else None
        results = self.session.get_all_results()
        if not results:
            print_status("No results to report. Run a module first.", "warn")
            return
        gen  = ReportGenerator(results, self.session.get_stats())
        path = gen.generate(fmt=fmt, filename=fname)
        if path:
            self.session.increment_reports()
            print_status(f"Report saved: {Colors.CYAN}{path}{Colors.RESET}", "ok")

    def _auto_save(self, results):
        """Auto-save results to JSON after every scan."""
        os.makedirs("reports", exist_ok=True)
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = f"reports/auto_{self.active_module_name.replace('/', '_')}_{ts}.json"
        try:
            with open(path, "w") as f:
                json.dump({
                    "module":    self.active_module_name,
                    "timestamp": ts,
                    "results":   results if isinstance(results, (dict, list)) else str(results),
                }, f, indent=2, default=str)
        except Exception:
            pass

    # ── Utility Commands ──────────────────────────────────────────

    def do_clear(self, _):
        """Clear the terminal screen.\n  Usage: clear"""
        os.system("clear" if os.name == "posix" else "cls")
        self._show_header()

    def do_history(self, _):
        """Show session scan history.\n  Usage: history"""
        history = self.session.get_history()
        if not history:
            print_status("No history yet.", "info")
            return
        print(f"\n  {Colors.BOLD}{Colors.WHITE}Command History{Colors.RESET}\n")
        for i, entry in enumerate(history, 1):
            print(f"  {Colors.DARK_GRAY}{i:>3}.{Colors.RESET} "
                  f"{Colors.YELLOW}{entry['module']:<25}{Colors.RESET}"
                  f"{Colors.WHITE}{entry['target']:<30}{Colors.RESET}"
                  f"{Colors.DARK_GRAY}{entry['time']}{Colors.RESET}")
        print()

    def do_exit(self, _):
        """Exit ORFX.\n  Usage: exit"""
        print(f"\n  {Colors.DARK_GRAY}Goodbye. Stay ethical.{Colors.RESET}\n")
        return True

    def do_quit(self, _):
        """Alias for exit."""
        return self.do_exit(_)

    def do_help(self, arg):
        """Show help for commands."""
        if arg:
            super().do_help(arg)
            return
        print(f"""
  {Colors.BOLD}{Colors.WHITE}Core Commands{Colors.RESET}
  {'─'*40}
  {Colors.CYAN}use <module>{Colors.RESET}            Load a module
  {Colors.CYAN}set <OPTION> <value>{Colors.RESET}    Set a module option
  {Colors.CYAN}run{Colors.RESET}                     Execute the loaded module
  {Colors.CYAN}options{Colors.RESET}                 Show module options
  {Colors.CYAN}info{Colors.RESET}                    Show module information
  {Colors.CYAN}back{Colors.RESET}                    Unload current module

  {Colors.BOLD}{Colors.WHITE}Show Commands{Colors.RESET}
  {'─'*40}
  {Colors.CYAN}show modules{Colors.RESET}            List all available modules
  {Colors.CYAN}show results{Colors.RESET}            Show session results
  {Colors.CYAN}show sessions{Colors.RESET}           Show session info

  {Colors.BOLD}{Colors.WHITE}Output{Colors.RESET}
  {'─'*40}
  {Colors.CYAN}report [json|txt|html]{Colors.RESET}  Generate report
  {Colors.CYAN}history{Colors.RESET}                 Show scan history

  {Colors.BOLD}{Colors.WHITE}Utility{Colors.RESET}
  {'─'*40}
  {Colors.CYAN}clear{Colors.RESET}                   Clear screen
  {Colors.CYAN}exit{Colors.RESET}                    Exit ORFX
""")


# ── Entry Point ───────────────────────────────────────────────────

def main():
    try:
        shell = ORFXShell()
        shell.cmdloop()
    except KeyboardInterrupt:
        print(f"\n\n  {Colors.DARK_GRAY}Interrupted. Goodbye.{Colors.RESET}\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
