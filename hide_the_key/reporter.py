"""Terminal reporting and visual output formatting."""

import os
import sys
import json
from typing import List
from .scanner import ScanSummary, FileIssue


class Colors:
    """ANSI color codes with NO_COLOR support."""
    def __init__(self):
        use_color = sys.stdout.isatty() and "NO_COLOR" not in os.environ
        self.RESET = "\033[0m" if use_color else ""
        self.BOLD = "\033[1m" if use_color else ""
        self.DIM = "\033[2m" if use_color else ""
        self.RED = "\033[31m" if use_color else ""
        self.GREEN = "\033[32m" if use_color else ""
        self.YELLOW = "\033[33m" if use_color else ""
        self.BLUE = "\033[34m" if use_color else ""
        self.MAGENTA = "\033[35m" if use_color else ""
        self.CYAN = "\033[36m" if use_color else ""
        self.WHITE = "\033[37m" if use_color else ""
        self.BG_RED = "\033[41m" if use_color else ""
        self.BG_GREEN = "\033[42m" if use_color else ""


c = Colors()


def print_banner():
    banner = rf"""{c.CYAN}{c.BOLD}
  _   _ _     _        _____ _             _  __           
 | | | (_) __| | ___  |_   _| |__   ___   | |/ /___ _   _  
 | |_| | |/ _` |/ _ \   | | | '_ \ / _ \  | ' // _ \ | | | 
 |  _  | | (_| |  __/   | | | | | |  __/  | . \  __/ |_| | 
 |_| |_|_|\__,_|\___|   |_| |_| |_|\___|  |_|\_\___|\__, | 
                                                    |___/  
{c.RESET}{c.DIM}   🔍 Secret Leak Prevention & .gitignore Auditor for GitHub{c.RESET}
"""
    print(banner)


def render_report(summary: ScanSummary, show_safe: bool = True):
    """Render a comprehensive visual report to stdout."""
    print(f"{c.BOLD}Target Directory:{c.RESET} {summary.target_dir}")
    if summary.is_git:
        print(f"{c.BOLD}Git Repository  :{c.RESET} {c.GREEN}Yes{c.RESET} (Root: {summary.git_root})")
    else:
        print(f"{c.BOLD}Git Repository  :{c.RESET} {c.YELLOW}No (.git not found){c.RESET}")
    print(f"{c.BOLD}Files Scanned   :{c.RESET} {summary.scanned_files_count} files\n")

    # Group issues by severity
    critical_issues = [i for i in summary.issues if i.severity == "CRITICAL"]
    high_issues = [i for i in summary.issues if i.severity == "HIGH"]
    medium_issues = [i for i in summary.issues if i.severity == "MEDIUM"]
    low_issues = [i for i in summary.issues if i.severity == "LOW"]
    safe_issues = [i for i in summary.issues if i.severity == "SAFE"]

    # 1. CRITICAL ISSUES
    if critical_issues:
        print(f"{c.BG_RED}{c.WHITE}{c.BOLD} 🚨 CRITICAL DANGER - IMMEDIATE ACTION REQUIRED 🚨 {c.RESET}")
        print(f"{c.RED}These secrets are ALREADY tracked or staged in git and WILL BE pushed to GitHub!{c.RESET}\n")
        for issue in critical_issues:
            print_issue_card(issue, c.RED, "CRITICAL")

    # 2. HIGH ISSUES
    if high_issues:
        print(f"\n{c.YELLOW}{c.BOLD} ⚠️  HIGH RISK - UNPROTECTED SECRET FILES ⚠️ {c.RESET}")
        print(f"{c.YELLOW}These secret files exist but are NOT in .gitignore. 'git add .' will expose them!{c.RESET}\n")
        for issue in high_issues:
            print_issue_card(issue, c.YELLOW, "HIGH")

    # 3. MEDIUM ISSUES
    if medium_issues:
        print(f"\n{c.MAGENTA}{c.BOLD} ⚡ WARNINGS {c.RESET}")
        for issue in medium_issues:
            print_issue_card(issue, c.MAGENTA, "WARNING")

    # 4. LOW ISSUES
    if low_issues:
        print(f"\n{c.BLUE}{c.BOLD} ℹ️  NOTICES {c.RESET}")
        for issue in low_issues:
            print_issue_card(issue, c.BLUE, "INFO")

    # 5. SAFE (IGNORED) FILES
    if show_safe and safe_issues:
        print(f"\n{c.GREEN}{c.BOLD} ✅ PROTECTED FILES (Safely Ignored by .gitignore) {c.RESET}")
        for issue in safe_issues:
            rule = issue.details.get("ignore_rule") or ".gitignore"
            rel = os.path.relpath(issue.file_path, summary.target_dir)
            print(f"  {c.GREEN}✔{c.RESET} {rel} {c.DIM}(Matched rule: {rule}){c.RESET}")

    # Summary box
    print("\n" + "=" * 65)
    print(f"{c.BOLD}📊 SCAN SUMMARY:{c.RESET}")
    print(f"  Critical (Tracked / Exposed) : {c.RED}{c.BOLD}{len(critical_issues)}{c.RESET}")
    print(f"  High (Missing .gitignore)   : {c.YELLOW}{c.BOLD}{len(high_issues)}{c.RESET}")
    print(f"  Warnings & Notices           : {c.CYAN}{len(medium_issues) + len(low_issues)}{c.RESET}")
    print(f"  Safely Protected             : {c.GREEN}{len(safe_issues)}{c.RESET}")
    print("=" * 65)

    if critical_issues or high_issues:
        print(f"\n{c.BOLD}🛠  RECOMMENDED ACTIONS:{c.RESET}")
        if critical_issues:
            print(f" {c.RED}1.{c.RESET} Remove tracked secret files from git cache without deleting local files:")
            for issue in critical_issues:
                if issue.issue_type == "SECRET_FILE_TRACKED":
                    rel = os.path.relpath(issue.file_path, summary.git_root or summary.target_dir)
                    print(f"    {c.BOLD}git rm --cached {rel}{c.RESET}")
            print(f" {c.RED}2.{c.RESET} If secrets were committed in previous commits, rotate your keys immediately!")
            print(f"    Consider using {c.CYAN}git-filter-repo{c.RESET} or {c.CYAN}BFG Repo-Cleaner{c.RESET} to scrub history.")

        if high_issues:
            print(f" {c.YELLOW}3.{c.RESET} Add unignored secret files to .gitignore:")
            for issue in high_issues:
                if issue.issue_type == "SECRET_FILE_NOT_IGNORED":
                    fname = os.path.basename(issue.file_path)
                    print(f"    {c.BOLD}echo '{fname}' >> .gitignore{c.RESET}")

        print(f"\n  💡 Run with {c.BOLD}--fix{c.RESET} to automatically add unignored secret files to .gitignore!")
    else:
        print(f"\n{c.GREEN}{c.BOLD}🎉 Awesome! No exposed API keys or unignored secrets found.{c.RESET}")


def print_issue_card(issue: FileIssue, color: str, badge: str):
    print(f"  {color}[{badge}]{c.RESET} {c.BOLD}{issue.file_path}{c.RESET}")
    print(f"    {color}•{c.RESET} {issue.message}")
    if issue.suggestion:
        print(f"    {c.CYAN}💡 Fix:{c.RESET} {issue.suggestion}")
    print()


def render_json(summary: ScanSummary):
    """Output scan results as structured JSON."""
    data = {
        "target_dir": summary.target_dir,
        "is_git": summary.is_git,
        "git_root": summary.git_root,
        "scanned_files_count": summary.scanned_files_count,
        "critical_count": summary.critical_count,
        "high_count": summary.high_count,
        "medium_count": summary.medium_count,
        "safe_count": summary.safe_count,
        "issues": [issue.to_dict() for issue in summary.issues],
    }
    print(json.dumps(data, indent=2, ensure_ascii=False))
