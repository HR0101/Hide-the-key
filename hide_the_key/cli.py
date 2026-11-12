"""CLI entry point for HideTheKey (supports full-PC and targeted scans)."""

import os
import sys
import argparse
import subprocess
from typing import List, Optional
from .ci_formatter import (
    is_github_actions,
    emit_github_actions_annotations,
    write_github_step_summary,
    install_git_hook,
    init_github_workflow,
    init_gitlab_ci,
)
from .sarif_formatter import export_sarif
from .scanner import scan_directory, ScanSummary
from .global_scanner import run_global_scan, GlobalScanResult
from .reporter import print_banner, render_report, render_json, Colors
from .html_reporter import generate_html_report, generate_html_report_for_single
from .fix import add_to_gitignore, untrack_file

c = Colors()


def clean_input_path(raw_path: str) -> str:
    """Clean path inputted via drag-and-drop in macOS Terminal."""
    p = raw_path.strip()
    if (p.startswith('"') and p.endswith('"')) or (p.startswith("'") and p.endswith("'")):
        p = p[1:-1]
    p = p.replace(r"\ ", " ")
    return os.path.expanduser(p)


def open_file_in_browser(file_path: str):
    """Open a file in macOS default browser."""
    try:
        if sys.platform == "darwin":
            subprocess.run(["open", file_path], check=False)
        elif sys.platform.startswith("linux"):
            subprocess.run(["xdg-open", file_path], check=False)
    except Exception:
        pass


def print_global_summary(result: GlobalScanResult, html_path: Optional[str] = None):
    """Print terminal summary of global scan results."""
    print("\n" + "=" * 70)
    print(f"{c.BOLD}📊 GLOBAL PC SCAN RESULTS{c.RESET}")
    print(f"  Root Searched        : {result.start_root}")
    print(f"  Directories Audited  : {c.CYAN}{len(result.discovered_dirs)}{c.RESET}")
    print(f"  Files Inspected      : {c.CYAN}{result.total_scanned_files}{c.RESET}")
    print(f"  Scan Duration        : {result.duration_seconds:.2f} seconds")
    print("-" * 70)
    print(f"  🚨 Critical (Tracked/Staged)  : {c.RED}{c.BOLD}{result.total_critical}{c.RESET}")
    print(f"  ⚠️  High Risk (Unprotected)   : {c.YELLOW}{c.BOLD}{result.total_high}{c.RESET}")
    print(f"  ⚡ Warnings (Non-git / info)  : {c.MAGENTA}{result.total_medium}{c.RESET}")
    print(f"  ✅ Safely Protected           : {c.GREEN}{result.total_safe}{c.RESET}")
    print("=" * 70)

    # List affected directories if issues found
    flagged_summaries = [s for s in result.summaries if s.critical_count > 0 or s.high_count > 0]
    if flagged_summaries:
        print(f"\n{c.RED}{c.BOLD}⚠️  DIRECTORIES REQUIRING ATTENTION ({len(flagged_summaries)}):{c.RESET}")
        for s in flagged_summaries:
            badge = f"{c.RED}[CRITICAL: {s.critical_count}]{c.RESET}" if s.critical_count > 0 else f"{c.YELLOW}[HIGH: {s.high_count}]{c.RESET}"
            print(f"  {badge} {c.BOLD}{s.target_dir}{c.RESET}")
            for issue in s.issues:
                if issue.severity in ("CRITICAL", "HIGH"):
                    print(f"     • {issue.message}")
                    if issue.suggestion:
                        print(f"       {c.CYAN}Fix:{c.RESET} {issue.suggestion}")

    if html_path and os.path.exists(html_path):
        print(f"\n{c.GREEN}🌐 Interactive HTML report saved to:{c.RESET} {c.BOLD}{html_path}{c.RESET}")


def run_fix_action(summary: ScanSummary) -> None:
    """Execute automated fixes for detected issues."""
    if not summary.is_git:
        print("Cannot run auto-fix: Not inside a git repository.")
        return

    fixed_count = 0
    for issue in summary.issues:
        fname = os.path.basename(issue.file_path)
        if issue.issue_type == "SECRET_FILE_NOT_IGNORED":
            if add_to_gitignore(summary.git_root, fname):
                print(f"  [FIXED] Added '{fname}' to .gitignore")
                fixed_count += 1
        elif issue.issue_type == "SECRET_FILE_TRACKED":
            rel = os.path.relpath(issue.file_path, summary.git_root)
            success, msg = untrack_file(summary.git_root, rel)
            if success:
                print(f"  [FIXED] Untracked '{rel}' from git index (git rm --cached)")
                fixed_count += 1
                add_to_gitignore(summary.git_root, fname)

    if fixed_count > 0:
        print(f"\n🎉 Successfully applied {fixed_count} fix(es)! Please review and commit .gitignore.")


def main():
    parser = argparse.ArgumentParser(
        prog="hide-the-key",
        description="Audit your PC or repositories for exposed API keys, secret files, and .gitignore coverage.",
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=None,
        help="Specific path to scan. If omitted, scans the entire user home directory (~).",
    )
    parser.add_argument(
        "--global",
        "-g",
        dest="global_scan",
        action="store_true",
        help="Scan the entire computer / user home directory (default when no path provided).",
    )
    parser.add_argument(
        "--root",
        default="~",
        help="Root directory for global scan (default: '~'). E.g. '/' or '/Volumes/Drive'.",
    )
    parser.add_argument(
        "--history",
        action="store_true",
        help="Check git commit history for past committed secrets.",
    )
    parser.add_argument(
        "--fix",
        action="store_true",
        help="Automatically add unprotected secret files to .gitignore and untrack cached secrets.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output scan results in JSON format.",
    )
    parser.add_argument(
        "--ci",
        action="store_true",
        help="Run in CI mode (emits GitHub Actions annotations & step summary, fails on leaks).",
    )
    parser.add_argument(
        "--install-hook",
        action="store_true",
        help="Install HideTheKey as a local git pre-commit hook in the current repository.",
    )
    parser.add_argument(
        "--init-ci",
        action="store_true",
        help="Generate a GitHub Actions workflow (.github/workflows/hide-the-key.yml).",
    )
    parser.add_argument(
        "--sarif",
        metavar="FILE",
        help="Export findings in SARIF v2.1.0 format for GitHub Code Scanning / Security Alerts.",
    )
    parser.add_argument(
        "--init-gitlab",
        action="store_true",
        help="Generate a GitLab CI configuration (.gitlab-ci.yml).",
    )
    parser.add_argument(
        "--html",
        nargs="?",
        const="hide-the-key-report.html",
        default="hide-the-key-report.html",
        help="Generate an interactive HTML report (default: hide-the-key-report.html).",
    )
    parser.add_argument(
        "--no-open",
        action="store_true",
        help="Do not automatically open the HTML report in the browser.",
    )
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Run in interactive mode with menu options.",
    )

    args = parser.parse_args()

    # Handle setup flags
    if args.install_hook:
        repo_root = os.getcwd()
        if install_git_hook(repo_root):
            print(f"{c.GREEN}✅ Successfully installed pre-commit hook in {repo_root}/.git/hooks/pre-commit{c.RESET}")
            print(f"Git will now automatically audit for secret leaks before every commit!")
        sys.exit(0)

    if args.init_ci:
        repo_root = os.getcwd()
        path = init_github_workflow(repo_root)
        print(f"{c.GREEN}✅ Successfully created GitHub Actions workflow:{c.RESET} {path}")
        print("Commit and push this file to GitHub to enable automatic PR & push security audits.")
        sys.exit(0)

    if args.init_gitlab:
        repo_root = os.getcwd()
        path = init_gitlab_ci(repo_root)
        print(f"{c.GREEN}✅ Successfully created GitLab CI config:{c.RESET} {path}")
        sys.exit(0)

    # Interactive Mode (used by .command launcher)
    if args.interactive:
        print_banner()
        print(f"{c.BOLD}Select Scan Mode:{c.RESET}")
        print(f"  {c.CYAN}[1]{c.RESET} {c.BOLD}Scan entire PC (User Home Directory: ~){c.RESET} [Recommended]")
        print(f"  {c.CYAN}[2]{c.RESET} Scan a specific folder (drag & drop)")
        print(f"  {c.CYAN}[3]{c.RESET} Scan current working directory ({os.getcwd()})")
        print()
        choice = input("Enter choice [1/2/3] (default: 1): ").strip()

        if choice == "2":
            folder_input = input("Drag and drop the folder here: ").strip()
            target_path = clean_input_path(folder_input) if folder_input else os.getcwd()
            args.path = target_path
            args.global_scan = False
        elif choice == "3":
            args.path = os.getcwd()
            args.global_scan = False
        else:
            args.path = None
            args.global_scan = True

    # Check whether to run a global PC scan or a targeted single-directory scan
    if args.global_scan:
        is_global = True
    elif args.path is not None:
        is_global = False
    else:
        # If inside a git repository, default to scanning the repository immediately.
        # Otherwise, perform a global PC scan.
        from .git_checker import is_git_repo
        cwd = os.getcwd()
        # Don't treat home directory itself as a single repo default even if ~/.git exists
        is_home = (os.path.realpath(cwd) == os.path.realpath(os.path.expanduser("~")))
        if is_git_repo(cwd) and not is_home:
            is_global = False
            args.path = cwd
        else:
            is_global = True

    if is_global:
        # Full PC / Home directory scan
        scan_root = args.root if args.root != "~" else os.path.expanduser("~")
        if not args.json:
            print_banner()
            print(f"{c.BOLD}🚀 Launching Full PC Security Audit...{c.RESET}")
            print(f"Root: {scan_root}")

        result = run_global_scan(scan_root, check_history=args.history, show_progress=not args.json)

        html_file = None
        if args.html and not args.json:
            html_file = os.path.abspath(args.html)
            generate_html_report(result, html_file)

        if args.json:
            import json
            data = {
                "scan_root": result.start_root,
                "directories_count": len(result.discovered_dirs),
                "total_files": result.total_scanned_files,
                "critical": result.total_critical,
                "high": result.total_high,
                "medium": result.total_medium,
                "safe": result.total_safe,
                "duration": result.duration_seconds,
                "directories": [s.target_dir for s in result.summaries],
            }
            print(json.dumps(data, indent=2, ensure_ascii=False))
        else:
            print_global_summary(result, html_path=html_file)

            if html_file and not args.no_open and not args.json:
                print(f"\n{c.CYAN}Opening interactive report in browser...{c.RESET}")
                open_file_in_browser(html_file)

        sys.exit(1 if (result.total_critical > 0 or result.total_high > 0) else 0)

    # Targeted single directory scan
    target_path = os.path.realpath(os.path.expanduser(args.path))
    if not os.path.exists(target_path):
        print(f"Error: Path does not exist: {target_path}", file=sys.stderr)
        sys.exit(1)

    if not args.json:
        print_banner()

    summary = scan_directory(target_path, check_history=args.history)

    # In CI / GitHub Actions mode
    if args.ci or is_github_actions():
        emit_github_actions_annotations(summary)
        write_github_step_summary(summary)

    if args.sarif:
        export_sarif(summary, args.sarif)
        if not args.ci and not args.json:
            print(f"{c.GREEN}✅ Exported SARIF to:{c.RESET} {args.sarif}")

    if args.json:
        render_json(summary)
    else:
        render_report(summary)

    # Generate and open HTML report for single directory scan
    if args.html and not args.json:
        html_file = os.path.abspath(args.html)
        generate_html_report_for_single(summary, html_file)
        print(f"\n{c.GREEN}🌐 Interactive HTML report saved to:{c.RESET} {c.BOLD}{html_file}{c.RESET}")

        if not args.no_open and (args.interactive or sys.stdout.isatty()):
            open_file_in_browser(html_file)

    if args.fix:
        print("\n🔧 Applying automatic fixes...")
        run_fix_action(summary)

    sys.exit(1 if (summary.critical_count > 0 or summary.high_count > 0) else 0)


if __name__ == "__main__":
    main()
