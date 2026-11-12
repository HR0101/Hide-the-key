"""CLI entry point for HideTheKey."""

import os
import sys
import argparse
from typing import List
from .scanner import scan_directory, ScanSummary
from .reporter import print_banner, render_report, render_json
from .git_checker import find_all_git_repos
from .fix import add_to_gitignore, untrack_file


def clean_input_path(raw_path: str) -> str:
    """Clean path inputted via drag-and-drop in macOS Terminal."""
    p = raw_path.strip()
    # Strip quotes if wrapped
    if (p.startswith('"') and p.endswith('"')) or (p.startswith("'") and p.endswith("'")):
        p = p[1:-1]
    # Handle terminal escaped spaces (e.g., My\ Folder -> My Folder)
    p = p.replace(r"\ ", " ")
    return os.path.expanduser(p)


def run_fix_action(summary: ScanSummary) -> None:
    """Execute automated fixes for detected issues."""
    if not summary.is_git:
        print("Cannot run auto-fix: Not inside a git repository.")
        return

    fixed_count = 0
    for issue in summary.issues:
        fname = os.path.basename(issue.file_path)
        if issue.issue_type == "SECRET_FILE_NOT_IGNORED":
            # Add to .gitignore
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
    else:
        print("\nNo automated fixes could be applied.")


def main():
    parser = argparse.ArgumentParser(
        prog="hide-the-key",
        description="Audit directories for API keys, secret files, .gitignore coverage, and accidental GitHub leaks.",
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=None,
        help="Path to scan (defaults to current working directory).",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Recursively scan all Git repositories found within the target directory.",
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
        "--no-safe",
        action="store_true",
        help="Do not display safely ignored files in the report.",
    )
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Run in interactive mode (prompt for directory if not provided).",
    )

    args = parser.parse_args()

    # Determine target path
    target_path = args.path
    if not target_path:
        if args.interactive:
            print_banner()
            prompt = "Enter folder to scan (drag and drop here, or press Enter for current folder): "
            user_input = input(prompt).strip()
            if user_input:
                target_path = clean_input_path(user_input)
            else:
                target_path = os.getcwd()
        else:
            target_path = os.getcwd()

    target_path = os.path.abspath(os.path.expanduser(target_path))

    if not os.path.exists(target_path):
        print(f"Error: Path does not exist: {target_path}", file=sys.stderr)
        sys.exit(1)

    if not args.json and not args.interactive:
        print_banner()

    # Multi-repo scan mode
    if args.all:
        repos = find_all_git_repos(target_path)
        if not repos:
            print(f"No git repositories found under: {target_path}")
            sys.exit(0)

        total_critical = 0
        total_high = 0

        for repo in repos:
            print(f"\nScanning repository: {repo}")
            summary = scan_directory(repo, check_history=args.history)
            if args.json:
                render_json(summary)
            else:
                render_report(summary, show_safe=not args.no_safe)
            total_critical += summary.critical_count
            total_high += summary.high_count

        exit_code = 1 if (total_critical > 0 or total_high > 0) else 0
        sys.exit(exit_code)

    # Single directory scan
    summary = scan_directory(target_path, check_history=args.history)

    if args.json:
        render_json(summary)
    else:
        render_report(summary, show_safe=not args.no_safe)

    if args.fix:
        print("\n🔧 Applying automatic fixes...")
        run_fix_action(summary)

    # In interactive mode, offer to fix if issues exist and wait before exit
    if args.interactive and (summary.critical_count > 0 or summary.high_count > 0) and not args.fix:
        answer = input("\nWould you like HideTheKey to automatically fix .gitignore for unprotected files? [y/N]: ").strip().lower()
        if answer == "y":
            run_fix_action(summary)

    # Return non-zero status if leaks are present (useful for CI/CD or pre-commit hooks)
    if summary.critical_count > 0 or summary.high_count > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
