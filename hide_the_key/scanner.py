"""Scanner orchestration for directories, sensitive files, and git tracking status."""

import os
import fnmatch
from typing import List, Dict, Optional, Set, Tuple
from .constants import (
    DEFAULT_IGNORE_DIRS,
    SECRET_FILE_NAMES,
    SECRET_FILE_EXTENSIONS,
    SECRET_FILE_REGEXES,
    SAFE_FILE_SUFFIXES,
    SUSPICIOUS_UNWANTED_FILES,
)
from .git_checker import (
    find_git_root,
    is_git_repo,
    get_git_status_info,
    get_staged_diff,
)
from .secret_detector import (
    scan_file_for_secrets,
    scan_diff_for_secrets,
    is_safe_filename,
)


class FileIssue:
    def __init__(
        self,
        file_path: str,
        issue_type: str,  # 'SECRET_FILE', 'HARDCODED_KEY', 'SUSPICIOUS_FILE'
        severity: str,    # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'SAFE'
        message: str,
        details: Optional[Dict] = None,
        suggestion: Optional[str] = None,
    ):
        self.file_path = file_path
        self.issue_type = issue_type
        self.severity = severity
        self.message = message
        self.details = details or {}
        self.suggestion = suggestion

    def to_dict(self) -> Dict:
        return {
            "file_path": self.file_path,
            "issue_type": self.issue_type,
            "severity": self.severity,
            "message": self.message,
            "details": self.details,
            "suggestion": self.suggestion,
        }


class ScanSummary:
    def __init__(self, target_dir: str):
        self.target_dir = target_dir
        self.git_root: Optional[str] = None
        self.is_git: bool = False
        self.scanned_files_count: int = 0
        self.issues: List[FileIssue] = []

    def add_issue(self, issue: FileIssue):
        self.issues.append(issue)

    @property
    def critical_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == "CRITICAL")

    @property
    def high_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == "HIGH")

    @property
    def medium_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == "MEDIUM")

    @property
    def safe_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == "SAFE")


def is_potential_secret_file(filename: str) -> bool:
    """Check if the filename itself implies a secret/config file."""
    if is_safe_filename(filename):
        return False

    lower_name = filename.lower()
    if lower_name in SECRET_FILE_NAMES:
        return True

    _, ext = os.path.splitext(lower_name)
    if ext in SECRET_FILE_EXTENSIONS:
        return True

    for regex in SECRET_FILE_REGEXES:
        if regex.match(filename):
            return True

    return False


def check_suspicious_unwanted(filename: str) -> Optional[Tuple[str, str]]:
    """Check if a file is an unwanted file like .DS_Store or db dumps."""
    lower_name = filename.lower()
    for pattern, reason in SUSPICIOUS_UNWANTED_FILES:
        if fnmatch.fnmatch(lower_name, pattern.lower()):
            return pattern, reason
    return None


def scan_directory(
    target_dir: str,
    check_staged: bool = True,
    check_history: bool = False,
    shallow_only: bool = False,
    custom_ignore_dirs: Optional[Set[str]] = None,
) -> ScanSummary:
    """
    Perform a complete scan of target_dir:
    1. Identify Git repository root
    2. Check sensitive files (.env, keys) & their .gitignore / tracking status
    3. Check code content for hardcoded secrets
    4. Check git staged diff if git is available
    """
    target_dir = os.path.realpath(target_dir)
    summary = ScanSummary(target_dir)

    git_root = find_git_root(target_dir)
    if git_root:
        git_root = os.path.realpath(git_root)
    summary.git_root = git_root
    summary.is_git = git_root is not None

    ignore_dirs = DEFAULT_IGNORE_DIRS.copy()
    if custom_ignore_dirs:
        ignore_dirs.update(custom_ignore_dirs)

    # 1. Walk through the directory tree
    for root, dirs, files in os.walk(target_dir):
        if shallow_only and root != target_dir:
            dirs.clear()
            continue

        # Prune ignored directories
        dirs[:] = [d for d in dirs if d not in ignore_dirs and not d.startswith(".git")]
        if shallow_only:
            dirs.clear()

        for fname in files:
            full_path = os.path.join(root, fname)
            rel_to_target = os.path.relpath(full_path, target_dir)
            rel_to_repo = (
                os.path.relpath(full_path, git_root) if git_root else rel_to_target
            )

            summary.scanned_files_count += 1

            # (A) Check if this is a Secret / Config File (e.g. .env, key)
            if is_potential_secret_file(fname):
                if summary.is_git:
                    git_status = get_git_status_info(git_root, rel_to_repo)
                    if git_status["is_tracked"]:
                        summary.add_issue(
                            FileIssue(
                                file_path=full_path,
                                issue_type="SECRET_FILE_TRACKED",
                                severity="CRITICAL",
                                message=f"Secret file '{fname}' is TRACKED by git! (Already in repository or staged)",
                                details=git_status,
                                suggestion=f"Run: git rm --cached {rel_to_repo} && echo '{fname}' >> .gitignore",
                            )
                        )
                    elif not git_status["is_ignored"]:
                        summary.add_issue(
                            FileIssue(
                                file_path=full_path,
                                issue_type="SECRET_FILE_NOT_IGNORED",
                                severity="HIGH",
                                message=f"Secret file '{fname}' is NOT listed in .gitignore! Will be committed if 'git add .' is run.",
                                details=git_status,
                                suggestion=f"Add to .gitignore: echo '{fname}' >> .gitignore",
                            )
                        )
                    else:
                        summary.add_issue(
                            FileIssue(
                                file_path=full_path,
                                issue_type="SECRET_FILE_IGNORED",
                                severity="SAFE",
                                message=f"Secret file '{fname}' is safely ignored by .gitignore ({git_status['ignore_rule']}).",
                                details=git_status,
                            )
                        )
                else:
                    summary.add_issue(
                        FileIssue(
                            file_path=full_path,
                            issue_type="SECRET_FILE_NO_GIT",
                            severity="MEDIUM",
                            message=f"Secret file '{fname}' found in non-git directory.",
                            suggestion="Make sure to add it to .gitignore before initializing a git repository.",
                        )
                    )

            # (B) Check unwanted files like .DS_Store or database dumps
            suspicious = check_suspicious_unwanted(fname)
            if suspicious:
                pattern, reason = suspicious
                if summary.is_git:
                    git_status = get_git_status_info(git_root, rel_to_repo)
                    if git_status["is_tracked"]:
                        summary.add_issue(
                            FileIssue(
                                file_path=full_path,
                                issue_type="UNWANTED_FILE_TRACKED",
                                severity="HIGH",
                                message=f"Unwanted file '{fname}' ({reason}) is TRACKED in git!",
                                details=git_status,
                                suggestion=f"Run: git rm --cached {rel_to_repo} && echo '{pattern}' >> .gitignore",
                            )
                        )
                    elif not git_status["is_ignored"]:
                        summary.add_issue(
                            FileIssue(
                                file_path=full_path,
                                issue_type="UNWANTED_FILE_NOT_IGNORED",
                                severity="LOW",
                                message=f"Unwanted file '{fname}' ({reason}) is not ignored by .gitignore.",
                                details=git_status,
                                suggestion=f"Add '{pattern}' to your .gitignore",
                            )
                        )

            # (C) Scan file contents for hardcoded API keys / secrets
            # Skip scanning if the file itself is an ignored .env file (we already know it holds secrets)
            is_env_like = fname.startswith(".env") or fname.endswith((".pem", ".key", ".p12"))
            if not is_env_like:
                findings = scan_file_for_secrets(full_path)
                for f in findings:
                    severity = f["severity"]
                    git_note = ""
                    if summary.is_git:
                        git_status = get_git_status_info(git_root, rel_to_repo)
                        if git_status["is_ignored"]:
                            severity = "LOW"
                            git_note = " (Note: File is currently ignored by .gitignore)"
                        elif git_status["is_tracked"]:
                            severity = "CRITICAL"
                            git_note = " (CRITICAL: File is tracked in git!)"
                        else:
                            severity = "HIGH"
                            git_note = " (HIGH: File is untracked and not in .gitignore)"
                    else:
                        # Non-git directory
                        severity = "MEDIUM"
                        git_note = " (Directory is not a Git repo)"

                    summary.add_issue(
                        FileIssue(
                            file_path=full_path,
                            issue_type="HARDCODED_KEY",
                            severity=severity,
                            message=f"Hardcoded {f['rule_name']} on line {f['line_number']}: {f['masked_secret']}{git_note}",
                            details=f,
                            suggestion="Move the secret to an environment variable (.env) and read it via os.environ / process.env.",
                        )
                    )

    # 2. Check staged diff for secrets if inside git repo
    if summary.is_git and check_staged:
        diff_text = get_staged_diff(git_root)
        if diff_text:
            diff_findings = scan_diff_for_secrets(diff_text)
            for df in diff_findings:
                summary.add_issue(
                    FileIssue(
                        file_path=os.path.join(git_root, df["file_path"]),
                        issue_type="STAGED_DIFF_KEY",
                        severity="CRITICAL",
                        message=f"STAGED SECRET: {df['rule_name']} is currently staged to be committed in '{df['file_path']}': {df['masked_secret']}",
                        details=df,
                        suggestion=f"Unstage immediately: git restore --staged {df['file_path']}",
                    )
                )

    # 3. Check git history for committed secrets if requested
    if summary.is_git and check_history:
        from .git_checker import check_git_history_for_secrets
        history_findings = check_git_history_for_secrets(git_root)
        for hf in history_findings:
            summary.add_issue(
                FileIssue(
                    file_path=hf["file"],
                    issue_type="GIT_HISTORY_LEAK",
                    severity="CRITICAL",
                    message=f"HISTORICAL LEAK: Secret file was added in past commit {hf['commit_hash']} (\"{hf['subject']}\" by {hf['author']})",
                    details=hf,
                    suggestion="Keys in git history are compromised! Rotate the credentials and rewrite history using 'git-filter-repo'.",
                )
            )

    return summary
