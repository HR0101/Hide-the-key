"""Git operations and .gitignore tracking checks."""

import os
import subprocess
from typing import Optional, Tuple, List, Dict


def run_git(args: List[str], cwd: str) -> Tuple[int, str, str]:
    """Run a git command in the specified directory."""
    try:
        proc = subprocess.run(
            ["git"] + args,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except FileNotFoundError:
        return -1, "", "git command not found"
    except Exception as e:
        return -1, "", str(e)


def find_git_root(path: str) -> Optional[str]:
    """Find the root directory of the git repository containing path."""
    target_dir = os.path.realpath(path if os.path.isdir(path) else os.path.dirname(path))
    code, out, _ = run_git(["rev-parse", "--show-toplevel"], cwd=target_dir)
    if code == 0 and out:
        return os.path.realpath(out)
    return None


def is_git_repo(path: str) -> bool:
    """Check if the given directory or path is inside a git work tree."""
    return find_git_root(path) is not None


def check_git_ignore(repo_root: str, file_rel_path: str) -> Tuple[bool, Optional[str]]:
    """
    Check if a file is ignored by git.
    Returns (is_ignored, ignore_rule_source).
    e.g., (True, ".gitignore:12:*.env")
    """
    code, out, _ = run_git(["check-ignore", "-v", file_rel_path], cwd=repo_root)
    if code == 0 and out:
        # out looks like: ".gitignore:3:.env	.env"
        parts = out.split("\t")
        rule = parts[0] if parts else out
        return True, rule
    return False, None


def is_file_tracked(repo_root: str, file_rel_path: str) -> bool:
    """
    Check if a file is currently tracked by git (committed or in index).
    Returns True if tracked.
    """
    code, _, _ = run_git(["ls-files", "--error-unmatch", file_rel_path], cwd=repo_root)
    return code == 0


def is_file_staged(repo_root: str, file_rel_path: str) -> bool:
    """Check if a file has changes staged in git index."""
    code, out, _ = run_git(["diff", "--name-only", "--cached"], cwd=repo_root)
    if code == 0:
        staged_files = set(out.splitlines())
        return file_rel_path in staged_files
    return False


def get_git_status_info(repo_root: str, file_rel_path: str) -> Dict[str, any]:
    """
    Get detailed git status for a specific file.
    Returns:
      {
        'is_tracked': bool,
        'is_ignored': bool,
        'is_staged': bool,
        'ignore_rule': Optional[str],
      }
    """
    tracked = is_file_tracked(repo_root, file_rel_path)
    ignored, rule = check_git_ignore(repo_root, file_rel_path)
    staged = is_file_staged(repo_root, file_rel_path)

    return {
        "is_tracked": tracked,
        "is_ignored": ignored,
        "is_staged": staged,
        "ignore_rule": rule,
    }


def get_staged_diff(repo_root: str) -> str:
    """Get the full diff of staged changes."""
    code, out, _ = run_git(["diff", "--cached", "-U1"], cwd=repo_root)
    if code == 0:
        return out
    return ""


def check_git_history_for_secrets(repo_root: str, max_commits: int = 50) -> List[Dict[str, str]]:
    """
    Check recent git commit history for sensitive filenames ever added.
    Returns list of dicts: [{'commit': 'abc1234', 'file': '.env', 'author': '...'}]
    """
    from .constants import SECRET_FILE_NAMES, SECRET_FILE_EXTENSIONS
    
    code, out, _ = run_git(
        ["log", f"-n{max_commits}", "--name-only", "--pretty=format:COMMIT:%h|%an|%s", "--diff-filter=A"],
        cwd=repo_root,
    )
    if code != 0 or not out:
        return []

    findings = []
    current_commit_info = {}

    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("COMMIT:"):
            parts = line[7:].split("|", 2)
            current_commit_info = {
                "hash": parts[0] if len(parts) > 0 else "",
                "author": parts[1] if len(parts) > 1 else "",
                "subject": parts[2] if len(parts) > 2 else "",
            }
            continue

        base = os.path.basename(line).lower()
        _, ext = os.path.splitext(base)

        if base in SECRET_FILE_NAMES or ext in SECRET_FILE_EXTENSIONS or ".env" in base:
            # Found historical secret file addition
            findings.append({
                "commit_hash": current_commit_info.get("hash", ""),
                "author": current_commit_info.get("author", ""),
                "subject": current_commit_info.get("subject", ""),
                "file": line,
            })

    return findings


def find_all_git_repos(root_dir: str, max_depth: int = 4) -> List[str]:
    """
    Find all git repositories located under root_dir up to max_depth.
    Useful for sweeping a developer's workspace or home directory.
    """
    repos = []
    root_dir = os.path.realpath(root_dir)

    for dirpath, dirnames, _ in os.walk(root_dir):
        # Calculate current depth relative to root_dir
        rel_depth = dirpath[len(root_dir):].count(os.sep)
        if rel_depth > max_depth:
            dirnames.clear()
            continue

        if ".git" in dirnames:
            repos.append(dirpath)
            # Do not search submodules/nested dirs inside this repo
            dirnames.remove(".git")

    return repos
