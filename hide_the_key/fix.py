"""Automated fixes for unignored or tracked secret files."""

import os
from typing import List, Tuple
from .git_checker import run_git


def add_to_gitignore(repo_root: str, pattern: str) -> bool:
    """Add a pattern to the repository's root .gitignore file if not present."""
    gitignore_path = os.path.join(repo_root, ".gitignore")
    lines = []
    if os.path.exists(gitignore_path):
        try:
            with open(gitignore_path, "r", encoding="utf-8") as f:
                lines = [line.strip() for line in f.readlines()]
        except Exception:
            pass

    # Check if already present
    pattern_clean = pattern.strip()
    if pattern_clean in lines or f"/{pattern_clean}" in lines:
        return False

    try:
        with open(gitignore_path, "a", encoding="utf-8") as f:
            if lines and lines[-1] != "":
                f.write("\n")
            f.write(f"{pattern_clean}\n")
        return True
    except Exception as e:
        print(f"Failed to write to {gitignore_path}: {e}")
        return False


def untrack_file(repo_root: str, rel_path: str) -> Tuple[bool, str]:
    """
    Remove a file from git index without deleting it locally (git rm --cached).
    """
    code, out, err = run_git(["rm", "--cached", rel_path], cwd=repo_root)
    if code == 0:
        return True, out
    return False, err
