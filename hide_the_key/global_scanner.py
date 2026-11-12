"""Full PC / Home directory global scanner for finding secret repositories."""

import os
import sys
import time
from typing import List, Dict, Set, Optional, Callable
from .constants import GLOBAL_SCAN_IGNORE_DIRS, SECRET_FILE_NAMES, SECRET_FILE_EXTENSIONS
from .scanner import scan_directory, ScanSummary
from .reporter import Colors

c = Colors()


class GlobalScanResult:
    def __init__(self, start_root: str):
        self.start_root = start_root
        self.discovered_dirs: List[str] = []
        self.summaries: List[ScanSummary] = []
        self.total_scanned_files: int = 0
        self.start_time: float = 0.0
        self.end_time: float = 0.0

    @property
    def total_critical(self) -> int:
        return sum(s.critical_count for s in self.summaries)

    @property
    def total_high(self) -> int:
        return sum(s.high_count for s in self.summaries)

    @property
    def total_medium(self) -> int:
        return sum(s.medium_count for s in self.summaries)

    @property
    def total_safe(self) -> int:
        return sum(s.safe_count for s in self.summaries)

    @property
    def duration_seconds(self) -> float:
        return max(0.0, self.end_time - self.start_time)


def discover_target_directories(
    root_path: str,
    progress_callback: Optional[Callable[[str, int], None]] = None,
    max_depth: int = 6,
) -> List[str]:
    """
    Rapidly traverse the filesystem under root_path to discover:
    1. Git repositories (.git directories)
    2. Non-git project directories that contain secret files (.env, *.key, etc.)
    """
    root_path = os.path.realpath(os.path.expanduser(root_path))
    discovered = []
    seen_dirs: Set[str] = set()

    for dirpath, dirnames, filenames in os.walk(root_path, followlinks=False):
        rel_to_root = os.path.relpath(dirpath, root_path)
        current_depth = 0 if rel_to_root == "." else rel_to_root.count(os.sep) + 1

        if current_depth > max_depth:
            dirnames.clear()
            continue

        # Filter out ignored directories
        dirnames[:] = [
            d for d in dirnames
            if d not in GLOBAL_SCAN_IGNORE_DIRS
            and not (d.startswith(".") and d != ".git")
        ]

        # Case 1: Git repository found
        if ".git" in dirnames:
            if dirpath == root_path:
                # If root_path itself happens to be a git repo (e.g. ~/ dotfiles),
                # do NOT stop recursion; just remove .git and keep discovering child projects!
                dirnames.remove(".git")
            else:
                if dirpath not in seen_dirs:
                    seen_dirs.add(dirpath)
                    discovered.append(dirpath)
                    if progress_callback:
                        progress_callback(dirpath, len(discovered))
                # Stop recursing inside this Git repository (it will be scanned as a single unit)
                dirnames.clear()
                continue

        # Case 2: Non-git directory containing potential secret files
        if dirpath != root_path:
            has_secret_file = False
            for fname in filenames:
                lower = fname.lower()
                _, ext = os.path.splitext(lower)
                if lower in SECRET_FILE_NAMES or ext in SECRET_FILE_EXTENSIONS or lower.startswith(".env"):
                    has_secret_file = True
                    break

            if has_secret_file and dirpath not in seen_dirs:
                seen_dirs.add(dirpath)
                discovered.append(dirpath)
                if progress_callback:
                    progress_callback(dirpath, len(discovered))

    return discovered


def run_global_scan(
    root_path: str = "~",
    check_history: bool = False,
    show_progress: bool = True,
) -> GlobalScanResult:
    """
    Perform a complete scan across the entire user environment or system.
    1. Fast discovery of repositories and sensitive folders.
    2. Deep audit of each target for unignored keys and code leaks.
    """
    resolved_root = os.path.realpath(os.path.expanduser(root_path))
    result = GlobalScanResult(resolved_root)
    result.start_time = time.time()

    if show_progress:
        print(f"\n{c.CYAN}{c.BOLD}⚡ Step 1: Discovering repositories and secret directories across {resolved_root}...{c.RESET}")

    def on_discover(found_path: str, count: int):
        if show_progress and sys.stdout.isatty():
            short_path = found_path if len(found_path) < 60 else "..." + found_path[-55:]
            sys.stdout.write(f"\r  🔍 Found {c.BOLD}{count}{c.RESET} targets | Scanning: {short_path:<60}")
            sys.stdout.flush()

    # Check if root_path itself has direct secret files (e.g. ~/.env)
    root_has_secret = False
    try:
        for fname in os.listdir(resolved_root):
            lower = fname.lower()
            _, ext = os.path.splitext(lower)
            if lower in SECRET_FILE_NAMES or ext in SECRET_FILE_EXTENSIONS or lower.startswith(".env"):
                root_has_secret = True
                break
    except Exception:
        pass

    # Step 1: Discovery
    discovered = discover_target_directories(resolved_root, progress_callback=on_discover)
    if root_has_secret and resolved_root not in discovered:
        # Check files directly in root
        discovered.insert(0, resolved_root)

    result.discovered_dirs = discovered

    if show_progress and sys.stdout.isatty():
        sys.stdout.write("\r" + " " * 80 + "\r")
        print(f"  ✅ Discovery complete! Found {c.BOLD}{len(discovered)}{c.RESET} directories to audit.\n")
    elif show_progress:
        print(f"  ✅ Found {len(discovered)} directories to audit.\n")

    # Step 2: Deep audit of each discovered target
    if show_progress:
        print(f"{c.CYAN}{c.BOLD}🛡️  Step 2: Auditing .gitignore & scanning code for leaks in each directory...{c.RESET}")

    for idx, target_dir in enumerate(discovered, start=1):
        if show_progress and sys.stdout.isatty():
            short_path = target_dir if len(target_dir) < 60 else "..." + target_dir[-55:]
            sys.stdout.write(f"\r  [{idx}/{len(discovered)}] Auditing: {short_path:<60}")
            sys.stdout.flush()

        try:
            # If target_dir is not a git repo, only scan its shallow direct files
            # to avoid freezing on massive folders like Downloads/ or Documents/
            is_git = os.path.isdir(os.path.join(target_dir, ".git"))
            is_root = (target_dir == resolved_root)
            should_be_shallow = is_root or (not is_git)

            summary = scan_directory(
                target_dir,
                check_staged=True,
                check_history=check_history,
                shallow_only=should_be_shallow,
            )
            result.summaries.append(summary)
            result.total_scanned_files += summary.scanned_files_count
        except Exception:
            pass

    if show_progress and sys.stdout.isatty():
        sys.stdout.write("\r" + " " * 80 + "\r")

    result.end_time = time.time()
    return result
