#!/usr/bin/env python3
"""Create a history-free public repository without touching the private clone."""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
from pathlib import Path

from netops_platform.privacy import scan_git_history, scan_tree


EXCLUDED = {
    "ai/logs/agent_runs.jsonl",
    "ui-ux-design-guide.md",
}

PUBLIC_COMMIT_SUBJECT = "Public beta source release"
PUBLIC_COMMIT_BODY = (
    "NetOps Platform v8.5 public beta.\n\n"
    "This repository was generated from the project's publication-safe source "
    "export. Historical development commits are intentionally not included "
    "because the project was originally developed in a private engineering "
    "repository."
)


# Markdown between these markers is for the private repository only (its own
# clone URL, the operator's move-to-a-new-machine notes) and never exported.
PRIVATE_START = "<!-- private-only:start -->"
PRIVATE_END = "<!-- private-only:end -->"


def strip_private(text: str, relative: str) -> str:
    if text.count(PRIVATE_START) != text.count(PRIVATE_END):
        raise RuntimeError(f"public export refuses unbalanced private-only markers: {relative}")
    return re.sub(re.escape(PRIVATE_START) + r".*?" + re.escape(PRIVATE_END) + r"\n*", "", text, flags=re.S)


def repository_files(source: Path, include_untracked: bool = False) -> list[str]:
    commands = [["git", "ls-files", "-z", "--cached"]]
    if include_untracked:
        commands.append(["git", "ls-files", "-z", "--others", "--exclude-standard"])
    paths: set[str] = set()
    for command in commands:
        listed = subprocess.run(command, cwd=source, stdout=subprocess.PIPE, check=True).stdout.split(b"\0")
        paths.update(
            raw.decode("utf-8", errors="surrogateescape")
            for raw in listed
            if raw
        )
    return sorted(paths)


def run(command: list[str], cwd: Path) -> None:
    process = subprocess.run(command, cwd=cwd, check=False)
    if process.returncode:
        raise RuntimeError("command failed: " + " ".join(command))


def stage_export(destination: Path) -> None:
    # The copied set is already bounded and privacy-scanned. Force-add it so
    # source-tracked build assets remain tracked in the clean baseline even
    # when a broad ignore pattern exists for future local output.
    run(["git", "add", "--force", "."], destination)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("destination", type=Path)
    parser.add_argument("--maintainer-name", default="NetOps maintainers")
    parser.add_argument("--maintainer-email", default="public-beta@example.invalid")
    parser.add_argument("--denylist", type=Path, help="Private newline-separated identifiers; defaults to SOURCE/.privacy-denylist")
    parser.add_argument("--include-untracked", action="store_true", help="Also copy non-ignored untracked files; off by default")
    parser.add_argument("--no-commit", action="store_true")
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[1]
    denylist = args.denylist or (source / ".privacy-denylist")
    denied = []
    if denylist.is_file():
        denied = [line.strip() for line in denylist.read_text(encoding="utf-8").splitlines() if line.strip() and not line.lstrip().startswith("#")]
    destination = args.destination.expanduser().resolve()
    if destination == source or source in destination.parents:
        parser.error("destination must be outside the private source tree")
    if destination.exists() and (not destination.is_dir() or any(destination.iterdir())):
        parser.error("destination must not exist or must be an empty directory")
    destination.mkdir(parents=True, exist_ok=True)
    for relative in repository_files(source, args.include_untracked):
        relative_path = Path(relative)
        if relative_path.is_absolute() or ".." in relative_path.parts:
            raise RuntimeError(f"public export refuses unsafe repository path: {relative}")
        if relative in EXCLUDED or relative.startswith(("legacy-local/", ".private/")):
            continue
        source_path = source / relative_path
        if source_path.is_symlink():
            raise RuntimeError(f"public export refuses tracked symbolic links: {relative}")
        if not source_path.is_file():
            raise RuntimeError(f"public export refuses non-file repository entry: {relative}")
        output = destination / relative_path
        output.parent.mkdir(parents=True, exist_ok=True)
        if relative.endswith(".md"):
            output.write_text(strip_private(source_path.read_text(encoding="utf-8"), relative), encoding="utf-8")
            shutil.copystat(source_path, output)
        else:
            shutil.copy2(source_path, output)
    findings = scan_tree(destination, denied)
    if findings:
        for finding in findings:
            print(f"{finding.code}: {finding.path}:{finding.line}: {finding.detail}")
        print("Public export was not initialized because privacy checks failed.")
        return 1
    run(["git", "init", "--initial-branch=main"], destination)
    run(["git", "config", "user.name", args.maintainer_name], destination)
    run(["git", "config", "user.email", args.maintainer_email], destination)
    run(["git", "config", "commit.gpgsign", "false"], destination)
    run(["git", "config", "tag.gpgsign", "false"], destination)
    if not args.no_commit:
        stage_export(destination)
        run(["git", "commit", "-m", PUBLIC_COMMIT_SUBJECT, "-m", PUBLIC_COMMIT_BODY], destination)
        history_findings = scan_git_history(destination, denied)
        if history_findings:
            for finding in history_findings:
                print(f"{finding.code}: {finding.path}:{finding.line}: {finding.detail}")
            raise RuntimeError("clean public Git history failed privacy validation")
    print(f"Clean public export created at {destination}")
    print("No remote was configured and the private repository was not modified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
