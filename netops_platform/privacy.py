"""Privacy and secret-pattern checks for public trees and release archives."""

from __future__ import annotations

import ipaddress
import os
import re
import subprocess
import stat
import tarfile
import zipfile
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable, Iterator


# Tool state that lives beside the source and never ships with it. Flagging
# these produces findings nobody can act on, which is how a scanner teaches
# people to skim past it.
SKIP_PARTS = {".git", ".venv", "node_modules", "__pycache__", ".pytest_cache",
              ".claude", ".vscode", ".idea", ".mypy_cache", ".ruff_cache"}
SKIP_ROOTS = {"dist", "build"}
SKIP_NAMES = {".privacy-denylist"}
MAX_TEXT_BYTES = 5_000_000
MAX_ARCHIVE_BYTES = 500_000_000
MAX_ARCHIVE_MEMBERS = 50_000
PATTERNS = {
    "absolute-user-path": re.compile(r"(?:/home/|/Users/)[A-Za-z0-9._-]+/|[A-Za-z]:\\Users\\[^\\\s]+\\"),
    "private-key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "cloud-token": re.compile(r"\b(?:ghp_|github_pat_|sk-[A-Za-z0-9]|AKIA)[A-Za-z0-9_-]{12,}"),
    "assigned-secret": re.compile(r"(?i)\b(?:password|passwd|token|secret|community|api[_-]?key)\s*[=:]\s*(['\"])(?!\s*(?:\$|none|null|empty|configured|redacted|replace|example|vault:|env:|file:))[^'\"\r\n]{8,}\1"),
}
IPV4_LITERAL = re.compile(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])")
RFC1918_NETWORKS = tuple(
    ipaddress.ip_network((address, prefix))
    for address, prefix in (
        (0x0A000000, 8),
        (0xAC100000, 12),
        (0xC0A80000, 16),
    )
)


@dataclass(frozen=True)
class PrivacyFinding:
    code: str
    path: str
    line: int
    detail: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class ArchiveScanError(ValueError):
    pass


def _denied_identifiers(extra: Iterable[str] = ()) -> list[str]:
    values = [value.strip() for value in extra if value.strip()]
    configured = os.environ.get("NETRUNE_PRIVACY_DENYLIST", os.environ.get("NETOPS_PRIVACY_DENYLIST", ""))
    values.extend(value.strip() for value in configured.split(",") if value.strip())
    path = os.environ.get("NETRUNE_PRIVACY_DENYLIST_FILE", os.environ.get("NETOPS_PRIVACY_DENYLIST_FILE", "")).strip()
    if path and Path(path).is_file():
        values.extend(line.strip() for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip() and not line.lstrip().startswith("#"))
    return sorted(set(values), key=str.lower)


def scan_text(path: str, text: str, denied: Iterable[str] = ()) -> list[PrivacyFinding]:
    findings: list[PrivacyFinding] = []
    denied_values = _denied_identifiers(denied)
    for line_number, line in enumerate(text.splitlines(), 1):
        for code, pattern in PATTERNS.items():
            match = pattern.search(line)
            if match:
                findings.append(PrivacyFinding(code, path, line_number, match.group(0)[:120]))
        for match in IPV4_LITERAL.finditer(line):
            try:
                address = ipaddress.ip_address(match.group(0))
            except ValueError:
                continue
            if any(address in network for network in RFC1918_NETWORKS):
                findings.append(PrivacyFinding("private-ip-literal", path, line_number, str(address)))
        lowered = line.lower()
        for value in denied_values:
            if value.lower() in lowered:
                findings.append(PrivacyFinding("denied-identifier", path, line_number, value))
    return findings


def scan_path(path: str, denied: Iterable[str] = ()) -> list[PrivacyFinding]:
    """Inspect a relative publication path without treating it as file content."""
    normalized = path.replace("\\", "/")
    findings: list[PrivacyFinding] = []
    absolute_match = PATTERNS["absolute-user-path"].search("/" + normalized.lstrip("/"))
    if absolute_match:
        findings.append(PrivacyFinding("absolute-user-path", path, 0, absolute_match.group(0)[:120]))
    cloud_match = PATTERNS["cloud-token"].search(normalized)
    if cloud_match:
        findings.append(PrivacyFinding("cloud-token", path, 0, cloud_match.group(0)[:120]))
    lowered = normalized.lower()
    for value in _denied_identifiers(denied):
        if value.lower() in lowered:
            findings.append(PrivacyFinding("denied-path-identifier", path, 0, value))
    return findings


def _skip_tree_path(relative: Path) -> bool:
    return (
        bool(relative.parts)
        and relative.parts[0] in SKIP_ROOTS
    ) or any(part in SKIP_PARTS for part in relative.parts)


def _tree_files(root: Path) -> Iterator[Path]:
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file() or path.name in SKIP_NAMES or _skip_tree_path(path.relative_to(root)):
            continue
        if path.stat().st_size <= MAX_TEXT_BYTES:
            yield path


def scan_tree(root: Path, denied: Iterable[str] = ()) -> list[PrivacyFinding]:
    root = Path(root)
    findings: list[PrivacyFinding] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if _skip_tree_path(relative):
            continue
        if path.is_symlink() or path.is_file():
            findings.extend(scan_path(relative.as_posix(), denied))
        if path.is_symlink():
            findings.append(PrivacyFinding("symbolic-link", relative.as_posix(), 0, "public trees cannot contain symbolic links"))
        elif path.is_file() and path.name not in SKIP_NAMES and path.stat().st_size > MAX_TEXT_BYTES:
            findings.append(PrivacyFinding("file-too-large-to-scan", relative.as_posix(), 0, "file exceeds privacy scan limit"))
    for path in _tree_files(root):
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        findings.extend(scan_text(path.relative_to(root).as_posix(), text, denied))
    return findings


def _safe_archive_name(name: str) -> bool:
    path = Path(name.replace("\\", "/"))
    return not path.is_absolute() and ".." not in path.parts and not re.match(r"^[A-Za-z]:", name)


def _archive_members(path: Path) -> Iterator[tuple[str, bytes]]:
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            members = archive.infolist()
            if len(members) > MAX_ARCHIVE_MEMBERS or sum(item.file_size for item in members) > MAX_ARCHIVE_BYTES:
                raise ArchiveScanError("archive exceeds member or expanded-size limits")
            for item in members:
                name = item.filename
                if not _safe_archive_name(name):
                    raise ArchiveScanError(f"unsafe archive member path: {name}")
                mode = (item.external_attr >> 16) & 0xFFFF
                if stat.S_ISLNK(mode):
                    raise ArchiveScanError(f"archive contains a symbolic link: {name}")
                if item.is_dir():
                    continue
                if item.file_size > MAX_TEXT_BYTES:
                    raise ArchiveScanError(f"archive member exceeds privacy scan limit: {name}")
                yield name, archive.read(item)
        return
    with tarfile.open(path, "r:*") as archive:
        members = archive.getmembers()
        if len(members) > MAX_ARCHIVE_MEMBERS or sum(member.size for member in members if member.isfile()) > MAX_ARCHIVE_BYTES:
            raise ArchiveScanError("archive exceeds member or expanded-size limits")
        for member in members:
            if not _safe_archive_name(member.name):
                raise ArchiveScanError(f"unsafe archive member path: {member.name}")
            if member.issym() or member.islnk():
                raise ArchiveScanError(f"archive contains a link: {member.name}")
            if not member.isfile():
                continue
            if member.size > MAX_TEXT_BYTES:
                raise ArchiveScanError(f"archive member exceeds privacy scan limit: {member.name}")
            stream = archive.extractfile(member)
            if stream:
                yield member.name, stream.read(MAX_TEXT_BYTES + 1)


def scan_archive(path: Path, denied: Iterable[str] = ()) -> list[PrivacyFinding]:
    findings: list[PrivacyFinding] = []
    try:
        for name, content in _archive_members(Path(path)):
            findings.extend(scan_path(name, denied))
            try:
                text = content.decode("utf-8")
            except UnicodeDecodeError:
                continue
            findings.extend(scan_text(f"{Path(path).name}:{name}", text, denied))
    except (ArchiveScanError, OSError, tarfile.TarError, zipfile.BadZipFile) as exc:
        findings.append(PrivacyFinding("archive-invalid", Path(path).name, 0, str(exc)))
    return findings


def scan_git_history(root: Path, denied: Iterable[str] = ()) -> list[PrivacyFinding]:
    """Scan committed blobs; intended for the clean public export, not private history."""
    root = Path(root)
    revisions = subprocess.run(
        ["git", "rev-list", "--all"], cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False
    )
    if revisions.returncode:
        return [PrivacyFinding("git-history-unavailable", ".git", 0, revisions.stderr.strip())]
    findings: list[PrivacyFinding] = []
    for revision in revisions.stdout.splitlines():
        names = subprocess.run(
            ["git", "ls-tree", "-rz", "--name-only", revision], cwd=root,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False,
        )
        for raw_name in names.stdout.split(b"\0"):
            if not raw_name:
                continue
            name = raw_name.decode("utf-8", errors="surrogateescape")
            for finding in scan_path(name, denied):
                findings.append(PrivacyFinding(
                    finding.code,
                    f"{revision[:12]}:{name}",
                    finding.line,
                    finding.detail,
                ))
            size = subprocess.run(
                ["git", "cat-file", "-s", f"{revision}:{name}"], cwd=root,
                text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False,
            )
            if size.returncode:
                continue
            try:
                blob_size = int(size.stdout.strip())
            except ValueError:
                continue
            if blob_size > MAX_TEXT_BYTES:
                findings.append(PrivacyFinding(
                    "git-blob-too-large-to-scan",
                    f"{revision[:12]}:{name}",
                    0,
                    "blob exceeds privacy scan limit",
                ))
                continue
            blob = subprocess.run(
                ["git", "show", f"{revision}:{name}"], cwd=root, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, check=False,
            )
            if blob.returncode:
                continue
            try:
                text = blob.stdout.decode("utf-8")
            except UnicodeDecodeError:
                continue
            findings.extend(scan_text(f"{revision[:12]}:{name}", text, denied))
    return findings
