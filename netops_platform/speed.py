#!/usr/bin/env python3
"""Secure speedtest-cli backend used by NetOps diagnostics.

The distro speedtest-cli module is retained because it is already deployed on
the operator host.  This wrapper adds structured output and, on WSL, combines
the Linux CA bundle with certificates trusted by Windows.  Certificate and
hostname verification remain enabled.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import ssl
import subprocess
import sys
import tempfile
from typing import Any, Dict, Iterator, List, Optional, Tuple


def _is_wsl() -> bool:
    with contextlib.suppress(OSError):
        return "microsoft" in Path("/proc/version").read_text(errors="ignore").lower()
    return False


def _powershell() -> Optional[str]:
    candidates = (
        shutil.which("powershell.exe"),
        "/mnt/c/WINDOWS/System32/WindowsPowerShell/v1.0/powershell.exe",
    )
    return next((str(item) for item in candidates if item and Path(item).exists()), None)


def _windows_certificates() -> str:
    executable = _powershell()
    if not executable:
        raise RuntimeError("Windows PowerShell is unavailable")
    script = r"""
$ErrorActionPreference = 'Stop'
Get-ChildItem Cert:\LocalMachine\Root, Cert:\LocalMachine\CA | ForEach-Object {
  '-----BEGIN CERTIFICATE-----'
  [Convert]::ToBase64String($_.RawData, [Base64FormattingOptions]::InsertLineBreaks)
  '-----END CERTIFICATE-----'
}
"""
    completed = subprocess.run(
        [executable, "-NoProfile", "-NonInteractive", "-Command", script],
        check=False,
        capture_output=True,
        text=True,
        timeout=45,
    )
    if completed.returncode or "BEGIN CERTIFICATE" not in completed.stdout:
        detail = (completed.stderr or completed.stdout or "certificate export failed").strip()
        raise RuntimeError(detail[:500])
    return completed.stdout.replace("\r", "")


def _ca_bundle(explicit: str = "") -> Tuple[Optional[str], str, Optional[str]]:
    """Return bundle path, human-readable source, and temporary path."""
    requested = explicit or os.environ.get("NETOPS_SPEED_CA_FILE", "")
    if requested:
        path = Path(requested).expanduser()
        if not path.is_file():
            raise RuntimeError(f"CA bundle does not exist: {path}")
        return str(path), "explicit", None

    env_bundle = os.environ.get("SSL_CERT_FILE", "")
    if env_bundle and Path(env_bundle).is_file():
        return env_bundle, "SSL_CERT_FILE", None

    defaults = ssl.get_default_verify_paths()
    linux_bundle = defaults.cafile if defaults.cafile and Path(defaults.cafile).is_file() else ""
    if not _is_wsl():
        return linux_bundle or None, "linux-system", None

    try:
        windows_pem = _windows_certificates()
    except Exception as exc:
        if linux_bundle:
            return linux_bundle, f"linux-system (Windows CA import unavailable: {exc})", None
        raise

    handle = tempfile.NamedTemporaryFile(
        mode="w", prefix="netops-speed-ca-", suffix=".pem", delete=False
    )
    try:
        if linux_bundle:
            handle.write(Path(linux_bundle).read_text(errors="ignore"))
            handle.write("\n")
        handle.write(windows_pem)
    finally:
        handle.close()
    return handle.name, "linux+windows-trusted", handle.name


@contextlib.contextmanager
def _verified_tls(ca_file: str = "") -> Iterator[Dict[str, Any]]:
    bundle, source, temporary = _ca_bundle(ca_file)
    old_env = os.environ.get("SSL_CERT_FILE")
    original_default = ssl.create_default_context
    original_https = ssl._create_default_https_context

    def compatible_context(*args: Any, **kwargs: Any) -> ssl.SSLContext:
        context = original_default(*args, **kwargs)
        if bundle:
            context.load_verify_locations(cafile=bundle)
        # Python 3.14 enables strict RFC 5280 checks. Some enterprise roots in
        # otherwise trusted Windows stores predate AKI requirements. Clear only
        # strict mode; chain validation and hostname checking stay mandatory.
        if hasattr(ssl, "VERIFY_X509_STRICT"):
            context.verify_flags &= ~ssl.VERIFY_X509_STRICT
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        return context

    if bundle:
        os.environ["SSL_CERT_FILE"] = bundle
    ssl.create_default_context = compatible_context
    ssl._create_default_https_context = compatible_context
    try:
        yield {
            "verified": True,
            "hostname_check": True,
            "source": source,
            "ca_file": bundle or "system default",
        }
    finally:
        ssl.create_default_context = original_default
        ssl._create_default_https_context = original_https
        if old_env is None:
            os.environ.pop("SSL_CERT_FILE", None)
        else:
            os.environ["SSL_CERT_FILE"] = old_env
        if temporary:
            with contextlib.suppress(OSError):
                Path(temporary).unlink()


def _server_payload(server: Dict[str, Any]) -> Dict[str, Any]:
    def number(value: Any) -> Optional[float]:
        try:
            return round(float(value), 3)
        except (TypeError, ValueError):
            return None

    return {
        "id": int(server.get("id") or 0),
        "host": str(server.get("host") or ""),
        "sponsor": str(server.get("sponsor") or "Unknown"),
        "name": str(server.get("name") or "Unknown"),
        "country": str(server.get("country") or ""),
        "distance_km": number(server.get("d")),
        "latency_ms": number(server.get("latency")),
    }


def _speedtest(timeout: int, bind: str = "") -> Any:
    try:
        import speedtest
    except ImportError as exc:
        raise RuntimeError("Python speedtest-cli module is not installed") from exc
    return speedtest.Speedtest(
        source_address=bind or None,
        timeout=timeout,
        secure=True,
    )


def list_servers(limit: int, timeout: int, bind: str, ca_file: str) -> Dict[str, Any]:
    with _verified_tls(ca_file) as trust:
        client = _speedtest(timeout, bind)
        servers: List[Dict[str, Any]] = client.get_closest_servers(limit=limit)
        return {
            "ok": len(servers) > 0,
            "backend": "speedtest-cli-python",
            "scope": "netops-host-to-internet",
            "tls_trust": trust,
            "servers": [_server_payload(server) for server in servers],
        }


def run_server(server_id: int, direction: str, timeout: int, bind: str, ca_file: str) -> Dict[str, Any]:
    with _verified_tls(ca_file) as trust:
        client = _speedtest(timeout, bind)
        client.get_servers([server_id])
        server = client.get_best_server()
        if int(server.get("id") or 0) != server_id:
            raise RuntimeError(f"requested server {server_id} was not selected")
        bits_per_second = client.download() if direction == "download" else client.upload(pre_allocate=True)
        result = client.results.dict()
        transferred = result.get("bytes_received" if direction == "download" else "bytes_sent") or 0
        if float(bits_per_second or 0) <= 0 or int(transferred or 0) <= 0:
            raise RuntimeError(f"speedtest returned zero-transfer result for {direction}")
        return {
            "ok": True,
            "backend": "speedtest-cli-python",
            "scope": "netops-host-to-internet",
            "direction": direction,
            "bits_per_second": round(float(bits_per_second), 3),
            "megabits_per_second": round(float(bits_per_second) / 1_000_000, 3),
            "bytes": int(transferred),
            "server": _server_payload(server),
            "client": result.get("client") or {},
            "tls_trust": trust,
        }


def _server_ping_host(host: str) -> str:
    value = str(host or "").strip()
    if value.startswith("[") and "]" in value:
        return value[1:value.index("]")]
    if value.count(":") == 1:
        return value.rsplit(":", 1)[0]
    return value


def _ping_metrics(output: str) -> Dict[str, Any]:
    samples = [float(value) for value in re.findall(r"time[=<]([0-9.]+)", output or "", re.I)]
    loss_match = re.search(r"(\d+(?:\.\d+)?)%\s+packet loss", output or "", re.I)
    jitter = 0.0
    if len(samples) > 1:
        jitter = sum(abs(samples[index] - samples[index - 1]) for index in range(1, len(samples))) / (len(samples) - 1)
    return {
        "available": bool(samples),
        "avg": round(sum(samples) / len(samples), 3) if samples else None,
        "jitter": round(jitter, 3) if samples else None,
        "packet_loss_pct": round(float(loss_match.group(1)), 3) if loss_match else (0.0 if samples else None),
        "samples": len(samples),
    }


def _stop_ping(process: subprocess.Popen[Any]) -> None:
    if process.poll() is not None:
        return
    with contextlib.suppress(ProcessLookupError, PermissionError):
        process.send_signal(signal.SIGINT)
    try:
        process.wait(timeout=2)
        return
    except subprocess.TimeoutExpired:
        pass
    with contextlib.suppress(ProcessLookupError, PermissionError):
        process.terminate()
    try:
        process.wait(timeout=2)
        return
    except subprocess.TimeoutExpired:
        pass
    with contextlib.suppress(ProcessLookupError, PermissionError):
        process.kill()
    with contextlib.suppress(subprocess.TimeoutExpired):
        process.wait(timeout=2)


def _measure_loaded_latency(host: str, action: Any) -> Tuple[Any, Dict[str, Any]]:
    """Run one transfer with an independent ICMP stream for loaded latency."""
    ping_host = _server_ping_host(host)
    with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as output:
        try:
            process = subprocess.Popen(
                ["ping", "-n", "-i", "0.2", "-W", "2", ping_host],
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.DEVNULL,
                text=True,
            )
        except OSError:
            return action(), _ping_metrics("")
        try:
            result = action()
        finally:
            _stop_ping(process)
        output.seek(0)
        return result, _ping_metrics(output.read())


def _direction_payload(
    direction: str,
    bits_per_second: Any,
    result: Dict[str, Any],
    server: Dict[str, Any],
    loaded_latency: Dict[str, Any],
) -> Dict[str, Any]:
    transferred = result.get("bytes_received" if direction == "download" else "bytes_sent") or 0
    if float(bits_per_second or 0) <= 0 or int(transferred or 0) <= 0:
        raise RuntimeError(f"speedtest returned zero-transfer result for {direction}")
    return {
        "direction": direction,
        "bits_per_second": round(float(bits_per_second), 3),
        "megabits_per_second": round(float(bits_per_second) / 1_000_000, 3),
        "bytes": int(transferred),
        "server": _server_payload(server),
        "client": result.get("client") or {},
        "loaded_latency_ms": loaded_latency,
    }


def run_server_pair(server_id: int, timeout: int, bind: str, ca_file: str) -> Dict[str, Any]:
    """Measure both directions with one verified, server-pinned client session."""
    with _verified_tls(ca_file) as trust:
        client = _speedtest(timeout, bind)
        client.get_servers([server_id])
        server = client.get_best_server()
        if int(server.get("id") or 0) != server_id:
            raise RuntimeError(f"requested server {server_id} was not selected")

        upload_bps, upload_latency = _measure_loaded_latency(
            str(server.get("host") or ""), lambda: client.upload(pre_allocate=True)
        )
        upload_result = client.results.dict()
        download_bps, download_latency = _measure_loaded_latency(
            str(server.get("host") or ""), client.download
        )
        download_result = client.results.dict()

        return {
            "ok": True,
            "backend": "speedtest-cli-python",
            "scope": "netops-host-to-internet",
            "measurement_order": ["upload", "download"],
            "server": _server_payload(server),
            "directions": {
                "upload": _direction_payload("upload", upload_bps, upload_result, server, upload_latency),
                "download": _direction_payload("download", download_bps, download_result, server, download_latency),
            },
            "tls_trust": trust,
        }


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description="Secure structured backend for NetOps Internet speed diagnostics")
    root.add_argument("--timeout", type=int, default=30, help="per-request timeout in seconds")
    root.add_argument("--bind", default="", help="optional source IP address")
    root.add_argument("--ca-file", default="", help="additional trusted PEM bundle")
    commands = root.add_subparsers(dest="command", required=True)
    servers = commands.add_parser("servers", help="list nearby servers")
    servers.add_argument("--limit", type=int, default=3)
    run = commands.add_parser("run", help="run one direction against one server")
    run.add_argument("--server", type=int, required=True)
    run.add_argument("--direction", choices=("download", "upload", "both"), required=True)
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        if args.timeout < 5 or args.timeout > 120:
            raise ValueError("--timeout must be between 5 and 120 seconds")
        if args.command == "servers":
            if args.limit < 1 or args.limit > 20:
                raise ValueError("--limit must be between 1 and 20")
            payload = list_servers(args.limit, args.timeout, args.bind, args.ca_file)
        elif args.direction == "both":
            payload = run_server_pair(args.server, args.timeout, args.bind, args.ca_file)
        else:
            payload = run_server(args.server, args.direction, args.timeout, args.bind, args.ca_file)
        print(json.dumps(payload, sort_keys=True))
        return 0 if payload.get("ok") else 1
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc), "type": type(exc).__name__}, sort_keys=True))
        return 1


if __name__ == "__main__":
    sys.exit(main())
