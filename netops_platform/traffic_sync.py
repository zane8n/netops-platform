"""Moving readings from a remote poller to this machine.

A poller sits on the monitored network because that is where SNMP and ICMP have
to originate from. The laptop that reads the results does not, and moves. The
two are joined over SSH, which this project already treats as an audited channel
(ADR 0004), rather than by opening anything new on the poller.

What crosses the link is raw stored rows, not scraped metrics. Scraping would
hand back gauges that have already had their rate computed, and the counters
behind them were never retained; pulling rows keeps whatever the poller actually
recorded. Every row is already stamped with the collector that took it, so a
merge cannot make one collector's reading look like another's.
"""

from __future__ import annotations

import json
import re
import shlex
import subprocess
import time
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional, Sequence

#: Bumped when the wire shape changes in a way an older reader cannot handle.
EXPORT_SCHEMA = 1

#: Rows carried by an export, in the order a merge must apply them. The
#: envelope field is "record" rather than "kind" because a watch row has a
#: kind of its own -- interface or icmp -- and would overwrite it.
EXPORT_RECORD_FIELD = "record"
EXPORT_RECORDS = ("meta", "watch", "sample", "counter")

SAMPLE_COLUMNS = ("watch_id", "observed_at", "metric", "value", "unit", "status",
                  "collector", "raw_json")
COUNTER_COLUMNS = ("watch_id", "counter", "observed_at", "value", "collector")
WATCH_COLUMNS = ("watch_id", "kind", "device_ip", "device_name", "interface_name", "target",
                 "label", "interval_seconds", "enabled", "added_at", "added_by", "notes",
                 "ifindex", "ifname", "display_name")


class RemoteError(RuntimeError):
    """A remote command could not be run, or answered with something unusable."""


# ssh reads any argument that starts with a dash as an option, and one of its
# options runs a local command. A host or user field is neither trusted nor
# quoted away by argument lists, so both are checked against what a real
# destination can look like before they are ever placed in an argv.
HOST_RE = re.compile(r"\A(?!-)[A-Za-z0-9._-]{1,253}\Z|\A\[[0-9A-Fa-f:.]{2,45}\]\Z|\A[0-9A-Fa-f:]{2,45}\Z")
SSH_USER_RE = re.compile(r"\A(?!-)[A-Za-z0-9._-]{1,32}\Z")


def check_destination(host: str, ssh_user: str = "") -> None:
    """Refuse a host or user that ssh would read as an option."""
    if not HOST_RE.match(str(host or "")):
        raise ValueError(
            f"'{host}' is not a usable host. Give a hostname or an IP address; a value starting "
            "with '-' would be read by ssh as an option rather than a destination.")
    if ssh_user and not SSH_USER_RE.match(str(ssh_user)):
        raise ValueError(
            f"'{ssh_user}' is not a usable SSH user name.")


# ---------------------------------------------------------------------------
# Export: what a poller hands over
# ---------------------------------------------------------------------------

def export_rows(monitor: Any, since: int, until: int = 0,
                collector: str = "") -> Iterator[Dict[str, Any]]:
    """Every row this collector recorded in the window, newest last.

    Only this collector's own readings are emitted. A poller that has itself
    pulled from somewhere else does not pass that data on: each collector
    answers for what it measured, and nothing else.
    """
    owner = collector or monitor.collector_id()
    end = int(until or time.time())
    yield {
        "record": "meta",
        "schema": EXPORT_SCHEMA,
        "collector": owner,
        "since": int(since),
        "until": end,
        "generated_at": int(time.time()),
    }

    watch_ids: List[str] = []
    for watch in monitor.list_watches():
        if not monitor.owns(watch):
            continue
        watch_ids.append(str(watch["watch_id"]))
        yield {"record": "watch", **{column: watch.get(column) for column in WATCH_COLUMNS}}

    if not watch_ids:
        return
    placeholders = ",".join("?" * len(watch_ids))
    for row in monitor.state.rows(
        f"SELECT {','.join(SAMPLE_COLUMNS)} FROM traffic_samples"
        f" WHERE collector=? AND observed_at>? AND observed_at<=? AND watch_id IN ({placeholders})"
        " ORDER BY observed_at, id",
        (owner, int(since), end, *watch_ids),
    ):
        yield {"record": "sample", **{column: row[column] for column in SAMPLE_COLUMNS}}

    for row in monitor.state.rows(
        f"SELECT {','.join(COUNTER_COLUMNS)} FROM traffic_counters"
        f" WHERE collector=? AND watch_id IN ({placeholders})",
        (owner, *watch_ids),
    ):
        yield {"record": "counter", **{column: row[column] for column in COUNTER_COLUMNS}}


def render_jsonl(rows: Iterable[Mapping[str, Any]]) -> Iterator[str]:
    for row in rows:
        yield json.dumps(row, separators=(",", ":"), sort_keys=True)


def parse_jsonl(text: str) -> List[Dict[str, Any]]:
    """Parse an export, refusing anything that is not one.

    A remote command that fails often still prints something on stdout, and
    treating that as an empty export would silently record a successful pull of
    nothing.
    """
    rows: List[Dict[str, Any]] = []
    for number, line in enumerate(str(text or "").splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
        except ValueError as exc:
            raise RemoteError(f"line {number} of the export is not JSON: {line[:80]}") from exc
        if not isinstance(parsed, dict) or parsed.get("record") not in EXPORT_RECORDS:
            raise RemoteError(f"line {number} of the export is not a known row: {line[:80]}")
        rows.append(parsed)
    if not rows:
        raise RemoteError("the remote returned no export at all")
    if rows[0].get("record") != "meta":
        raise RemoteError("the export does not start with its metadata line")
    schema = int(rows[0].get("schema") or 0)
    if schema > EXPORT_SCHEMA:
        raise RemoteError(
            f"the remote speaks export schema {schema} and this install understands {EXPORT_SCHEMA};"
            " upgrade netrune here")
    return rows


# ---------------------------------------------------------------------------
# Remotes
# ---------------------------------------------------------------------------

class RemoteStore:
    """Where the pollers are and how to reach them."""

    def __init__(self, state: Any) -> None:
        self.state = state

    def add(self, name: str, host: str, ssh_user: str = "", ssh_port: int = 0,
            profile: str = "", actor: str = "", notes: str = "") -> Dict[str, Any]:
        clean = str(name or "").strip()
        if not clean or not clean.replace("-", "").replace("_", "").isalnum():
            raise ValueError("a remote name may contain letters, digits, dashes, and underscores")
        if not str(host or "").strip():
            raise ValueError("a remote needs a host")
        check_destination(str(host).strip(), str(ssh_user or ""))
        self.state.execute(
            "INSERT INTO traffic_remotes(name,host,ssh_user,ssh_port,profile,collector_id,"
            "added_at,added_by,last_pull_at,last_sample_at,notes)"
            " VALUES(?,?,?,?,?,'',?,?,0,0,?)"
            " ON CONFLICT(name) DO UPDATE SET host=excluded.host, ssh_user=excluded.ssh_user,"
            " ssh_port=excluded.ssh_port, profile=excluded.profile, notes=excluded.notes",
            (clean, str(host).strip(), str(ssh_user or ""), int(ssh_port or 0),
             str(profile or ""), int(time.time()), str(actor or ""), str(notes or "")),
        )
        return self.get(clean) or {}

    def get(self, name: str) -> Optional[Dict[str, Any]]:
        return self.state.one("SELECT * FROM traffic_remotes WHERE name=?", (str(name or "").strip(),))

    def list(self) -> List[Dict[str, Any]]:
        return self.state.rows("SELECT * FROM traffic_remotes ORDER BY name")

    def remove(self, name: str) -> bool:
        if not self.get(name):
            return False
        self.state.execute("DELETE FROM traffic_remotes WHERE name=?", (str(name).strip(),))
        return True

    def record_pull(self, name: str, collector_id: str, newest_sample: int) -> None:
        self.state.execute(
            "UPDATE traffic_remotes SET collector_id=?, last_pull_at=?,"
            " last_sample_at=MAX(COALESCE(last_sample_at,0),?) WHERE name=?",
            (str(collector_id or ""), int(time.time()), int(newest_sample or 0), str(name).strip()),
        )


def ssh_command(remote: Mapping[str, Any], arguments: Sequence[str],
                connect_timeout: int = 15) -> List[str]:
    """The ssh invocation for one remote netrune command.

    BatchMode keeps a missing key from parking on a password prompt, which in a
    scheduled pull would hang rather than fail.
    """
    host = str(remote.get("host") or "")
    user = str(remote.get("ssh_user") or "")
    port = int(remote.get("ssh_port") or 0)
    # Checked again here, not only when the remote was added: a row stored by an
    # older version, or edited by hand, reaches this function too.
    check_destination(host, user)
    command = ["ssh", "-o", "BatchMode=yes", "-o", f"ConnectTimeout={max(5, int(connect_timeout))}"]
    if port:
        command += ["-p", str(port)]
    # Everything after this is a destination and a command, never an option.
    command += ["--", f"{user}@{host}" if user else host]
    command += list(arguments)
    return command


def remote_netrune(remote: Mapping[str, Any], arguments: Sequence[str]) -> List[str]:
    """`netrune ...` on the remote, in that remote's profile."""
    profile = str(remote.get("profile") or "")
    remote_side = ["netrune"] + (["--profile", profile] if profile else []) + list(arguments)
    # The remote runs a login shell, so the command is quoted as one word.
    return ssh_command(remote, [shlex.join(remote_side)])


def run_remote(remote: Mapping[str, Any], arguments: Sequence[str], timeout: int = 120) -> str:
    """Run a read-only netrune command on the remote and return its stdout."""
    command = remote_netrune(remote, arguments)
    try:
        finished = subprocess.run(command, capture_output=True, text=True, timeout=max(10, timeout))
    except FileNotFoundError as exc:
        raise RemoteError("ssh is not installed on this machine") from exc
    except subprocess.TimeoutExpired as exc:
        raise RemoteError(f"{remote.get('name')} did not answer within {timeout}s") from exc
    if finished.returncode != 0:
        detail = (finished.stderr or finished.stdout or "").strip().splitlines()
        hint = detail[-1] if detail else f"exit {finished.returncode}"
        raise RemoteError(f"{remote.get('name')}: {hint}")
    return finished.stdout


# ---------------------------------------------------------------------------
# Merge
# ---------------------------------------------------------------------------

def merge_export(monitor: Any, rows: Sequence[Mapping[str, Any]],
                 dry_run: bool = False) -> Dict[str, Any]:
    """Fold an export into the local store.

    Watches arrive owned by the collector that polls them, so the local daemon
    leaves them alone. Samples are inserted against the identity index, which
    makes a repeated pull a no-op rather than a source of duplicates -- the
    property that lets a pull be retried after a dropped connection.
    """
    meta = dict(rows[0])
    collector = str(meta.get("collector") or "")
    if not collector:
        raise RemoteError("the export does not say which collector produced it")
    if collector == monitor.collector_id():
        raise RemoteError(
            f"the remote calls itself '{collector}', which is this collector's own id; "
            "give the poller a distinct traffic_collector_id or its readings will be "
            "indistinguishable from this machine's")

    watches = [row for row in rows if row.get("record") == "watch"]
    samples = [row for row in rows if row.get("record") == "sample"]
    counters = [row for row in rows if row.get("record") == "counter"]
    newest = max((int(row.get("observed_at") or 0) for row in samples), default=0)

    summary = {
        "collector": collector,
        "watches": len(watches),
        "samples": len(samples),
        "counters": len(counters),
        "newest_sample_at": newest,
        "window": {"since": meta.get("since"), "until": meta.get("until")},
        "merged": 0,
        "already_present": 0,
    }
    if dry_run:
        return summary

    for watch in watches:
        columns = [column for column in WATCH_COLUMNS if column in watch]
        assignments = ",".join(f"{column}=excluded.{column}" for column in columns
                               if column != "watch_id")
        monitor.state.execute(
            f"INSERT INTO traffic_watch({','.join(columns)},owner)"
            f" VALUES({','.join('?' * len(columns))},?)"
            f" ON CONFLICT(watch_id) DO UPDATE SET {assignments}, owner=excluded.owner",
            (*[watch.get(column) for column in columns], collector),
        )

    merged = monitor.state.execute_many(
        f"INSERT OR IGNORE INTO traffic_samples({','.join(SAMPLE_COLUMNS)})"
        f" VALUES({','.join('?' * len(SAMPLE_COLUMNS))})",
        [tuple(sample.get(column) for column in SAMPLE_COLUMNS) for sample in samples],
    )
    summary["merged"] = merged
    summary["already_present"] = len(samples) - merged

    monitor.state.execute_many(
        f"INSERT OR REPLACE INTO traffic_counters({','.join(COUNTER_COLUMNS)})"
        f" VALUES({','.join('?' * len(COUNTER_COLUMNS))})",
        [tuple(counter.get(column) for column in COUNTER_COLUMNS) for counter in counters],
    )
    return summary
