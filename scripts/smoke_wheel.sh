#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    printf 'Usage: %s <wheel>\n' "$0" >&2
    exit 2
fi

wheel=$(realpath "$1")
work=$(mktemp -d)
server_pid=""
cleanup() {
    if [[ -n "$server_pid" ]]; then
        kill "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
    rm -rf "$work"
}
trap cleanup EXIT
python_bin="${PYTHON:-python3}"
export HOME="$work/home"
export XDG_CONFIG_HOME="$work/config"
export XDG_STATE_HOME="$work/state"
export XDG_CACHE_HOME="$work/cache"
export XDG_DATA_HOME="$work/data"

"$python_bin" -m venv "$work/venv"
"$work/venv/bin/python" -m pip install "$wheel"
"$work/venv/bin/netops" --no-tui version
"$work/venv/bin/netops" --no-tui init --profile smoke
"$work/venv/bin/netops" --no-tui --profile smoke commands list --json >/dev/null
"$work/venv/bin/netop" tui --help >/dev/null
test -f "$work/venv/share/netops-platform/webui/dist/index.html"
grep -q '/assets/' "$work/venv/share/netops-platform/webui/dist/index.html"
test -f "$XDG_CONFIG_HOME/netops/profiles/smoke/profile.toml"
test -f "$XDG_STATE_HOME/netops/profiles/smoke/netops.sqlite3"
port=$("$work/venv/bin/python" -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')
"$work/venv/bin/netops" --no-tui --profile smoke serve --port "$port" >"$work/server.log" 2>&1 &
server_pid=$!
"$work/venv/bin/python" - "$port" <<'PY'
import re
import sys
import time
from urllib.request import urlopen

base = f"http://127.0.0.1:{sys.argv[1]}"
last_error = None
for _ in range(50):
    try:
        html = urlopen(base + "/", timeout=1).read().decode("utf-8")
        break
    except Exception as exc:
        last_error = exc
        time.sleep(0.1)
else:
    raise SystemExit(f"installed WebUI did not start: {last_error}")
if "NetOps Studio" not in html:
    raise SystemExit("installed server returned the fallback page")
asset = re.search(r'src="([^"]+\.js)"', html)
if not asset or not urlopen(base + asset.group(1), timeout=2).read(32):
    raise SystemExit("installed WebUI JavaScript asset is unavailable")
PY
printf 'Isolated wheel smoke test passed: %s\n' "$wheel"
