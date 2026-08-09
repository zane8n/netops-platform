import glob
import json
import os
from pathlib import Path
import signal
import shlex
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]


class NetOpsShellLifecycleTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        self.config_dir = base / "config"
        self.cache_dir = base / "cache"
        self.bin_dir = base / "bin"
        self.config_dir.mkdir()
        self.cache_dir.mkdir()
        self.bin_dir.mkdir()
        (self.config_dir / "netsnmp.conf").write_text('scan_workers="4"\n', encoding="utf-8")
        (self.config_dir / ".env").write_text('ssh_user="admin"\n', encoding="utf-8")
        self.password_file = base / "sshpass.gpg"
        self.password_file.write_text("fixture", encoding="utf-8")
        perl = self.bin_dir / "perl"
        perl.write_text("#!/usr/bin/env bash\nprintf 'Connection refused'\nexit 1\n", encoding="utf-8")
        perl.chmod(0o700)
        self.env = os.environ.copy()
        self.env.update(
            {
                "NETOPS_CONFIG_DIR": str(self.config_dir),
                "NETOPS_CACHE_DIR": str(self.cache_dir),
                "NETOPS_PASSWORD_FILE": str(self.password_file),
                "NETOPS_AUTO_CONFIGURE": "false",
                "NETOPS_PROGRESS": "0",
                "NETOPS_TEST_MODE": "true",
                "NETOPS_SUDO_VAULT_KEY_DIR": str(base / "sudo-vault-keys"),
                "PATH": f"{self.bin_dir}:{self.env.get('PATH', '')}",
            }
        )

    def tearDown(self):
        self.temp.cleanup()

    def run_helper(self, *args, input_text=None):
        return subprocess.run(
            [str(ROOT / args[0]), *args[1:]],
            cwd=ROOT,
            env=self.env,
            input=input_text,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )

    def test_closed_tcp_probe_is_not_mislabeled_as_timeout(self):
        result = self.run_helper("netops-probe", "127.0.0.1", "--port", "65000", "--count", "1")
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 4)
        self.assertIn("CLOSED", output)
        self.assertIn("1 sent, 0 recv", output)
        self.assertNotIn("TIMEOUT", output)

    def test_legacy_launcher_reports_central_version(self):
        result = self.run_helper("netops-legacy", "--version")
        expected = (ROOT / "VERSION").read_text(encoding="ascii").strip()
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), f"NetOps {expected}")

    def test_every_control_helper_mode_has_working_command_help(self):
        modes = (
            "shell", "backup", "backup-history", "diff", "inventory", "propagated",
            "locate-vlan", "show", "core-lookup", "mac-lookup", "config", "vlan",
        )
        for mode in modes:
            with self.subTest(mode=mode):
                result = self.run_helper("netops-control", mode, "--help")
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("Usage:", result.stdout)

    def test_interrupted_probe_skips_route_and_ssh_followups_and_cleans_state(self):
        before = set(glob.glob("/tmp/netops-probe.*"))
        proc = subprocess.Popen(
            [str(ROOT / "netops-probe"), "127.0.0.1", "--port", "65000"],
            cwd=ROOT,
            env=self.env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        try:
            time.sleep(0.35)
            os.killpg(proc.pid, signal.SIGINT)
            stdout, stderr = proc.communicate(timeout=5)
        finally:
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=5)
        output = stdout + stderr
        self.assertEqual(proc.returncode, 130)
        self.assertIn("Stats for 127.0.0.1", output)
        self.assertNotIn("Routing path", output)
        self.assertNotIn("SSH is open", output)
        self.assertEqual(set(glob.glob("/tmp/netops-probe.*")) - before, set())

    def test_direct_probe_termination_reaps_ping_descendant(self):
        ping = self.bin_dir / "ping"
        ping_child_file = Path(self.temp.name) / "probe-ping-child.pid"
        ping.write_text(
            "#!/usr/bin/env bash\n"
            "sleep 30 &\n"
            "child=$!\n"
            "printf '%s' \"$child\" > \"$PROBE_PING_CHILD_FILE\"\n"
            "wait \"$child\"\n",
            encoding="utf-8",
        )
        ping.chmod(0o700)
        env = dict(self.env)
        env["PROBE_PING_CHILD_FILE"] = str(ping_child_file)
        before = set(glob.glob("/tmp/netops-probe.*"))
        proc = subprocess.Popen(
            [str(ROOT / "netops-probe"), "127.0.0.1", "--count", "20"],
            cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True,
        )
        child_pid = None
        try:
            deadline = time.monotonic() + 4
            while time.monotonic() < deadline and not ping_child_file.exists():
                time.sleep(0.05)
            self.assertTrue(ping_child_file.exists(), "ping fixture did not start")
            child_pid = int(ping_child_file.read_text(encoding="utf-8"))
            os.kill(proc.pid, signal.SIGTERM)
            proc.communicate(timeout=5)
            self.assertEqual(proc.returncode, 143)
            with self.assertRaises(ProcessLookupError):
                os.kill(child_pid, 0)
            self.assertEqual(set(glob.glob("/tmp/netops-probe.*")) - before, set())
        finally:
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=5)
            if child_pid is not None:
                try:
                    os.kill(child_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_control_editor_path_has_no_top_level_local_runtime_error(self):
        env = dict(self.env)
        env["EDITOR"] = "true"
        result = subprocess.run(
            [str(ROOT / "netops-control"), "config", "127.0.0.1", "--dry-run"],
            cwd=ROOT,
            env=env,
            input="",
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("local: can only be used in a function", result.stderr)
        self.assertIn("Dry run: config", result.stdout)

    def test_connect_interrupt_removes_private_error_state(self):
        gpg = self.bin_dir / "gpg"
        sshpass = self.bin_dir / "sshpass"
        gpg.write_text("#!/usr/bin/env bash\nprintf 'fixture-password'\n", encoding="utf-8")
        sshpass.write_text("#!/usr/bin/env bash\nsleep 30\n", encoding="utf-8")
        gpg.chmod(0o700)
        sshpass.chmod(0o700)
        env = dict(self.env)
        env["PATH"] = f"{self.bin_dir}:{env.get('PATH', '')}"
        before = set(glob.glob("/tmp/netops-connect.*"))
        proc = subprocess.Popen(
            [str(ROOT / "netops-connect"), "127.0.0.1"],
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        try:
            time.sleep(0.3)
            os.killpg(proc.pid, signal.SIGINT)
            proc.communicate(timeout=5)
        finally:
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=5)
        self.assertEqual(proc.returncode, 130)
        self.assertEqual(set(glob.glob("/tmp/netops-connect.*")) - before, set())

    def test_connect_requires_ssh_username_before_vault_or_transport(self):
        (self.config_dir / ".env").write_text("", encoding="utf-8")
        sshpass_marker = Path(self.temp.name) / "sshpass-invoked"
        gpg_marker = Path(self.temp.name) / "gpg-invoked"
        sshpass = self.bin_dir / "sshpass"
        gpg = self.bin_dir / "gpg"
        sshpass.write_text("#!/usr/bin/env bash\nprintf invoked > \"$SSHPASS_MARKER\"\n", encoding="utf-8")
        gpg.write_text("#!/usr/bin/env bash\nprintf invoked > \"$GPG_MARKER\"\n", encoding="utf-8")
        sshpass.chmod(0o700)
        gpg.chmod(0o700)
        env = dict(self.env)
        env.update({"SSHPASS_MARKER": str(sshpass_marker), "GPG_MARKER": str(gpg_marker)})
        result = subprocess.run(
            [str(ROOT / "netops-connect"), "127.0.0.1"], cwd=ROOT, env=env,
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
        )
        self.assertEqual(result.returncode, 6, result.stdout + result.stderr)
        self.assertIn("netops config set ssh_user <username>", result.stderr)
        self.assertFalse(sshpass_marker.exists())
        self.assertFalse(gpg_marker.exists())

    def test_connect_builds_valid_explicit_ssh_login_arguments(self):
        argument_log = Path(self.temp.name) / "connect-ssh-arguments.log"
        gpg = self.bin_dir / "gpg"
        sshpass = self.bin_dir / "sshpass"
        gpg.write_text("#!/usr/bin/env bash\nprintf 'fixture-password'\n", encoding="utf-8")
        sshpass.write_text(
            "#!/usr/bin/env bash\n"
            "printf '<%s>\\n' \"$@\" > \"$SSH_ARGUMENT_LOG\"\n",
            encoding="utf-8",
        )
        gpg.chmod(0o700)
        sshpass.chmod(0o700)
        env = dict(self.env)
        env["SSH_ARGUMENT_LOG"] = str(argument_log)
        result = subprocess.run(
            [str(ROOT / "netops-connect"), "127.0.0.1"], cwd=ROOT, env=env,
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        arguments = argument_log.read_text(encoding="utf-8").splitlines()
        self.assertIn("<-l>", arguments)
        self.assertIn("<admin>", arguments)
        self.assertIn("<127.0.0.1>", arguments)
        self.assertNotIn("<admin@127.0.0.1>", arguments)

    def test_public_device_ssh_route_reaches_valid_transport_arguments(self):
        argument_log = Path(self.temp.name) / "public-ssh-arguments.log"
        gpg = self.bin_dir / "gpg"
        sshpass = self.bin_dir / "sshpass"
        gpg.write_text("#!/usr/bin/env bash\nprintf 'fixture-password'\n", encoding="utf-8")
        sshpass.write_text(
            "#!/usr/bin/env bash\n"
            "printf '<%s>\\n' \"$@\" > \"$SSH_ARGUMENT_LOG\"\n",
            encoding="utf-8",
        )
        gpg.chmod(0o700)
        sshpass.chmod(0o700)
        env = dict(self.env)
        env["SSH_ARGUMENT_LOG"] = str(argument_log)
        result = subprocess.run(
            [str(ROOT / "netops"), "device", "ssh", "127.0.0.1"], cwd=ROOT, env=env,
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("usage:", (result.stdout + result.stderr).lower())
        arguments = argument_log.read_text(encoding="utf-8").splitlines()
        self.assertIn("<-l>", arguments)
        self.assertIn("<admin>", arguments)
        self.assertIn("<127.0.0.1>", arguments)

    def test_public_speed_profile_reaches_the_speed_backend_unchanged(self):
        result = subprocess.run(
            [str(ROOT / "netops"), "diagnose", "speed", "--profile", "quick", "--runs", "1", "--dry-run", "--plain"],
            cwd=ROOT, env=self.env, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("--profile quick --speed-runs 1", result.stdout)
        self.assertNotIn("--profile balanced", result.stdout)

    def test_shell_config_save_preserves_public_ssh_username(self):
        result = subprocess.run(
            [
                "bash", "-c",
                'source "$1"; CONFIG[ssh_user]="operator"; save_config',
                "netops-config-save-test", str(ROOT / "netops-lib.sh"),
            ],
            cwd=ROOT, env=self.env, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        saved = (self.config_dir / "netsnmp.conf").read_text(encoding="utf-8")
        self.assertIn('ssh_user="operator"', saved)

    def test_direct_connect_termination_reaps_ssh_descendant(self):
        gpg = self.bin_dir / "gpg"
        sshpass = self.bin_dir / "sshpass"
        ssh_pid_file = Path(self.temp.name) / "connect-ssh.pid"
        gpg.write_text("#!/usr/bin/env bash\nprintf 'fixture-password'\n", encoding="utf-8")
        sshpass.write_text(
            "#!/usr/bin/env bash\n"
            "printf '%s' \"$$\" > \"$CONNECT_SSH_PID_FILE\"\n"
            "exec sleep 30\n",
            encoding="utf-8",
        )
        gpg.chmod(0o700)
        sshpass.chmod(0o700)
        env = dict(self.env)
        env["CONNECT_SSH_PID_FILE"] = str(ssh_pid_file)
        before = set(glob.glob("/tmp/netops-connect.*"))
        proc = subprocess.Popen(
            [str(ROOT / "netops-connect"), "127.0.0.1"],
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        child_pid = None
        try:
            deadline = time.monotonic() + 4
            while time.monotonic() < deadline and not ssh_pid_file.exists():
                time.sleep(0.05)
            self.assertTrue(ssh_pid_file.exists(), "SSH fixture did not start")
            child_pid = int(ssh_pid_file.read_text(encoding="utf-8"))
            os.kill(proc.pid, signal.SIGTERM)
            proc.communicate(timeout=5)
            self.assertEqual(proc.returncode, 143)
            with self.assertRaises(ProcessLookupError):
                os.kill(child_pid, 0)
            self.assertEqual(set(glob.glob("/tmp/netops-connect.*")) - before, set())
        finally:
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=5)
            if child_pid is not None:
                try:
                    os.kill(child_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_prompt_aware_ssh_waits_for_a_complete_prompt_line(self):
        sshpass = self.bin_dir / "sshpass"
        argument_log = Path(self.temp.name) / "prompted-ssh-arguments.log"
        sshpass.write_text(
            """#!/usr/bin/env bash
printf '<%s>' "$@" >> "$SSH_ARGUMENT_LOG"
printf '\n' >> "$SSH_ARGUMENT_LOG"
printf 'FIXTURE-SW# '
while IFS= read -r line; do
    line=${line%$'\\r'}
    case "$line" in
        'show comparison')
            printf '\\r\\nshow comparison\\r\\nvalue > threshold\\r\\nresult complete\\r\\nFIXTURE-SW# '
            ;;
        exit) exit 0 ;;
        *) printf '\\r\\nunknown command\\r\\nFIXTURE-SW# ' ;;
    esac
done
""",
            encoding="utf-8",
        )
        sshpass.chmod(0o700)
        env = dict(self.env)
        env.update({
            "CREDS_ssh_user": "admin",
            "SSHPASS": "fixture",
            "SSH_ARGUMENT_LOG": str(argument_log),
            "NETOPS_SSH_KEX_ALGORITHMS": "diffie-hellman-group14-sha1",
            "NETOPS_SSH_HOST_KEY_ALGORITHMS": "ssh-rsa",
            "NETOPS_SSH_CIPHERS": "aes128-cbc",
            "NETOPS_SSH_MACS": "hmac-sha1",
        })
        result = subprocess.run(
            [str(ROOT / "netops_aruba_ssh.exp"), "192.0.2.1", "show comparison"],
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("value > threshold", result.stdout)
        self.assertIn("result complete", result.stdout)
        self.assertNotIn("FIXTURE-SW#", result.stdout)
        arguments = argument_log.read_text(encoding="utf-8")
        self.assertIn("<KexAlgorithms=+diffie-hellman-group14-sha1>", arguments)
        self.assertIn("<HostKeyAlgorithms=+ssh-rsa>", arguments)
        self.assertIn("<Ciphers=+aes128-cbc>", arguments)
        self.assertIn("<MACs=+hmac-sha1>", arguments)

    def test_prompt_aware_ssh_reports_early_eof_and_kills_timed_out_child(self):
        sshpass = self.bin_dir / "sshpass"
        sshpass.write_text("#!/usr/bin/env bash\nprintf 'authentication failed\\n' >&2\nexit 7\n", encoding="utf-8")
        sshpass.chmod(0o700)
        env = dict(self.env)
        env.update({"CREDS_ssh_user": "admin", "SSHPASS": "fixture"})
        early_eof = subprocess.run(
            [str(ROOT / "netops_aruba_ssh.exp"), "192.0.2.1", "show version"],
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
        )
        self.assertEqual(early_eof.returncode, 7)
        self.assertIn("before the initial device prompt", early_eof.stderr)

        pid_file = Path(self.temp.name) / "timed-out-ssh.pid"
        sshpass.write_text(
            """#!/usr/bin/env bash
printf 'FIXTURE-SW# '
IFS= read -r line
printf '%s' "$$" > "$SSH_FIXTURE_PID_FILE"
exec sleep 30
""",
            encoding="utf-8",
        )
        sshpass.chmod(0o700)
        env.update({"NETOPS_SSH_COMMAND_TIMEOUT": "1", "SSH_FIXTURE_PID_FILE": str(pid_file)})
        timed_out = subprocess.run(
            [str(ROOT / "netops_aruba_ssh.exp"), "192.0.2.1", "show slow"],
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
        )
        self.assertEqual(timed_out.returncode, 9, timed_out.stderr)
        self.assertIn("command 1", timed_out.stderr)
        child_pid = int(pid_file.read_text(encoding="utf-8"))
        with self.assertRaises(ProcessLookupError):
            os.kill(child_pid, 0)

    def test_target_resolution_rejects_invalid_ip_and_emits_ranges_one_per_line(self):
        script = "source ./netops-lib.sh; resolve_targets \"$1\" DEVICES true"
        invalid = subprocess.run(
            ["bash", "-c", script, "resolve", "999.1.1.1"],
            cwd=ROOT,
            env=self.env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
        )
        valid_range = subprocess.run(
            ["bash", "-c", script, "resolve", "198.51.100.3-5"],
            cwd=ROOT,
            env=self.env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
        )
        self.assertEqual(invalid.returncode, 1)
        self.assertIn("Invalid IPv4 target", invalid.stderr)
        self.assertEqual(valid_range.returncode, 0)
        self.assertEqual(valid_range.stdout.splitlines(), ["198.51.100.3", "198.51.100.4", "198.51.100.5"])

    def test_missing_local_vault_returns_to_sourced_caller(self):
        missing = Path(self.temp.name) / "missing-vault.gpg"
        script = 'source ./netops-lib.sh; PASSWORD_FILE="$1"; get_password_from_store; rc=$?; printf "after:%s\\n" "$rc"; exit 0'
        result = subprocess.run(
            ["bash", "-c", script, "vault-return", str(missing)],
            cwd=ROOT, env=self.env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "after:1")
        self.assertIn("SSH password not found", result.stderr)

    def test_local_vault_update_is_private_atomic_and_preserves_previous_value_on_failure(self):
        vault = Path(self.temp.name) / "vault" / "sshpass.gpg"
        gpg = self.bin_dir / "gpg"
        gpg.write_text(
            "#!/usr/bin/env bash\n"
            "output=''\n"
            "while (($#)); do\n"
            "  if [[ \"$1\" == '-o' ]]; then output=$2; shift 2; else shift; fi\n"
            "done\n"
            "payload=$(cat)\n"
            "printf 'ciphertext:%s' \"$payload\" > \"$output\"\n"
            "[[ \"${GPG_FIXTURE_FAIL:-false}\" == true ]] && exit 9\n"
            "exit 0\n",
            encoding="utf-8",
        )
        gpg.chmod(0o700)
        script = 'source ./netops-lib.sh; PASSWORD_FILE="$1"; set_password legacy-gpg'

        success = subprocess.run(
            ["bash", "-c", script, "vault-set", str(vault)],
            cwd=ROOT, env=self.env, input="new secret\nnew secret\nvault phrase\nvault phrase\n", text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
        )
        self.assertEqual(success.returncode, 0, success.stderr)
        self.assertEqual(vault.read_text(encoding="utf-8"), "ciphertext:new secret")
        self.assertEqual(vault.stat().st_mode & 0o777, 0o600)

        failed_env = dict(self.env)
        failed_env["GPG_FIXTURE_FAIL"] = "true"
        failed = subprocess.run(
            ["bash", "-c", script, "vault-set", str(vault)],
            cwd=ROOT, env=failed_env, input="replacement\nreplacement\nvault phrase\nvault phrase\n", text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
        )
        self.assertEqual(failed.returncode, 1)
        self.assertEqual(vault.read_text(encoding="utf-8"), "ciphertext:new secret")
        self.assertEqual(list(vault.parent.glob(".netops-vault.*")), [])

    def test_sudo_gated_vault_uses_cached_terminal_auth_and_never_pinentry(self):
        vault = Path(self.temp.name) / "sudo-vault" / "sshpass.gpg"
        sudo_log = Path(self.temp.name) / "sudo-arguments.log"
        gpg_log = Path(self.temp.name) / "gpg-arguments.log"
        sudo_cache = Path(self.temp.name) / "sudo-cache"
        sudo = self.bin_dir / "sudo"
        gpg = self.bin_dir / "gpg"
        sudo.write_text(
            "#!/usr/bin/env bash\n"
            "printf '<%s>' \"$@\" >> \"$SUDO_ARGUMENT_LOG\"; printf '\\n' >> \"$SUDO_ARGUMENT_LOG\"\n"
            "if [[ \"$1\" == -n && \"$2\" == -v ]]; then [[ -f \"$SUDO_CACHE_FILE\" ]]; exit; fi\n"
            "if [[ \"$1\" == -v ]]; then\n"
            "  if [[ ! -f \"$SUDO_CACHE_FILE\" ]]; then printf '<AUTH>\\n' >> \"$SUDO_ARGUMENT_LOG\"; sleep \"${SUDO_AUTH_DELAY:-0}\"; : > \"$SUDO_CACHE_FILE\"; fi\n"
            "  exit 0\n"
            "fi\n"
            "if [[ \"$1\" != -n && ! -f \"$SUDO_CACHE_FILE\" ]]; then\n"
            "  printf '<AUTH>\\n' >> \"$SUDO_ARGUMENT_LOG\"; sleep \"${SUDO_AUTH_DELAY:-0}\"; : > \"$SUDO_CACHE_FILE\"\n"
            "fi\n"
            "[[ \"${SUDO_FAIL_CAT:-false}\" == true && (\"$1\" == /bin/sh || \"$2\" == /bin/sh) ]] && exit 12\n"
            "[[ \"$1\" == -n ]] && shift\n"
            "if [[ \"$1\" == /usr/bin/stat ]]; then\n"
            "  metadata=$(/usr/bin/stat -c '%a:%F' \"${@: -1}\") || exit $?\n"
            "  printf '65534:%s\\r\\n' \"$metadata\"; exit 0\n"
            "fi\n"
            "exec \"$@\"\n",
            encoding="utf-8",
        )
        gpg.write_text(
            "#!/usr/bin/env bash\n"
            "printf '<%s>' \"$@\" >> \"$GPG_ARGUMENT_LOG\"; printf '\\n' >> \"$GPG_ARGUMENT_LOG\"\n"
            "passphrase_fd=''\n"
            "args=(\"$@\")\n"
            "for ((i=0; i < ${#args[@]} - 1; i++)); do\n"
            "  [[ \"${args[$i]}\" == --passphrase-fd ]] && passphrase_fd=\"${args[$((i + 1))]}\"\n"
            "done\n"
            "[[ -n \"$passphrase_fd\" ]] || exit 13\n"
            "IFS= read -r vault_key <&\"$passphrase_fd\" || exit 14\n"
            "[[ -n \"$vault_key\" ]] || exit 15\n"
            "payload=$(cat)\n"
            "if [[ \" $* \" == *' --symmetric '* ]]; then\n"
            "  [[ \"${GPG_FIXTURE_FAIL:-false}\" == true ]] && exit 9\n"
            "  printf 'ciphertext:%s' \"$payload\"\n"
            "elif [[ \"$payload\" == ciphertext:* ]]; then\n"
            "  printf '%s' \"${payload#ciphertext:}\"\n"
            "else\n"
            "  exit 10\n"
            "fi\n",
            encoding="utf-8",
        )
        sudo.chmod(0o700)
        gpg.chmod(0o700)
        env = dict(self.env)
        env.update(
            {
                "SUDO_ARGUMENT_LOG": str(sudo_log),
                "SUDO_CACHE_FILE": str(sudo_cache),
                "GPG_ARGUMENT_LOG": str(gpg_log),
            }
        )
        set_script = 'source ./netops-lib.sh; PASSWORD_FILE="$1"; set_password sudo-gpg'
        created = subprocess.run(
            ["bash", "-c", set_script, "vault-set", str(vault)],
            cwd=ROOT,
            env=env,
            input="new secret\nnew secret\n",
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
        )
        self.assertEqual(created.returncode, 0, created.stderr)
        secret_store = self.cache_dir / "secrets.gpg"
        self.assertTrue(secret_store.read_bytes().startswith(b"NETOPS-NAMED-SECRETS-GPG-V1\nciphertext:"))
        self.assertNotIn(b"new secret", secret_store.read_bytes())
        self.assertEqual(secret_store.stat().st_mode & 0o777, 0o600)
        root_key = Path(env["NETOPS_SUDO_VAULT_KEY_DIR"]) / f"{os.getuid()}.key"
        self.assertTrue(root_key.is_file())
        self.assertEqual(root_key.stat().st_mode & 0o777, 0o600)
        self.assertIn("Unlocking the NetOps SSH vault with", created.stderr)
        gpg_arguments = gpg_log.read_text(encoding="utf-8")
        self.assertIn("<--pinentry-mode><loopback>", gpg_arguments)
        self.assertIn("<--passphrase-fd>", gpg_arguments)
        self.assertIn("<--no-symkey-cache>", gpg_arguments)
        self.assertNotIn("pinentry.exe", gpg_arguments)
        sudo_arguments = sudo_log.read_text(encoding="utf-8")
        self.assertIn("<-v>", sudo_arguments)
        self.assertNotIn("<-S>", sudo_arguments)

        read_script = 'source ./netops-lib.sh; PASSWORD_FILE="$1"; get_password_from_store || exit $?; printf "<%s>" "$SSHPASS"'
        opened = subprocess.run(
            ["bash", "-c", read_script, "vault-open", str(vault)],
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
        )
        self.assertEqual(opened.returncode, 0, opened.stderr)
        self.assertEqual(opened.stdout, "<new secret>")
        self.assertNotIn("Unlocking", opened.stderr)

        sudo_cache.unlink()
        concurrent_env = dict(env)
        concurrent_env["SUDO_AUTH_DELAY"] = "0.2"
        prompts_before = sudo_log.read_text(encoding="utf-8").splitlines().count("<AUTH>")
        workers = [
            subprocess.Popen(
                ["bash", "-c", read_script, "vault-open", str(vault)],
                cwd=ROOT,
                env=concurrent_env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            for _ in range(2)
        ]
        worker_results = [worker.communicate(timeout=5) for worker in workers]
        self.assertEqual([worker.returncode for worker in workers], [0, 0], worker_results)
        self.assertEqual([stdout for stdout, _ in worker_results], ["<new secret>", "<new secret>"])
        prompts_after = sudo_log.read_text(encoding="utf-8").splitlines().count("<AUTH>")
        self.assertEqual(prompts_after - prompts_before, 1)

        read_failure_env = dict(env)
        read_failure_env["SUDO_FAIL_CAT"] = "true"
        blocked = subprocess.run(
            ["bash", "-c", read_script, "vault-open", str(vault)],
            cwd=ROOT,
            env=read_failure_env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
        )
        self.assertEqual(blocked.returncode, 1)
        self.assertEqual(blocked.stdout, "")
        self.assertIn("Failed to decrypt named secret ssh/default/password", blocked.stderr)

        original = secret_store.read_bytes()
        failed_env = dict(env)
        failed_env["GPG_FIXTURE_FAIL"] = "true"
        failed = subprocess.run(
            ["bash", "-c", set_script, "vault-set", str(vault)],
            cwd=ROOT,
            env=failed_env,
            input="replacement\nreplacement\n",
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
        )
        self.assertEqual(failed.returncode, 1)
        self.assertEqual(secret_store.read_bytes(), original)
        self.assertEqual(list(secret_store.parent.glob(".netops-secrets.*")), [])

        root_key.chmod(0o644)
        insecure = subprocess.run(
            ["bash", "-c", read_script, "vault-open", str(vault)],
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
        )
        self.assertEqual(insecure.returncode, 1)
        self.assertIn("key mode is 644, expected 400 or 600", insecure.stderr)

    def test_secret_input_uses_inherited_tty_without_a_controlling_terminal(self):
        master_fd, slave_fd = os.openpty()
        proc = None
        try:
            script = (
                "source ./netops-lib.sh; NETOPS_TEST_MODE=false; exec() { return 1; }; "
                "_read_secret_value captured 'Inherited terminal secret: ' || exit $?; "
                "printf '<%s>' \"$captured\""
            )
            proc = subprocess.Popen(
                ["bash", "-c", script],
                cwd=ROOT,
                env=self.env,
                stdin=slave_fd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            os.close(slave_fd)
            slave_fd = -1
            os.write(master_fd, b"terminal-secret\n")
            stdout, stderr = proc.communicate(timeout=5)
        finally:
            if proc is not None and proc.poll() is None:
                proc.kill()
                proc.wait(timeout=2)
            os.close(master_fd)
            if slave_fd >= 0:
                os.close(slave_fd)
        self.assertEqual(proc.returncode, 0, stderr.decode(errors="replace"))
        self.assertIn(b"Inherited terminal secret: ", stderr)
        self.assertEqual(stdout, b"<terminal-secret>")
        self.assertNotIn(b"terminal-secret", stderr)

    def test_legacy_vault_migration_uses_loopback_once_then_sudo_gpg(self):
        vault = Path(self.temp.name) / "legacy-vault.gpg"
        vault.write_text("legacy-ciphertext", encoding="utf-8")
        sudo_cache = Path(self.temp.name) / "migration-sudo-cache"
        sudo = self.bin_dir / "sudo"
        gpg = self.bin_dir / "gpg"
        gpg_log = Path(self.temp.name) / "migration-gpg-arguments.log"
        sudo.write_text(
            "#!/usr/bin/env bash\n"
            "if [[ \"$1\" == -n && \"$2\" == -v ]]; then [[ -f \"$SUDO_CACHE_FILE\" ]]; exit; fi\n"
            "if [[ \"$1\" == -v ]]; then : > \"$SUDO_CACHE_FILE\"; exit 0; fi\n"
            "[[ \"$1\" == -n ]] && shift\n"
            "exec \"$@\"\n",
            encoding="utf-8",
        )
        gpg.write_text(
            "#!/usr/bin/env bash\n"
            "printf '<%s>' \"$@\" >> \"$GPG_ARGUMENT_LOG\"; printf '\\n' >> \"$GPG_ARGUMENT_LOG\"\n"
            "if [[ \" $* \" == *' --no-symkey-cache '* && \" $* \" == *' --symmetric '* ]]; then\n"
            "  args=(\"$@\"); passphrase_fd=''\n"
            "  for ((i=0; i < ${#args[@]} - 1; i++)); do\n"
            "    [[ \"${args[$i]}\" == --passphrase-fd ]] && passphrase_fd=\"${args[$((i + 1))]}\"\n"
            "  done\n"
            "  [[ -n \"$passphrase_fd\" ]] || exit 12\n"
            "  IFS= read -r vault_key <&\"$passphrase_fd\" || exit 13\n"
            "  [[ -n \"$vault_key\" ]] || exit 14\n"
            "  payload=$(cat); printf 'migrated:%s' \"$payload\"; exit 0\n"
            "fi\n"
            "if [[ \" $* \" == *' --passphrase-fd 0 '* ]]; then\n"
            "  passphrase=$(cat)\n"
            "  [[ \"$passphrase\" == 'old vault phrase' ]] || exit 11\n"
            "  printf 'fixture-ssh-password'; exit 0\n"
            "fi\n"
            "exit 9\n",
            encoding="utf-8",
        )
        sudo.chmod(0o700)
        gpg.chmod(0o700)
        env = dict(self.env)
        env.update(
            {
                "SUDO_CACHE_FILE": str(sudo_cache),
                "GPG_ARGUMENT_LOG": str(gpg_log),
            }
        )
        script = 'source ./netops-lib.sh; PASSWORD_FILE="$1"; migrate_password_store'
        migrated = subprocess.run(
            ["bash", "-c", script, "vault-migrate", str(vault)],
            cwd=ROOT,
            env=env,
            input="old vault phrase\n",
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
        )
        self.assertEqual(migrated.returncode, 0, migrated.stderr)
        self.assertEqual(vault.read_bytes(), b"legacy-ciphertext")
        secret_store = self.cache_dir / "secrets.gpg"
        self.assertTrue(secret_store.read_bytes().startswith(b"NETOPS-NAMED-SECRETS-GPG-V1\nmigrated:"))
        self.assertNotIn(b"fixture-ssh-password", secret_store.read_bytes())
        self.assertIn("original vault was left unchanged", migrated.stderr.lower())
        arguments = gpg_log.read_text(encoding="utf-8")
        self.assertGreaterEqual(arguments.count("<--pinentry-mode><loopback>"), 3)
        self.assertIn("<--passphrase-fd><0>", arguments)
        self.assertIn("<--no-symkey-cache>", arguments)
        self.assertGreaterEqual(arguments.count("<--passphrase-fd>"), 2)
        self.assertNotIn("pinentry.exe", arguments)

    def test_vault_lifecycle_uses_three_day_rotation_and_twenty_minute_window(self):
        vault = Path(self.temp.name) / "lifecycle.gpg"
        vault.write_text("fixture", encoding="utf-8")
        os.utime(vault, (1704067200, 1704067200))
        script = (
            'source ./netops-lib.sh; PASSWORD_FILE="$1"; '
            'for epoch in 1704283200 1704325200 1704327600; do '
            'NETOPS_VAULT_NOW_EPOCH="$epoch" _vault_credential_lifecycle; done'
        )
        result = subprocess.run(
            ["bash", "-c", script, "vault-lifecycle", str(vault)],
            cwd=ROOT,
            env=self.env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = [line.split("|") for line in result.stdout.splitlines()]
        self.assertEqual([row[0] for row in rows], ["DUE_SOON", "EXPIRY_WINDOW", "EXPIRED"])
        self.assertTrue(all(row[2] == "1704326400" for row in rows))
        self.assertTrue(all(row[3] == "1704325200" and row[4] == "1704327600" for row in rows))

    @unittest.skipUnless(shutil.which("gpg"), "GPG is required for the real vault round trip")
    def test_named_ssh_secret_round_trips_with_real_gpg(self):
        vault = Path(self.temp.name) / "real-gpg" / "sshpass.gpg"
        secrets = Path(self.temp.name) / "real-gpg" / "secrets.gpg"
        secrets_metadata = Path(self.temp.name) / "real-gpg" / "secrets.meta"
        sudo_cache = Path(self.temp.name) / "real-gpg-sudo-cache"
        gnupg_home = Path(self.temp.name) / "gnupg"
        gnupg_home.mkdir(mode=0o700)
        sudo = self.bin_dir / "sudo"
        sudo.write_text(
            "#!/usr/bin/env bash\n"
            "if [[ \"$1\" == -n && \"$2\" == -v ]]; then [[ -f \"$SUDO_CACHE_FILE\" ]]; exit; fi\n"
            "if [[ \"$1\" == -v ]]; then : > \"$SUDO_CACHE_FILE\"; exit 0; fi\n"
            "[[ \"$1\" == -n ]] && shift\n"
            "exec \"$@\"\n",
            encoding="utf-8",
        )
        sudo.chmod(0o700)
        env = dict(self.env)
        env.update({
            "SUDO_CACHE_FILE": str(sudo_cache),
            "GNUPGHOME": str(gnupg_home),
            "NETOPS_PASSWORD_FILE": str(vault),
            "NETOPS_SECRETS_FILE": str(secrets),
            "NETOPS_SECRETS_META_FILE": str(secrets_metadata),
        })
        script = (
            'source ./netops-lib.sh; '
            'set_password sudo-gpg || exit $?; '
            'get_password_from_store || exit $?; printf "<%s>" "$SSHPASS"'
        )
        result = subprocess.run(
            ["bash", "-c", script, "vault-real-gpg"],
            cwd=ROOT,
            env=env,
            input="actual roundtrip secret\nactual roundtrip secret\n",
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
        )
        if result.returncode != 0 and (
            "failed to start gpg-agent" in result.stderr
            or "can't connect to the gpg-agent" in result.stderr
        ):
            self.skipTest("execution sandbox prevents the temporary GPG Agent socket")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "<actual roundtrip secret>")
        encrypted = secrets.read_bytes()
        self.assertTrue(encrypted.startswith(b"NETOPS-NAMED-SECRETS-GPG-V1\n"))
        self.assertNotIn(b"actual roundtrip secret", encrypted)
        self.assertTrue(secrets_metadata.is_file())
        self.assertEqual(secrets.stat().st_mode & 0o777, 0o600)
        self.assertFalse(vault.exists())

    def test_snmpv3_credentials_with_spaces_remain_single_arguments(self):
        argument_log = Path(self.temp.name) / "snmp-arguments.log"
        snmpget = self.bin_dir / "snmpget"
        snmpget.write_text(
            "#!/usr/bin/env bash\n"
            "printf '<%s>\\n' \"$@\" > \"$SNMP_ARGUMENT_LOG\"\n"
            "printf 'fixture-system-name\\n'\n",
            encoding="utf-8",
        )
        snmpget.chmod(0o700)
        env = dict(self.env)
        env["SNMP_ARGUMENT_LOG"] = str(argument_log)
        script = (
            "source ./netops-lib.sh; "
            "CREDS[snmp_version]=v3; CREDS[snmpv3_user]='ops user'; "
            "CREDS[snmpv3_auth_pass]='auth phrase'; CREDS[snmpv3_priv_pass]='privacy phrase'; "
            "netops_snmp_get 192.0.2.1 sysName.0"
        )
        result = subprocess.run(
            ["bash", "-c", script], cwd=ROOT, env=env, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "fixture-system-name")
        arguments = argument_log.read_text(encoding="utf-8").splitlines()
        self.assertIn("<ops user>", arguments)
        self.assertIn("<auth phrase>", arguments)
        self.assertIn("<privacy phrase>", arguments)

    def test_remote_vault_sync_is_disabled_without_invoking_curl(self):
        marker = Path(self.temp.name) / "curl-invoked"
        curl = self.bin_dir / "curl"
        curl.write_text("#!/usr/bin/env bash\nprintf invoked > \"$CURL_MARKER\"\n", encoding="utf-8")
        curl.chmod(0o700)
        env = dict(self.env)
        env["CURL_MARKER"] = str(marker)
        result = subprocess.run(
            ["bash", "-c", "source ./netops-lib.sh; sync_password_from_gist"],
            cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("remote SSH vault sync is disabled", result.stderr)
        self.assertFalse(marker.exists())

    def test_ssh_uses_managed_known_hosts_and_rejects_unapproved_break_glass(self):
        command = 'source ./netops-lib.sh; declare -a opts; _build_ssh_opts opts || exit $?; printf "%s\\n" "${opts[@]}"'
        managed = subprocess.run(
            ["bash", "-c", command], cwd=ROOT, env=self.env, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
        )
        self.assertEqual(managed.returncode, 0, managed.stderr)
        self.assertIn("StrictHostKeyChecking=accept-new", managed.stdout)
        self.assertIn(f"UserKnownHostsFile={self.config_dir / 'known_hosts'}", managed.stdout)
        self.assertEqual(stat.S_IMODE((self.config_dir / "known_hosts").stat().st_mode), 0o600)

        blocked_env = dict(self.env)
        blocked_env["NETOPS_SSH_HOST_KEY_MODE"] = "break-glass"
        blocked = subprocess.run(
            ["bash", "-c", command], cwd=ROOT, env=blocked_env, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
        )
        self.assertEqual(blocked.returncode, 8)
        self.assertIn("NETOPS_SSH_BREAK_GLASS=true", blocked.stderr)

    def test_device_families_and_legacy_ssh_algorithms_are_selected_explicitly(self):
        ssh = self.bin_dir / "ssh"
        ssh.write_text(
            "#!/usr/bin/env bash\n"
            "if [[ \"$1\" == -Q ]]; then\n"
            "  case \"$2\" in\n"
            "    kex) printf 'diffie-hellman-group14-sha1\\n' ;;\n"
            "    key) printf 'ssh-rsa\\n' ;;\n"
            "    cipher) printf 'aes128-cbc\\n' ;;\n"
            "    mac) printf 'hmac-sha1\\n' ;;\n"
            "  esac\n"
            "fi\n",
            encoding="utf-8",
        )
        ssh.chmod(0o700)
        script = """
source ./netops-lib.sh
printf 'families=%s,%s,%s,%s,%s,%s\n' \
  "$(netops_platform_family 'Cisco IOS XE C9300')" \
  "$(netops_platform_family 'Aruba 2930F ProCurve')" \
  "$(netops_platform_family 'ArubaOS-CX 10.13 CX 6300')" \
  "$(netops_platform_family 'Ruckus ICX7150 FastIron 08.0.95')" \
  "$(netops_platform_family 'Ruckus SmartZone vSZ')" \
  "$(netops_platform_family 'Ruckus AP R750')"
CONFIG[legacy_ssh]=true
declare -a opts
_build_ssh_opts opts || exit $?
printf 'opts=%s\n' "${opts[*]}"
printf 'exports=%s|%s|%s|%s\n' "$NETOPS_SSH_KEX_ALGORITHMS" "$NETOPS_SSH_HOST_KEY_ALGORITHMS" "$NETOPS_SSH_CIPHERS" "$NETOPS_SSH_MACS"
printf 'failure=%s\n' "$(ssh_failure_kind 'Unable to negotiate: no matching cipher found. Their offer: aes128-cbc')"
"""
        result = subprocess.run(
            ["bash", "-c", script],
            cwd=ROOT,
            env=self.env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("families=cisco-ios,aruba-aos-switch,aruba-aos-cx,ruckus-fastiron,ruckus-smartzone,ruckus-ap", result.stdout)
        self.assertIn("KexAlgorithms=+diffie-hellman-group14-sha1", result.stdout)
        self.assertIn("HostKeyAlgorithms=+ssh-rsa", result.stdout)
        self.assertIn("Ciphers=+aes128-cbc", result.stdout)
        self.assertIn("MACs=+hmac-sha1", result.stdout)
        self.assertIn("exports=diffie-hellman-group14-sha1|ssh-rsa|aes128-cbc|hmac-sha1", result.stdout)
        self.assertIn("failure=CIPHER", result.stdout)

    def test_missing_config_snippet_stops_control_dry_run(self):
        result = self.run_helper("netops-control", "config", "127.0.0.1", "@definitely-missing", "--dry-run")
        self.assertEqual(result.returncode, 1)
        self.assertIn("Snippet definitely-missing not found", result.stdout + result.stderr)

    def test_direct_control_show_is_read_only_but_allows_diagnostic_commands(self):
        rejected = self.run_helper(
            "netops-control", "show", "127.0.0.1", "configure terminal", "--dry-run"
        )
        injected = self.run_helper(
            "netops-control", "show", "127.0.0.1", "show version; reload", "--dry-run"
        )
        unquoted = self.run_helper(
            "netops-control", "show", "127.0.0.1", "show", "version", "--dry-run"
        )
        self.assertEqual((rejected.returncode, injected.returncode, unquoted.returncode), (2, 2, 2))
        self.assertIn("only bounded read-only", rejected.stdout + rejected.stderr)
        self.assertIn("exactly one quoted command", unquoted.stdout + unquoted.stderr)

        for command in (
            "show interfaces Gi1/0/1",
            "ping 192.0.2.8 repeat 5 timeout 2",
            "test cable-diagnostics tdr interface Gi1/0/1",
            "diag cable-diagnostic show 1",
        ):
            with self.subTest(command=command):
                allowed = self.run_helper(
                    "netops-control", "show", "127.0.0.1", command, "--dry-run"
                )
                self.assertEqual(allowed.returncode, 0, allowed.stdout + allowed.stderr)
                self.assertIn(command, allowed.stdout)

    def test_direct_control_validates_vlan_arguments_before_execution(self):
        access = self.run_helper(
            "netops-control", "vlan", "127.0.0.1", "Gi1/0/8", "--access", "131", "--dry-run"
        )
        trunk = self.run_helper(
            "netops-control", "vlan", "127.0.0.1", "Gi1/0/48", "--trunk", "10,20-22",
            "--native", "99", "--replace", "--dry-run",
        )
        numeric_interface = self.run_helper(
            "netops-control", "vlan", "127.0.0.1", "1/1/1", "--access", "131", "--dry-run"
        )
        self.assertEqual(
            (access.returncode, trunk.returncode, numeric_interface.returncode),
            (0, 0, 0),
            access.stderr + trunk.stderr + numeric_interface.stderr,
        )
        self.assertIn("switchport access vlan 131", access.stdout)
        self.assertIn("switchport trunk allowed vlan 10,20-22", trunk.stdout)
        self.assertIn("switchport trunk native vlan 99", trunk.stdout)

        invalid_cases = (
            ("Gi1/0/8", "--access"),
            ("Gi1/0/8", "--access", "4095"),
            ("Gi1/0/48", "--trunk", "10,22-20"),
            ("Gi1/0/48", "--trunk", "10,20,"),
            ("Gi1/0/8;reload", "--access", "131"),
            ("Gi1/0/8", "--access", "131", "--trunk", "10"),
            ("Gi1/0/8", "--access", "131", "--native", "99"),
        )
        for arguments in invalid_cases:
            with self.subTest(arguments=arguments):
                result = self.run_helper(
                    "netops-control", "vlan", "127.0.0.1", *arguments, "--dry-run"
                )
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)

        invalid_vlan = self.run_helper(
            "netops-control", "propagated", "127.0.0.1", "5000", "--dry-run"
        )
        invalid_mac = self.run_helper(
            "netops-control", "mac-lookup", "127.0.0.1", "not-a-mac", "--dry-run"
        )
        self.assertEqual((invalid_vlan.returncode, invalid_mac.returncode), (2, 2))

    def test_direct_control_blocks_unreviewed_configuration_execution(self):
        (self.cache_dir / "devices.db").write_text(
            "127.0.0.1|FIXTURE-SW|Cisco|C9300|SERIAL|N/A|test|1|ONLINE\n",
            encoding="utf-8",
        )
        config = self.run_helper("netops-control", "config", "127.0.0.1", "hostname reviewed-only")
        vlan = self.run_helper("netops-control", "vlan", "127.0.0.1", "Gi1/0/8", "--access", "131")
        for result in (config, vlan):
            self.assertEqual(result.returncode, 7, result.stdout + result.stderr)
            self.assertIn("Direct configuration execution is blocked", result.stdout + result.stderr)

    def test_control_selects_ruckus_driver_from_model_when_platform_is_unknown(self):
        (self.cache_dir / "devices.db").write_text(
            "127.0.0.1|FIXTURE-SW|Unknown|ICX7150|SERIAL|N/A|test|1|ONLINE\n",
            encoding="utf-8",
        )
        stream_file = Path(self.temp.name) / "command-stream.txt"
        gpg = self.bin_dir / "gpg"
        sshpass = self.bin_dir / "sshpass"
        gpg.write_text("#!/usr/bin/env bash\nprintf 'fixture-password'\n", encoding="utf-8")
        sshpass.write_text(
            "#!/usr/bin/env bash\n"
            "cat > \"$CONTROL_STREAM_FILE\"\n"
            "printf 'MAC not present\\n'\n",
            encoding="utf-8",
        )
        gpg.chmod(0o700)
        sshpass.chmod(0o700)
        env = dict(self.env)
        env["CONTROL_STREAM_FILE"] = str(stream_file)
        result = subprocess.run(
            [str(ROOT / "netops-control"), "mac-lookup", "127.0.0.1", "0200.0000.0025"],
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        stream = stream_file.read_text(encoding="utf-8")
        self.assertIn("skip-page-display", stream)
        self.assertIn("show mac-address 020000000025", stream)
        self.assertNotIn("terminal length 0", stream)

    def test_shell_device_update_uses_normalized_ingest_boundary(self):
        devices = self.cache_dir / "devices.db"
        devices.write_text(
            "192.0.2.8|OLD-SW|Unknown|ICX7150|SERIAL-8|0200.0000.0025|SNMP|100|OFFLINE\n",
            encoding="utf-8",
        )
        result = subprocess.run(
            [
                "bash",
                "-c",
                'source "$1"; db_update_device 192.0.2.8 NEW-SW Unknown N/A N/A N/A SSH ONLINE',
                "_",
                str(ROOT / "netops-lib.sh"),
            ],
            cwd=ROOT,
            env=self.env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        fields = devices.read_text(encoding="utf-8").strip().split("|")
        self.assertEqual(fields[1:7], ["NEW-SW", "Ruckus FastIron", "ICX7150", "SERIAL-8", "020000000025", "SNMP+SSH"])
        self.assertEqual(fields[8], "ONLINE")

    def test_python_helper_resolution_falls_back_to_installed_module(self):
        empty_install = Path(self.temp.name) / "empty-install"
        empty_install.mkdir()
        result = subprocess.run(
            [
                "bash",
                "-c",
                'source "$1"; NETOPS_INSTALL_DIR="$2"; netops_python_helper_path netops_devices netops_devices.py',
                "_",
                str(ROOT / "netops-lib.sh"),
                str(empty_install),
            ],
            cwd=ROOT,
            env=self.env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(Path(result.stdout.strip()).resolve(), (ROOT / "netops_devices.py").resolve())

    def test_direct_control_termination_reaps_nested_ssh_processes(self):
        (self.cache_dir / "devices.db").write_text(
            "127.0.0.1|FIXTURE-SW|Cisco|C9300|SERIAL|N/A|test|1|ONLINE\n",
            encoding="utf-8",
        )
        child_pid_file = Path(self.temp.name) / "control-ssh-child.pid"
        gpg = self.bin_dir / "gpg"
        sshpass = self.bin_dir / "sshpass"
        gpg.write_text("#!/usr/bin/env bash\nprintf 'fixture-password'\n", encoding="utf-8")
        sshpass.write_text(
            "#!/usr/bin/env bash\n"
            "printf 'FIXTURE-SW# '\n"
            "IFS= read -r line\n"
            "sleep 30 &\n"
            "child=$!\n"
            "printf '%s' \"$child\" > \"$CONTROL_CHILD_PID_FILE\"\n"
            "wait \"$child\"\n",
            encoding="utf-8",
        )
        gpg.chmod(0o700)
        sshpass.chmod(0o700)
        env = dict(self.env)
        env["CONTROL_CHILD_PID_FILE"] = str(child_pid_file)
        proc = subprocess.Popen(
            [str(ROOT / "netops-control"), "show", "127.0.0.1", "show version"],
            cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True,
        )
        child_pid = None
        try:
            deadline = time.monotonic() + 4
            while time.monotonic() < deadline and not child_pid_file.exists():
                time.sleep(0.05)
            self.assertTrue(child_pid_file.exists(), "nested SSH fixture did not start")
            child_pid = int(child_pid_file.read_text(encoding="utf-8"))
            os.kill(proc.pid, signal.SIGTERM)
            proc.communicate(timeout=5)
            self.assertEqual(proc.returncode, 143)
            with self.assertRaises(ProcessLookupError):
                os.kill(child_pid, 0)
        finally:
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=5)
            if child_pid is not None:
                try:
                    os.kill(child_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_backups_use_safe_atomic_names_and_reuse_real_path_when_unchanged(self):
        (self.cache_dir / "devices.db").write_text(
            "127.0.0.1|../../escape|Cisco|C9300|SERIAL|N/A|test|1|ONLINE\n",
            encoding="utf-8",
        )
        gpg = self.bin_dir / "gpg"
        sshpass = self.bin_dir / "sshpass"
        gpg.write_text("#!/usr/bin/env bash\nprintf 'fixture-password'\n", encoding="utf-8")
        sshpass.write_text(
            "#!/usr/bin/env bash\n"
            "printf 'hostname fixture\\ninterface GigabitEthernet1/0/1\\n description fixture\\n'\n",
            encoding="utf-8",
        )
        gpg.chmod(0o700)
        sshpass.chmod(0o700)
        backup_dir = Path(self.temp.name) / "backups"

        first = self.run_helper("netops-control", "backup", "127.0.0.1", "--changed-only", "--output", str(backup_dir))
        second = self.run_helper("netops-control", "backup", "127.0.0.1", "--changed-only", "--output", str(backup_dir))
        self.assertEqual((first.returncode, second.returncode), (0, 0), first.stderr + second.stderr)
        configs = list(backup_dir.rglob("*.conf"))
        saved_configs = [path for path in configs if not path.is_symlink()]
        self.assertEqual(len(saved_configs), 1)
        self.assertTrue(saved_configs[0].resolve().is_relative_to(backup_dir.resolve()))
        self.assertNotIn("..", saved_configs[0].name)
        self.assertEqual(saved_configs[0].stat().st_mode & 0o777, 0o600)

        db = self.cache_dir / "netops.sqlite3"
        with sqlite3.connect(db) as connection:
            rows = connection.execute(
                "SELECT status,path FROM backup_history ORDER BY id"
            ).fetchall()
        self.assertEqual([row[0] for row in rows], ["saved", "unchanged"])
        self.assertEqual(rows[0][1], rows[1][1])
        self.assertTrue(Path(rows[1][1]).is_file())

    def test_discovery_dry_run_expands_targets_bounds_cidrs_and_cleans_runtime(self):
        before = set(glob.glob("/tmp/netops-discovery.*"))
        small = self.run_helper("netops-discovery", "--no-color", "--dry-run", "--update", "192.0.2.0/30")
        explicit_range = self.run_helper("netops-discovery", "--no-color", "--dry-run", "--update", "192.0.2.5-7")
        oversized = self.run_helper("netops-discovery", "--no-color", "--dry-run", "--update", "198.18.0.0/15")
        self.assertEqual(small.returncode, 0, small.stderr)
        self.assertIn("Would scan 2 target(s)", small.stdout)
        self.assertEqual(small.stdout.splitlines()[-2:], ["192.0.2.1", "192.0.2.2"])
        self.assertEqual(explicit_range.returncode, 0, explicit_range.stderr)
        self.assertEqual(explicit_range.stdout.splitlines()[-3:], ["192.0.2.5", "192.0.2.6", "192.0.2.7"])
        self.assertEqual(oversized.returncode, 6)
        self.assertIn("limit is 4096", oversized.stderr)
        self.assertNotIn("\x1b", small.stderr + explicit_range.stderr + oversized.stderr)
        self.assertRegex(small.stderr, r"^\[\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\]")
        self.assertEqual(set(glob.glob("/tmp/netops-discovery.*")) - before, set())

    def test_quick_speed_reuses_discovery_cache_and_runs_one_paired_session(self):
        helper_log = Path(self.temp.name) / "speed-helper.log"
        servers = json.dumps(
            {
                "ok": True,
                "backend": "fixture",
                "tls_trust": {"verified": True, "source": "fixture-ca"},
                "servers": [{"id": 42, "host": "speed.example:8080", "sponsor": "Fixture", "name": "Lab"}],
            }
        )
        pair = json.dumps(
            {
                "ok": True,
                "directions": {
                    "upload": {"megabits_per_second": 40.0, "bytes": 5_000_000, "loaded_latency_ms": {"avg": 8.0, "jitter": 1.0, "samples": 6}},
                    "download": {"megabits_per_second": 100.0, "bytes": 12_500_000, "loaded_latency_ms": {"avg": 12.0, "jitter": 2.0, "samples": 7}},
                },
            }
        )
        python = self.bin_dir / "python3"
        python.write_text(
            "#!/usr/bin/env bash\n"
            f"real_python={shlex.quote(sys.executable)}\n"
            "if [[ \"$*\" == *\"netops_speed.py\"* ]]; then\n"
            "  printf '%s\\n' \"$*\" >> \"$SPEED_HELPER_LOG\"\n"
            "  if [[ \" $* \" == *\" servers \"* ]]; then\n"
            f"    printf '%s\\n' {shlex.quote(servers)}\n"
            "  else\n"
            f"    printf '%s\\n' {shlex.quote(pair)}\n"
            "  fi\n"
            "  exit 0\n"
            "fi\n"
            "exec \"$real_python\" \"$@\"\n",
            encoding="utf-8",
        )
        ping = self.bin_dir / "ping"
        ping.write_text(
            "#!/usr/bin/env bash\n"
            "printf '64 bytes from speed.example: time=4.0 ms\\n64 bytes from speed.example: time=6.0 ms\\n2 packets transmitted, 2 received, 0%% packet loss\\n'\n",
            encoding="utf-8",
        )
        ip = self.bin_dir / "ip"
        ip.write_text(
            "#!/usr/bin/env bash\n"
            "case \"$*\" in\n"
            "  'route get 1.1.1.1') printf '1.1.1.1 via 192.0.2.1 dev fixture0 src 192.0.2.2\\n' ;;\n"
            "  '-o link show up') printf '2: fixture0: <UP> mtu 1500\\n' ;;\n"
            "esac\n",
            encoding="utf-8",
        )
        for path in (python, ping, ip):
            path.chmod(0o700)
        env = dict(self.env)
        env["SPEED_HELPER_LOG"] = str(helper_log)

        first = subprocess.run(
            [str(ROOT / "netops-probe"), "--speed-test", "--profile", "quick", "--runs", "1", "--json"],
            cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
        )
        second = subprocess.run(
            [str(ROOT / "netops-probe"), "--speed-test", "--profile", "quick", "--json"],
            cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
        )
        self.assertEqual((first.returncode, second.returncode), (0, 0), first.stderr + second.stderr)
        self.assertTrue(first.stdout.strip(), first.stderr)
        self.assertTrue(second.stdout.strip(), second.stderr)
        first_payload = json.loads(first.stdout)
        second_payload = json.loads(second.stdout)
        self.assertFalse(first_payload["server_discovery"]["cached"])
        self.assertTrue(second_payload["server_discovery"]["cached"])
        self.assertEqual(first_payload["latency_samples"], {"idle": 2, "loaded_download": 7, "loaded_upload": 6})
        calls = helper_log.read_text(encoding="utf-8").splitlines()
        self.assertEqual(sum(" servers " in f" {line} " for line in calls), 1)
        self.assertEqual(sum(" run " in f" {line} " and "--direction both" in line for line in calls), 2)

        real_jq = shutil.which("jq", path=os.environ.get("PATH"))
        self.assertIsNotNone(real_jq)
        jq = self.bin_dir / "jq"
        jq.write_text(
            "#!/usr/bin/env bash\n"
            "if [[ \"${1:-}\" == '-n' ]]; then exit 7; fi\n"
            f"exec {shlex.quote(str(real_jq))} \"$@\"\n",
            encoding="utf-8",
        )
        jq.chmod(0o700)
        render_failure = subprocess.run(
            [str(ROOT / "netops-probe"), "--speed-test", "--profile", "quick", "--json"],
            cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
        )
        self.assertEqual(render_failure.returncode, 10)
        self.assertIn("could not render", render_failure.stderr)

    def test_direct_speed_termination_reaps_transfer_descendant_and_runtime(self):
        transfer_child_file = Path(self.temp.name) / "speed-transfer-child.pid"
        servers = json.dumps(
            {
                "ok": True,
                "backend": "fixture",
                "tls_trust": {"verified": True, "source": "fixture-ca"},
                "servers": [{"id": 42, "host": "speed.example:8080", "sponsor": "Fixture", "name": "Lab"}],
            }
        )
        python = self.bin_dir / "python3"
        python.write_text(
            "#!/usr/bin/env bash\n"
            "if [[ \" $* \" == *\" servers \"* ]]; then\n"
            f"  printf '%s\\n' {shlex.quote(servers)}\n"
            "  exit 0\n"
            "fi\n"
            "sleep 30 &\n"
            "child=$!\n"
            "printf '%s' \"$child\" > \"$SPEED_TRANSFER_CHILD_FILE\"\n"
            "wait \"$child\"\n",
            encoding="utf-8",
        )
        ping = self.bin_dir / "ping"
        ping.write_text(
            "#!/usr/bin/env bash\n"
            "printf '64 bytes from speed.example: time=4.0 ms\\n1 packets transmitted, 1 received, 0%% packet loss\\n'\n",
            encoding="utf-8",
        )
        ip = self.bin_dir / "ip"
        ip.write_text(
            "#!/usr/bin/env bash\n"
            "case \"$*\" in\n"
            "  'route get 1.1.1.1') printf '1.1.1.1 via 192.0.2.1 dev fixture0 src 192.0.2.2\\n' ;;\n"
            "  '-o link show up') printf '2: fixture0: <UP> mtu 1500\\n' ;;\n"
            "esac\n",
            encoding="utf-8",
        )
        for path in (python, ping, ip):
            path.chmod(0o700)
        env = dict(self.env)
        env["SPEED_TRANSFER_CHILD_FILE"] = str(transfer_child_file)
        before = set(glob.glob("/tmp/netops-speed.*"))
        proc = subprocess.Popen(
            [str(ROOT / "netops-probe"), "--speed-test", "--profile", "quick", "--json"],
            cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True,
        )
        child_pid = None
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and not transfer_child_file.exists():
                time.sleep(0.05)
            self.assertTrue(transfer_child_file.exists(), "speed transfer fixture did not start")
            child_pid = int(transfer_child_file.read_text(encoding="utf-8"))
            os.kill(proc.pid, signal.SIGTERM)
            proc.communicate(timeout=5)
            self.assertEqual(proc.returncode, 143)
            with self.assertRaises(ProcessLookupError):
                os.kill(child_pid, 0)
            self.assertEqual(set(glob.glob("/tmp/netops-speed.*")) - before, set())
        finally:
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=5)
            if child_pid is not None:
                try:
                    os.kill(child_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_interface_sampler_uses_real_ifindex_and_reuses_cached_identity(self):
        base = Path(self.temp.name)
        fixture_bin = base / "snmp-bin"
        fixture_bin.mkdir()
        walk_log = base / "walk.log"
        sysname_log = base / "sysname.log"
        counter_log = base / "counter.log"

        (fixture_bin / "sleep").write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
        (fixture_bin / "snmpwalk").write_text(
            """#!/usr/bin/env bash
printf 'walk\\n' >> "$SNMP_WALK_LOG"
cat <<'EOF'
.1.3.6.1.2.1.2.2.1.2.2 = STRING: Vlan1
.1.3.6.1.2.1.2.2.1.2.47 = STRING: GigabitEthernet1/0/1
EOF
""",
            encoding="utf-8",
        )
        (fixture_bin / "snmpget").write_text(
            """#!/usr/bin/env bash
if [[ "$*" == *"sysName.0"* ]]; then
    printf 'sysname\\n' >> "$SNMP_SYSNAME_LOG"
    exit 0
fi
if [[ "$*" == *"ifInOctets.47"* && "$*" != *"ifHCInOctets.47"* ]]; then
    printf '100\\n50\\n1000\\n1\\n1\\n'
    exit 0
fi
[[ "$*" == *"ifHCInOctets.47"* ]] || exit 8
printf 'sample\\n' >> "$SNMP_COUNTER_LOG"
n=$(wc -l < "$SNMP_COUNTER_LOG")
case "$n" in
    1) printf '1000\\n2000\\n1000\\n1\\n1\\n' ;;
    2) printf '100001000\\n50002000\\n1000\\n1\\n1\\n' ;;
    *) printf '200001000\\n100002000\\n1000\\n1\\n1\\n' ;;
esac
""",
            encoding="utf-8",
        )
        for path in fixture_bin.iterdir():
            path.chmod(0o700)

        env = dict(self.env)
        env.update(
            {
                "PATH": f"{fixture_bin}:{env.get('PATH', '')}",
                "SNMP_WALK_LOG": str(walk_log),
                "SNMP_SYSNAME_LOG": str(sysname_log),
                "SNMP_COUNTER_LOG": str(counter_log),
            }
        )

        first = subprocess.run(
            [
                str(ROOT / "netops-legacy"),
                "interface",
                "192.0.2.10",
                "on",
                "Gi1/0/1",
                "--json",
                "--once",
                "--interval",
                "1",
                "--community",
                "public",
            ],
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
        )
        self.assertEqual(first.returncode, 0, first.stderr)
        sample = json.loads(first.stdout)
        self.assertEqual(sample["interface_index"], 47)
        self.assertEqual(sample["interface_name"], "GigabitEthernet1/0/1")
        self.assertEqual(sample["in_bps"], 800_000_000)
        self.assertEqual(sample["out_bps"], 400_000_000)
        self.assertEqual(sample["aggregate_bps"], 1_200_000_000)
        self.assertEqual(sample["peak_direction_bps"], 800_000_000)
        self.assertEqual(sample["utilization_pct"], 80)
        self.assertEqual(sample["counters"]["in_octets"], 100_001_000)
        self.assertRegex(sample["timestamp"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

        second = subprocess.run(
            [
                str(ROOT / "netops-legacy"),
                "interface",
                "192.0.2.10",
                "on",
                "Gi1/0/1",
                "--json",
                "--once",
                "--interval",
                "1",
                "--community",
                "public",
                "--if-index",
                str(sample["interface_index"]),
                "--if-name",
                sample["interface_name"],
                "--baseline-in",
                str(sample["counters"]["in_octets"]),
                "--baseline-out",
                str(sample["counters"]["out_octets"]),
                "--baseline-speed",
                str(sample["speed_mbps"]),
                "--baseline-admin",
                str(sample["admin_status_code"]),
                "--baseline-oper",
                str(sample["oper_status_code"]),
                "--counter-bits",
                str(sample["counter_bits"]),
            ],
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
        )
        self.assertEqual(second.returncode, 0, second.stderr)
        cached_sample = json.loads(second.stdout)
        self.assertEqual(cached_sample["interface_index"], 47)
        self.assertEqual(walk_log.read_text(encoding="utf-8").splitlines(), ["walk"])
        self.assertEqual(sysname_log.read_text(encoding="utf-8").splitlines(), ["sysname"])

        wrapped = subprocess.run(
            [
                str(ROOT / "netops-legacy"),
                "interface",
                "192.0.2.10",
                "on",
                "Gi1/0/1",
                "--json",
                "--once",
                "--interval",
                "1",
                "--community",
                "public",
                "--if-index",
                "47",
                "--if-name",
                "GigabitEthernet1/0/1",
                "--baseline-in",
                "4294967200",
                "--baseline-out",
                "4294967100",
                "--baseline-speed",
                "1000",
                "--baseline-admin",
                "1",
                "--baseline-oper",
                "1",
                "--counter-bits",
                "32",
            ],
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
        )
        self.assertEqual(wrapped.returncode, 0, wrapped.stderr)
        wrap_sample = json.loads(wrapped.stdout)
        self.assertEqual(wrap_sample["in_bps"], 1568)
        self.assertEqual(wrap_sample["out_bps"], 1968)
        self.assertFalse(wrap_sample["counter_reset_detected"])


if __name__ == "__main__":
    unittest.main()
