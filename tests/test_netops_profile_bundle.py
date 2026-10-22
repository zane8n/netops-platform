import io
import os
import shutil
import sqlite3
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from netops_platform import profile_bundle
from netops_platform.profiles import ProfileStore


class ProfileBundleTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        self.old, self.new = base / "old", base / "new"
        config, cache, state, data = (self.old / name for name in ("config", "cache", "state", "data"))
        for path in (config / "channels", cache, state, data / "backups"):
            path.mkdir(parents=True)
        (config / "profile.toml").write_text('[network]\ncisco_wlc_ip = "198.51.100.131"\n')
        (config / "netsnmp.conf").write_text("cisco_wlc_ap_name_prefix=SITEA\n")
        (config / "netsnmp.conf.before-kibali-filter").write_text("old\n")
        (config / ".env").write_text("communities=example-community\n")
        (config / "known_hosts").write_text("192.0.2.10 ssh-ed25519 AAAAexample\n")
        (config / "channels" / "site.json").write_text("{}\n")
        (cache / "devices.db").write_text("192.0.2.10|SITE-A-CORE-SW01|Cisco||||||ONLINE\n")
        (cache / "snmp_cache.db").write_text("192.0.2.10|example-community|v2c\n")
        (cache / "devices.db.lock").write_text("")
        (data / "backups" / "SITE-A-CORE-SW01.cfg").write_text("hostname SITE-A-CORE-SW01\n")
        con = sqlite3.connect(state / "netrune.sqlite3")
        con.execute("CREATE TABLE memory(fact TEXT)")
        con.execute("INSERT INTO memory VALUES ('kept')")
        con.commit()
        con.close()
        self.paths = SimpleNamespace(profile="site-a", config_dir=config, cache_dir=cache, sqlite_db=state / "netrune.sqlite3",
                                     backup_dir=data / "backups")
        self.env = mock.patch.dict(os.environ, {"HOME": str(self.new)}, clear=False)
        self.env.start()
        for name in ("XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "NETRUNE_CONFIG_DIR",
                     "NETOPS_CONFIG_DIR", "NETRUNE_CACHE_DIR", "NETOPS_CACHE_DIR", "NETRUNE_PROFILE", "NETOPS_PROFILE",
                     profile_bundle.PASSPHRASE_ENV):
            os.environ.pop(name, None)
        self.store = ProfileStore(self.new)

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def test_a_plain_bundle_carries_the_profile_but_never_its_communities(self):
        bundle = Path(self.temp.name) / "site-a.tgz"
        manifest = profile_bundle.export_bundle(self.paths, bundle)
        self.assertEqual(bundle.read_bytes()[:2], profile_bundle.GZIP_MAGIC)
        self.assertIn("config/known_hosts", manifest["files"])
        self.assertNotIn("config/.env", manifest["files"])
        self.assertNotIn("cache/snmp_cache.db", manifest["files"])
        self.assertNotIn("cache/devices.db.lock", manifest["files"])
        self.assertNotIn("config/netsnmp.conf.before-kibali-filter", manifest["files"])
        self.assertNotIn("state/netrune.sqlite3", manifest["files"])
        result = profile_bundle.import_bundle(self.store, bundle)
        layout = self.store.layout("site-a")
        self.assertEqual(result["profile"], "site-a")
        self.assertEqual(self.store.active(), "site-a")
        self.assertIn("SITEA", (layout.config_dir / "netsnmp.conf").read_text())
        self.assertTrue((layout.cache_dir / "devices.db").is_file())
        self.assertFalse((layout.config_dir / ".env").exists())
        self.assertEqual(oct((layout.config_dir / "known_hosts").stat().st_mode & 0o777), "0o600")

    @unittest.skipUnless(shutil.which("gpg"), "gpg not installed")
    def test_a_bundle_with_secrets_is_encrypted_and_restores_memory_and_communities(self):
        bundle = Path(self.temp.name) / "site-a.tgz.gpg"
        with mock.patch.dict(os.environ, {profile_bundle.PASSPHRASE_ENV: "correct horse"}):
            manifest = profile_bundle.export_bundle(self.paths, bundle, with_state=True, with_secrets=True)
        self.assertNotEqual(bundle.read_bytes()[:2], profile_bundle.GZIP_MAGIC)
        self.assertNotIn(b"example-community", bundle.read_bytes())
        self.assertIn("state/netrune.sqlite3", manifest["files"])
        with mock.patch.dict(os.environ, {profile_bundle.PASSPHRASE_ENV: "wrong"}), self.assertRaises(profile_bundle.BundleError):
            profile_bundle.import_bundle(self.store, bundle)
        with mock.patch.dict(os.environ, {profile_bundle.PASSPHRASE_ENV: "correct horse"}):
            profile_bundle.import_bundle(self.store, bundle, as_name="lab")
        layout = self.store.layout("lab")
        self.assertIn("example-community", (layout.config_dir / ".env").read_text())
        self.assertTrue((layout.cache_dir / "snmp_cache.db").is_file())
        self.assertTrue((layout.data_dir / "backups" / "SITE-A-CORE-SW01.cfg").is_file())
        rows = sqlite3.connect(layout.state_dir / "netrune.sqlite3").execute("SELECT fact FROM memory").fetchall()
        self.assertEqual(rows, [("kept",)])

    def test_an_existing_profile_is_kept_unless_forced_and_force_keeps_the_old_files(self):
        bundle = Path(self.temp.name) / "site-a.tgz"
        profile_bundle.export_bundle(self.paths, bundle)
        profile_bundle.import_bundle(self.store, bundle)
        layout = self.store.layout("site-a")
        (layout.config_dir / "aliases.yaml").write_text("mine: 192.0.2.99\n")
        with self.assertRaises(profile_bundle.BundleError):
            profile_bundle.import_bundle(self.store, bundle)
        profile_bundle.import_bundle(self.store, bundle, force=True)
        kept = list(layout.config_dir.glob("known_hosts.before-import-*"))
        self.assertEqual(len(kept), 1)

    def test_entries_that_would_escape_the_profile_are_refused(self):
        bundle = Path(self.temp.name) / "evil.tgz"
        with tarfile.open(bundle, "w:gz") as tar:
            for name in ("manifest.json", "config/../../escaped"):
                data = b'{"bundle_version": 1, "profile": "evil"}' if name == "manifest.json" else b"x"
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        with self.assertRaises(profile_bundle.BundleError):
            profile_bundle.import_bundle(self.store, bundle)
        self.assertFalse((Path(self.temp.name) / "escaped").exists())


class ProfilePackCommandTest(unittest.TestCase):
    def setUp(self):
        import netops_core as netops
        self.netops = netops
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        self.env = mock.patch.dict(os.environ, {
            "NETOPS_CONFIG_DIR": str(base / "config"), "NETOPS_CACHE_DIR": str(base / "cache"),
            "NETOPS_STATE_DIR": str(base / "state"), "NETOPS_DATA_DIR": str(base / "data"),
            "NETOPS_SQLITE_DB": str(base / "state" / "netrune.sqlite3"), "NETOPS_BACKUP_DIR": str(base / "backups"),
            "NETOPS_PROGRESS": "0", "HOME": str(base / "home"),
        }, clear=False)
        self.env.start()
        self.app = netops.App(Path(__file__).resolve().parents[1])
        self.app.paths.env_file.write_text("communities=example-community\n")
        self.bundle = base / "site.tgz.gpg"

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def run_cli(self, *args):
        out = io.StringIO()
        import contextlib
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            code = self.app.dispatch(["profile", "pack", str(self.bundle), *args, "--plain"])
        return code, out.getvalue()

    def test_pack_previews_without_confirm_and_writes_an_encrypted_bundle_with_it(self):
        code, output = self.run_cli()
        self.assertEqual(code, self.netops.CONFIRM_REQUIRED, output)
        self.assertIn("Re-run with --confirm", output)
        self.assertIn("SNMP communities", output)
        self.assertFalse(self.bundle.exists())
        if not shutil.which("gpg"):
            self.skipTest("gpg not installed")
        with mock.patch.dict(os.environ, {profile_bundle.PASSPHRASE_ENV: "correct horse"}):
            code, output = self.run_cli("--confirm")
        self.assertEqual(code, self.netops.SUCCESS, output)
        self.assertIn("./install.sh --import", output)
        raw = self.bundle.read_bytes()
        self.assertNotEqual(raw[:2], profile_bundle.GZIP_MAGIC)
        self.assertNotIn(b"example-community", raw)
        event = self.app.state.one("SELECT action FROM audit_events WHERE action='profile-pack'")
        self.assertIsNotNone(event)
