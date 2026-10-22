import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import urllib.error

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from netops_platform.contracts import (
    CapabilityEvidenceV1,
    IngestRunV1,
    ObservationV1,
    PathRequestV1,
    PluginDescriptorV1,
)
from netops_platform.devices import DeviceDriver
from netops_platform.ingest import IngestManager, SameOriginRedirectHandler, SecretResolver, load_manifest
from netops_platform.path_inspector import PathInspector
from netops_platform.plugins import LoadedPlugin, PluginManager
from netops_platform.privacy import scan_archive, scan_git_history, scan_tree
from netops_platform.profiles import NEUTRAL_PROFILE, ProfileStore, read_kv
from netops_platform.release import release_metadata, write_release_metadata
from netops_platform.support import create_support_bundle
from netops_devices import REGISTRY as DEVICE_REGISTRY
from create_public_export import PUBLIC_COMMIT_BODY, PUBLIC_COMMIT_SUBJECT, repository_files, stage_export, PRIVATE_END, PRIVATE_START, strip_private


INGEST_SCHEMA = """
CREATE TABLE devices(ip TEXT PRIMARY KEY,hostname TEXT,platform TEXT,model TEXT,serial TEXT,mac TEXT,source TEXT,last_seen INTEGER,status TEXT);
CREATE TABLE ingest_channels(name TEXT PRIMARY KEY,kind TEXT,enabled INTEGER,manifest_path TEXT,config_json TEXT,created_at INTEGER,updated_at INTEGER);
CREATE TABLE ingest_runs(run_id TEXT PRIMARY KEY,channel TEXT,status TEXT,started_at INTEGER,finished_at INTEGER,received INTEGER DEFAULT 0,accepted INTEGER DEFAULT 0,duplicates INTEGER DEFAULT 0,rejected INTEGER DEFAULT 0,message TEXT,request_json TEXT,result_json TEXT);
CREATE TABLE observations(id INTEGER PRIMARY KEY AUTOINCREMENT,idempotency_key TEXT UNIQUE,entity_kind TEXT,stable_source_id TEXT,channel TEXT,observed_at INTEGER,received_at INTEGER,completeness TEXT,status TEXT,confidence INTEGER,provenance_json TEXT,facts_json TEXT,raw_evidence_hash TEXT,run_id TEXT);
CREATE TABLE observation_fields(observation_id INTEGER,field_name TEXT,value_json TEXT,source TEXT,confidence INTEGER,observed_at INTEGER,PRIMARY KEY(observation_id,field_name));
CREATE TABLE observation_rejects(id INTEGER PRIMARY KEY AUTOINCREMENT,run_id TEXT,channel TEXT,received_at INTEGER,record_index INTEGER,error_code TEXT,message TEXT,raw_evidence_hash TEXT,redacted_record_json TEXT);
"""


PATH_SCHEMA = """
CREATE TABLE devices(ip TEXT PRIMARY KEY,hostname TEXT,platform TEXT,model TEXT,serial TEXT,mac TEXT,status TEXT,last_seen INTEGER);
CREATE TABLE inventory_identity_state(identity_value TEXT,ip TEXT,name TEXT,entity_type TEXT);
CREATE TABLE neighbors(local_ip TEXT,local_name TEXT,local_port TEXT,remote_name TEXT,remote_port TEXT,remote_ip TEXT);
CREATE TABLE relationships_current(rel_type TEXT,subject_id TEXT,switch_ip TEXT,switch_name TEXT,switch_port TEXT,confidence INTEGER,last_seen INTEGER,updated_at INTEGER,attrs_json TEXT,source TEXT,status TEXT,object_id TEXT);
CREATE TABLE aps(ip TEXT,name TEXT,switch_ip TEXT,switch_name TEXT,switch_port TEXT,last_seen INTEGER,source TEXT);
CREATE TABLE scan_runs(id TEXT,domain TEXT,started_at INTEGER,finished_at INTEGER);
CREATE TABLE capability_evidence(id INTEGER PRIMARY KEY AUTOINCREMENT,device_id TEXT,capability TEXT,state TEXT,observed_at INTEGER,source TEXT,confidence INTEGER,facts_json TEXT,raw_evidence_hash TEXT,driver_family TEXT,parser_version TEXT);
CREATE TABLE path_runs(run_id TEXT PRIMARY KEY,status TEXT,endpoint TEXT,vlan INTEGER,source TEXT,destination TEXT,mode TEXT,depth INTEGER,max_nodes INTEGER,confidence INTEGER,started_at INTEGER,finished_at INTEGER,summary TEXT,request_json TEXT,result_json TEXT);
CREATE TABLE path_hops(run_id TEXT,sequence INTEGER,device_id TEXT,device_name TEXT,management_ip TEXT,ingress_interface TEXT,egress_interface TEXT,layer TEXT,vlan_state TEXT,forwarding_state TEXT,confidence INTEGER,evidence_observed_at INTEGER,evidence_json TEXT,PRIMARY KEY(run_id,sequence));
CREATE TABLE path_findings(id INTEGER PRIMARY KEY AUTOINCREMENT,run_id TEXT,severity TEXT,code TEXT,message TEXT,device_id TEXT,interface TEXT,confidence INTEGER,evidence_observed_at INTEGER,evidence_json TEXT);
"""


class SQLiteState:
    def __init__(self, path: Path, schema: str):
        self.path = path
        with self.connect() as connection:
            connection.executescript(schema)

    @contextlib.contextmanager
    def connect(self):
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def rows(self, query, parameters=()):
        with self.connect() as connection:
            return [dict(row) for row in connection.execute(query, parameters).fetchall()]

    def one(self, query, parameters=()):
        rows = self.rows(query, parameters)
        return rows[0] if rows else None


class ContractsAndProfilesTest(unittest.TestCase):
    def test_tool_state_beside_the_source_is_skipped_but_source_is_not(self):
        """A finding nobody can act on is how a scanner gets ignored.

        Editor and agent directories sit next to the source and never ship, so
        flagging a path inside one is noise. Anything that does ship stays under
        the same scrutiny.
        """
        from netops_platform.privacy import scan_tree

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            # Built rather than written literally, so this fixture does not
            # trip the very scanner it is testing.
            home = "/" + "home" + "/" + "someone"
            (root / ".claude").mkdir()
            (root / ".claude" / "settings.local.json").write_text('{"p":"%s/"}' % home)
            (root / "shipped.py").write_text('PATH = "%s/secret"\n' % home)
            findings = scan_tree(root, [])
        paths = {finding.path for finding in findings}
        self.assertNotIn(".claude/settings.local.json", paths)
        self.assertIn("shipped.py", paths)

    def test_flat_compatibility_modules_alias_canonical_implementations(self):
        import netops_core
        import netops_devices
        import netops_speed
        from netrune import core as netrune_core
        from netrune import devices as netrune_devices
        from netops_platform import core, devices, speed

        self.assertIs(netops_core, core)
        self.assertIs(netops_devices, devices)
        self.assertIs(netops_speed, speed)
        self.assertIs(netrune_core, core)
        self.assertIs(netrune_devices, devices)

    def test_every_netops_platform_module_has_a_canonical_netrune_alias(self):
        """`netrune` is the documented canonical Python API (docs/migration-netrune.md).

        A module can land in `netops_platform` without anyone remembering to add
        its one-line mirror under `netrune/`, and nothing else notices: the CLI
        still works because it imports `netops_platform` directly. The gap only
        shows up as an ImportError for whoever follows the docs and writes
        `import netrune.<module>`. This enumerates both packages so a missing
        alias fails here instead of in an integrator's face.
        """
        import importlib
        import netops_platform
        import netrune

        implementation_dir = Path(netops_platform.__file__).parent
        alias_dir = Path(netrune.__file__).parent
        skip = {"__init__", "__main__", "launcher", "tui"}
        implementation_modules = {
            path.stem for path in implementation_dir.glob("*.py") if path.stem not in skip
        }
        alias_modules = {
            path.stem for path in alias_dir.glob("*.py") if path.stem not in skip
        }
        missing = implementation_modules - alias_modules
        self.assertEqual(missing, set(), f"netrune is missing aliases for: {sorted(missing)}")

        for name in implementation_modules:
            implementation = importlib.import_module(f"netops_platform.{name}")
            alias = importlib.import_module(f"netrune.{name}")
            self.assertIs(alias, implementation, f"netrune.{name} does not alias netops_platform.{name}")

    def test_netrune_environment_paths_take_precedence_over_legacy_aliases(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            environment = {
                "NETRUNE_CONFIG_DIR": str(root / "canonical-config"),
                "NETRUNE_CACHE_DIR": str(root / "canonical-cache"),
                "NETOPS_CONFIG_DIR": str(root / "legacy-config"),
                "NETOPS_CACHE_DIR": str(root / "legacy-cache"),
            }
            with mock.patch.dict(os.environ, environment, clear=False):
                layout = ProfileStore(root / "home").layout("default")
            self.assertEqual(layout.config_dir, root / "canonical-config")
            self.assertEqual(layout.cache_dir, root / "canonical-cache")

    def test_observation_idempotency_and_contract_bounds(self):
        first = ObservationV1(
            "device", "switch-001", "fixture", 1_700_000_000, 1_700_000_001,
            "partial", {"ip": "192.0.2.11", "status": "ONLINE"},
        )
        second = ObservationV1(
            "device", "switch-001", "fixture", 1_700_000_000, 1_700_000_099,
            "partial", {"ip": "192.0.2.11", "status": "ONLINE"},
        )
        self.assertEqual(first.idempotency_key, second.idempotency_key)
        self.assertEqual(len(first.raw_evidence_hash), 64)
        with self.assertRaises(ValueError):
            PathRequestV1("endpoint", 120, depth=17)
        with self.assertRaises(ValueError):
            IngestRunV1("run", "channel", "completed", 10, 11, received=1, accepted=2)
        evidence = CapabilityEvidenceV1("192.0.2.11", "stp", "supported", 10, "fixture", 90, {"state": "forwarding"})
        self.assertEqual(len(evidence.raw_evidence_hash), 64)

    def test_profile_paths_are_private_and_active_selection_is_explicit(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, {}, clear=False):
            home = Path(directory)
            for variable in ("XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "NETOPS_CONFIG_DIR", "NETOPS_CACHE_DIR", "NETOPS_STATE_DIR", "NETOPS_DATA_DIR", "NETOPS_PROFILE"):
                os.environ.pop(variable, None)
            store = ProfileStore(home)
            layout = store.ensure("lab")
            self.assertEqual(layout.config_dir, home / ".config" / "netrune" / "profiles" / "lab")
            for path in (layout.config_dir, layout.state_dir, layout.cache_dir, layout.data_dir):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
            self.assertNotEqual(store.active(), "lab")
            store.use("lab")
            self.assertEqual(store.active(), "lab")
            self.assertEqual(stat.S_IMODE((layout.config_dir / "profile.toml").stat().st_mode), 0o600)
            self.assertIn('[access]\nssh_user = ""', (layout.config_dir / "profile.toml").read_text(encoding="utf-8"))
            self.assertEqual(read_kv(layout.config_dir / "netsnmp.conf")["ssh_user"], "")

    def test_netrune_state_rename_copies_xdg_profiles_and_wal_safely(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, {}, clear=False):
            home = Path(directory)
            for variable in (
                "XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME",
                "NETRUNE_CONFIG_DIR", "NETRUNE_CACHE_DIR", "NETRUNE_STATE_DIR", "NETRUNE_DATA_DIR", "NETRUNE_PROFILE",
                "NETOPS_CONFIG_DIR", "NETOPS_CACHE_DIR", "NETOPS_STATE_DIR", "NETOPS_DATA_DIR", "NETOPS_PROFILE",
            ):
                os.environ.pop(variable, None)
            old_config = home / ".config" / "netops"
            old_profile = old_config / "profiles" / "default"
            old_profile.mkdir(parents=True)
            (old_config / "active_profile").write_text("default\n", encoding="utf-8")
            (old_profile / "profile.toml").write_text(NEUTRAL_PROFILE, encoding="utf-8")
            old_state = home / ".local" / "state" / "netops" / "profiles" / "default"
            old_state.mkdir(parents=True)
            old_database = old_state / "netops.sqlite3"
            source = sqlite3.connect(old_database)
            source.execute("PRAGMA journal_mode=WAL")
            source.execute("CREATE TABLE fixture(value TEXT)")
            source.execute("INSERT INTO fixture VALUES('preserved-through-wal')")
            source.commit()

            store = ProfileStore(home)
            layout = store.layout("default")
            new_database = layout.state_dir / "netrune.sqlite3"
            copied = sqlite3.connect(new_database)
            self.assertEqual(copied.execute("SELECT value FROM fixture").fetchone()[0], "preserved-through-wal")
            copied.close()
            self.assertTrue(old_database.is_file())
            self.assertTrue((layout.state_root / "migration-from-netops.json").is_file())
            self.assertEqual(store.rename_migration["action"], "copied")

            second = ProfileStore(home)
            self.assertEqual(second.rename_migration["action"], "not-needed")
            self.assertTrue(old_database.is_file())
            source.close()

    def test_legacy_migration_is_copy_first_sqlite_consistent_and_idempotent(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, {}, clear=False):
            home = Path(directory)
            for variable in ("XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "NETOPS_CONFIG_DIR", "NETOPS_CACHE_DIR", "NETOPS_STATE_DIR", "NETOPS_DATA_DIR", "NETOPS_PROFILE"):
                os.environ.pop(variable, None)
            legacy_config = home / ".config" / "netsnmp"
            legacy_cache = home / ".cache" / "netsnmp"
            legacy_config.mkdir(parents=True)
            legacy_cache.mkdir(parents=True)
            public = legacy_config / "netsnmp.conf"
            public.write_text('core_switch_ip="192.0.2.10"\ntarget_abbreviation_prefix="192.0"\n', encoding="utf-8")
            secret = legacy_config / ".env"
            secret.write_text('ssh_user="operator"\napi_token="example"\n', encoding="utf-8")
            aliases = legacy_config / "aliases.yaml"
            aliases.write_text("aliases:\n  core: SITE-A-CORE-01\n", encoding="utf-8")
            source_db = legacy_cache / "netops.sqlite3"
            source = sqlite3.connect(source_db)
            source.execute("CREATE TABLE fixture(value TEXT)")
            source.execute("INSERT INTO fixture VALUES('preserved')")
            source.commit()
            source.close()
            source_bytes = source_db.read_bytes()

            store = ProfileStore(home)
            first = store.migrate_legacy("legacy-local")
            target = store.layout("legacy-local")
            self.assertEqual(read_kv(target.config_dir / "netsnmp.conf")["core_switch_ip"], "192.0.2.10")
            self.assertEqual(read_kv(target.config_dir / "netsnmp.conf")["ssh_user"], "operator")
            self.assertEqual((target.config_dir / "aliases.yaml").read_text(encoding="utf-8"), aliases.read_text(encoding="utf-8"))
            self.assertFalse((target.config_dir / ".env").exists())
            self.assertEqual(first["pending_secret_names"], ["api_token"])
            self.assertEqual(first["imported_public_keys"], ["ssh_user"])
            copied = sqlite3.connect(target.state_dir / "netrune.sqlite3")
            self.assertEqual(copied.execute("SELECT value FROM fixture").fetchone()[0], "preserved")
            copied.close()
            second = store.migrate_legacy("legacy-local")
            self.assertIn(str(source_db), second["skipped"])
            self.assertEqual(source_db.read_bytes(), source_bytes)
            self.assertTrue(first["source_files_unchanged"] and second["source_files_unchanged"])

    def test_legacy_migration_replaces_only_schema_only_initialized_database(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, {}, clear=False):
            home = Path(directory)
            for variable in ("XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "NETOPS_CONFIG_DIR", "NETOPS_CACHE_DIR", "NETOPS_STATE_DIR", "NETOPS_DATA_DIR", "NETOPS_PROFILE"):
                os.environ.pop(variable, None)
            legacy_cache = home / ".cache" / "netsnmp"
            legacy_cache.mkdir(parents=True)
            source_db = legacy_cache / "netops.sqlite3"
            source = sqlite3.connect(source_db)
            source.execute("CREATE TABLE devices(ip TEXT PRIMARY KEY, hostname TEXT)")
            source.execute("INSERT INTO devices VALUES('192.0.2.11', 'SITE-A-ACCESS-01')")
            source.commit()
            source.close()
            source_bytes = source_db.read_bytes()

            store = ProfileStore(home)
            target = store.ensure("legacy-local")
            destination_db = target.state_dir / "netrune.sqlite3"
            initialized = sqlite3.connect(destination_db)
            initialized.execute("CREATE TABLE schema_meta(key TEXT PRIMARY KEY, value TEXT)")
            initialized.execute("INSERT INTO schema_meta VALUES('schema_version', '12')")
            initialized.execute("CREATE TABLE devices(ip TEXT PRIMARY KEY, hostname TEXT)")
            initialized.commit()
            initialized.close()

            result = store.migrate_legacy("legacy-local")
            self.assertEqual(result["database_migration"]["action"], "replaced-schema-only-destination")
            self.assertTrue(Path(result["database_migration"]["backup"]).is_file())
            migrated = sqlite3.connect(destination_db)
            self.assertEqual(migrated.execute("SELECT hostname FROM devices").fetchone()[0], "SITE-A-ACCESS-01")
            migrated.close()
            self.assertEqual(source_db.read_bytes(), source_bytes)

            second = store.migrate_legacy("legacy-local")
            self.assertEqual(second["database_migration"]["action"], "skipped-populated-destination")

    def test_legacy_migration_never_overwrites_populated_profile_database(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, {}, clear=False):
            home = Path(directory)
            for variable in ("XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "NETOPS_CONFIG_DIR", "NETOPS_CACHE_DIR", "NETOPS_STATE_DIR", "NETOPS_DATA_DIR", "NETOPS_PROFILE"):
                os.environ.pop(variable, None)
            legacy_cache = home / ".cache" / "netsnmp"
            legacy_cache.mkdir(parents=True)
            source_db = legacy_cache / "netops.sqlite3"
            source = sqlite3.connect(source_db)
            source.execute("CREATE TABLE fixture(value TEXT)")
            source.execute("INSERT INTO fixture VALUES('legacy')")
            source.commit()
            source.close()

            store = ProfileStore(home)
            target = store.ensure("legacy-local")
            destination_db = target.state_dir / "netrune.sqlite3"
            destination = sqlite3.connect(destination_db)
            destination.execute("CREATE TABLE fixture(value TEXT)")
            destination.execute("INSERT INTO fixture VALUES('current')")
            destination.commit()
            destination.close()

            result = store.migrate_legacy("legacy-local")
            self.assertEqual(result["database_migration"]["action"], "skipped-populated-destination")
            preserved = sqlite3.connect(destination_db)
            self.assertEqual(preserved.execute("SELECT value FROM fixture").fetchone()[0], "current")
            preserved.close()


class IngestContractTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.channels = self.base / "channels"
        self.channels.mkdir()
        self.state = SQLiteState(self.base / "state.sqlite3", INGEST_SCHEMA)
        self.manager = IngestManager(self.state, self.channels)

    def tearDown(self):
        self.temp.cleanup()

    def write_channel(self, name="devices", data="devices.jsonl"):
        manifest = self.channels / f"{name}.toml"
        manifest.write_text(
            "schema_version = 1\n\n"
            "[channel]\n"
            f'name = "{name}"\nkind = "jsonl"\nenabled = true\nentity_kind = "device"\n'
            'source_id_field = "id"\nobserved_at_field = "observed_at"\n\n'
            "[reader]\n"
            f'path = "{data}"\ncompleteness = "partial"\nconfidence = 90\n\n'
            '[fields]\nip = "ip"\nhostname = "hostname"\nplatform = "platform"\nstatus = "status"\n',
            encoding="utf-8",
        )
        return manifest

    def test_duplicate_sparse_stale_and_field_provenance_behavior(self):
        self.write_channel()
        data = self.channels / "devices.jsonl"
        data.write_text(json.dumps({"id": "switch-001", "ip": "192.0.2.11", "hostname": "SITE-A-ACCESS-01", "platform": "Cisco IOS-XE", "status": "ONLINE", "observed_at": 200}) + "\n", encoding="utf-8")
        first = self.manager.run("devices")
        duplicate = self.manager.run("devices")
        self.assertEqual((first.accepted, duplicate.duplicates), (1, 1))
        data.write_text(json.dumps({"id": "switch-001", "ip": "192.0.2.11", "hostname": "STALE-NAME", "status": "OFFLINE", "observed_at": 100}) + "\n", encoding="utf-8")
        stale = self.manager.run("devices")
        self.assertEqual(stale.accepted, 1)
        device = self.state.one("SELECT * FROM devices WHERE ip='192.0.2.11'")
        self.assertEqual((device["hostname"], device["platform"], device["status"], device["last_seen"]), ("SITE-A-ACCESS-01", "Cisco IOS-XE", "ONLINE", 200))
        self.assertEqual(self.state.one("SELECT COUNT(*) AS count FROM observations")["count"], 2)
        fields = self.state.rows("SELECT field_name,source,confidence FROM observation_fields ORDER BY field_name")
        self.assertTrue(all(row["source"] == "devices" and row["confidence"] == 90 for row in fields))

    def test_large_ingest_uses_bounded_sqlite_batches(self):
        self.write_channel()
        data = self.channels / "devices.jsonl"
        data.write_text(
            "".join(
                json.dumps({
                    "id": f"switch-{index:04d}",
                    "ip": f"198.18.{index // 250}.{index % 250 + 1}",
                    "hostname": f"SITE-A-ACCESS-{index:04d}",
                    "status": "ONLINE",
                    "observed_at": 1_700_000_000 + index,
                }) + "\n"
                for index in range(600)
            ),
            encoding="utf-8",
        )
        with mock.patch.object(self.state, "connect", wraps=self.state.connect) as connections:
            result = self.manager.run("devices")
        self.assertEqual((result.status, result.accepted, result.rejected), ("completed", 600, 0))
        self.assertLessEqual(connections.call_count, 6)

    def test_invalid_record_is_quarantined_and_sensitive_fields_are_redacted(self):
        self.write_channel()
        data = self.channels / "devices.jsonl"
        data.write_text(json.dumps({"api_token": "example-value", "observed_at": 200}) + "\n", encoding="utf-8")
        result = self.manager.run("devices")
        self.assertEqual((result.status, result.rejected), ("failed", 1))
        reject = self.state.one("SELECT redacted_record_json FROM observation_rejects")
        self.assertEqual(json.loads(reject["redacted_record_json"])["api_token"], "[redacted]")

    def test_invalid_manifest_does_not_hide_valid_channels_or_duplicate_names(self):
        self.write_channel("valid")
        (self.channels / "broken.toml").write_text("schema_version = 9\n", encoding="utf-8")
        rows = self.manager.validation()
        self.assertEqual({row["status"] for row in rows}, {"valid", "invalid"})
        self.assertEqual([item.channel.name for item in self.manager.manifests()], ["valid"])
        self.write_channel("same", "devices.jsonl")
        duplicate = self.channels / "duplicate.toml"
        duplicate.write_text((self.channels / "same.toml").read_text(encoding="utf-8"), encoding="utf-8")
        self.assertEqual(sum(row["error"] == "duplicate ingest channel name" for row in self.manager.validation()), 2)

    def test_manifest_rejects_literal_credentials_and_cross_origin_pagination_is_bounded(self):
        manifest = self.channels / "http.toml"
        manifest.write_text(
            "schema_version = 1\n[channel]\nname = \"http\"\nkind = \"http-json\"\n"
            "[reader]\nurl = \"https://inventory.example/api/devices?token=example-value\"\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "credentials"):
            load_manifest(manifest)

    def test_secret_file_reference_requires_private_owner_only_permissions(self):
        secret = self.base / "secret"
        secret.write_text("fixture-value", encoding="utf-8")
        secret.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "0600"):
            SecretResolver().resolve(f"file:{secret}")
        secret.chmod(0o600)
        self.assertEqual(SecretResolver().resolve(f"file:{secret}"), "fixture-value")

    def test_secret_file_symlink_and_oversized_ingest_are_rejected(self):
        secret = self.base / "secret"
        secret.write_text("fixture-value", encoding="utf-8")
        secret.chmod(0o600)
        link = self.base / "secret-link"
        link.symlink_to(secret)
        with self.assertRaisesRegex(ValueError, "securely"):
            SecretResolver().resolve(f"file:{link}")
        self.write_channel()
        data = self.channels / "devices.jsonl"
        data.write_text("{}\n", encoding="utf-8")
        manifest = self.channels / "devices.toml"
        manifest.write_text(manifest.read_text(encoding="utf-8").replace("confidence = 90", "confidence = 90\nmax_bytes = 1"), encoding="utf-8")
        result = self.manager.run("devices")
        self.assertEqual(result.status, "failed")
        self.assertIn("max_bytes", result.message)

    def test_record_limit_stops_a_delivery_as_partial(self):
        self.write_channel()
        data = self.channels / "devices.jsonl"
        rows = [
            {"id": f"switch-{index}", "ip": f"192.0.2.{index}", "hostname": f"SITE-A-ACCESS-{index:02}", "observed_at": 200}
            for index in (11, 12)
        ]
        data.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
        manifest = self.channels / "devices.toml"
        manifest.write_text(manifest.read_text(encoding="utf-8").replace("confidence = 90", "confidence = 90\nmax_records = 1"), encoding="utf-8")
        result = self.manager.run("devices")
        self.assertEqual((result.status, result.accepted), ("partial", 1))
        self.assertIn("max_records", result.message)

    def test_pagination_cannot_change_origin(self):
        manifest_path = self.channels / "http.toml"
        manifest_path.write_text(
            "schema_version = 1\n[channel]\nname = \"http\"\nkind = \"http-json\"\n"
            "[reader]\nurl = \"https://inventory.example/api/devices\"\nrecords_path = \"items\"\nnext_path = \"next\"\n"
            "[fields]\nip = \"ip\"\n",
            encoding="utf-8",
        )
        manifest = load_manifest(manifest_path)
        with mock.patch.object(self.manager, "_http_json", return_value={"items": [], "next": "https://other.example/api/devices"}):
            with self.assertRaisesRegex(ValueError, "origin"):
                list(self.manager._read_http_records(manifest))
        handler = SameOriginRedirectHandler(("https", "inventory.example", 443))
        with self.assertRaisesRegex(urllib.error.HTTPError, "origin"):
            handler.redirect_request(None, None, 302, "Found", {}, "https://other.example/redirect")

    def test_http_rate_limit_retry_and_response_size_are_bounded(self):
        manifest_path = self.channels / "http.toml"
        manifest_path.write_text(
            "schema_version = 1\n[channel]\nname = \"http\"\nkind = \"http-json\"\n"
            "[reader]\nurl = \"https://inventory.example/api/devices\"\nrate_limit_attempts = 2\nmax_bytes = 32\n",
            encoding="utf-8",
        )
        manifest = load_manifest(manifest_path)

        class Response:
            headers = {"Content-Length": "2"}
            def __enter__(self): return self
            def __exit__(self, *_args): return False
            def geturl(self): return "https://inventory.example/api/devices"
            def read(self, _limit): return b"{}"

        opener = mock.Mock()
        opener.open.side_effect = [
            urllib.error.HTTPError("https://inventory.example/api/devices", 429, "rate", {"Retry-After": "invalid"}, None),
            Response(),
        ]
        with mock.patch("netops_platform.ingest.urllib.request.build_opener", return_value=opener), mock.patch("netops_platform.ingest.time.sleep") as sleep:
            self.assertEqual(self.manager._http_json("https://inventory.example/api/devices", manifest), {})
            sleep.assert_called_once_with(1)

        Response.headers = {"Content-Length": "33"}
        opener.open.side_effect = [Response()]
        with mock.patch("netops_platform.ingest.urllib.request.build_opener", return_value=opener):
            with self.assertRaisesRegex(ValueError, "max_bytes"):
                self.manager._http_json("https://inventory.example/api/devices", manifest)

    def test_enabled_plugin_provider_receives_only_declared_secrets_and_records_provenance(self):
        manifest = self.channels / "plugin.toml"
        manifest.write_text(
            "schema_version = 1\n[channel]\nname = \"plugin\"\nkind = \"plugin\"\n"
            "entity_kind = \"device\"\nsource_id_field = \"id\"\nobserved_at_field = \"observed_at\"\n"
            "[reader]\nprovider = \"fixture\"\nconfidence = 90\n"
            "[secrets]\ntoken = \"env:NETOPS_FIXTURE_PLUGIN_TOKEN\"\n"
            "[fields]\nip = \"ip\"\nhostname = \"hostname\"\nstatus = \"status\"\n",
            encoding="utf-8",
        )

        class Provider:
            seen = None

            @classmethod
            def read_records(cls, channel, reader, secrets):
                cls.seen = (channel.name, dict(reader), dict(secrets))
                return [{"id": "switch-plugin", "ip": "192.0.2.44", "hostname": "SITE-A-ACCESS-44", "status": "online", "observed_at": 1_700_000_000}]

        manager = IngestManager(
            self.state,
            self.channels,
            SecretResolver(),
            {"fixture": Provider},
            {"fixture": "distribution:fixture-plugin"},
        )
        with mock.patch.dict(os.environ, {"NETOPS_FIXTURE_PLUGIN_TOKEN": "fixture-secret"}):
            result = manager.run("plugin")
        self.assertEqual((result.status, result.accepted), ("completed", 1))
        self.assertEqual(Provider.seen[0], "plugin")
        self.assertEqual(Provider.seen[2], {"token": "fixture-secret"})
        observation = self.state.one("SELECT provenance_json FROM observations WHERE channel='plugin'")
        provenance = json.loads(observation["provenance_json"])
        self.assertEqual(provenance["provider_source"], "distribution:fixture-plugin")

    def test_plugin_provider_failure_redacts_declared_secret(self):
        manifest = self.channels / "failed-plugin.toml"
        manifest.write_text(
            "schema_version = 1\n[channel]\nname = \"failed-plugin\"\nkind = \"plugin\"\n"
            "[reader]\nprovider = \"fixture\"\n[secrets]\ntoken = \"env:NETOPS_FIXTURE_PLUGIN_TOKEN\"\n",
            encoding="utf-8",
        )

        class Provider:
            @staticmethod
            def read_records(_channel, _reader, secrets):
                raise RuntimeError("provider rejected " + secrets["token"])

        manager = IngestManager(self.state, self.channels, SecretResolver(), {"fixture": Provider})
        with mock.patch.dict(os.environ, {"NETOPS_FIXTURE_PLUGIN_TOKEN": "fixture-secret"}):
            result = manager.run("failed-plugin")
        self.assertEqual(result.status, "failed")
        self.assertIn("[redacted]", result.message)
        self.assertNotIn("fixture-secret", result.message)

    def test_builtin_snapshot_uses_same_idempotent_history_and_channel_catalog(self):
        records = [{
            "ip": "192.0.2.55",
            "hostname": "SITE-A-ACCESS-55",
            "platform": "Cisco IOS-XE",
            "status": "ONLINE",
            "last_seen": 1_700_000_000,
        }]
        first = self.manager.record_snapshot(
            "built-in-ssh-scan", "device", records,
            identity_fields=("ip",), source="ssh-scan", confidence=85,
        )
        second = self.manager.record_snapshot(
            "built-in-ssh-scan", "device", records,
            identity_fields=("ip",), source="ssh-scan", confidence=85,
        )
        self.assertEqual((first.accepted, first.duplicates), (1, 0))
        self.assertEqual((second.accepted, second.duplicates), (0, 1))
        channels = {row["name"]: row for row in self.manager.sync_channels()}
        self.assertEqual(channels["built-in-ssh-scan"]["status"], "built-in")
        self.assertEqual(self.state.one("SELECT COUNT(*) AS count FROM observations")["count"], 1)


class FakeDistribution:
    def __init__(self, name="fixture-plugin", version="1.0"):
        self.metadata = {"Name": name}
        self.version = version


class FakeEntryPoint:
    def __init__(self, name="fixture", group="netrune.parsers", value="fixture:plugin", implementation=None):
        self.name = name
        self.group = group
        self.value = value
        self.dist = FakeDistribution()
        self.implementation = implementation
        self.loads = 0

    def load(self):
        self.loads += 1
        if isinstance(self.implementation, Exception):
            raise self.implementation
        return self.implementation


class FakeEntryPoints(list):
    def select(self, *, group):
        return [entry for entry in self if entry.group == group]


class PluginPolicyTest(unittest.TestCase):
    def implementation(self, api="1", capabilities=()):
        return type("Plugin", (), {
            "NETRUNE_PLUGIN_API_VERSION": api,
            "NETRUNE_PLUGIN_CAPABILITIES": capabilities,
            "parse": staticmethod(lambda _parser_id, _text, _context=None: {}),
        })

    def test_disabled_plugins_are_not_imported_and_valid_enablement_is_recorded(self):
        with tempfile.TemporaryDirectory() as directory:
            entry = FakeEntryPoint(implementation=self.implementation())
            manager = PluginManager(Path(directory))
            with mock.patch("netops_platform.plugins.metadata.entry_points", return_value=FakeEntryPoints([entry])):
                discovered = manager.discover()
                self.assertEqual((discovered[0].load_status, entry.loads), ("disabled", 0))
                enabled = manager.set_enabled("netrune.parsers:fixture", True)
                self.assertEqual((enabled.load_status, enabled.api_version, entry.loads), ("loaded", "1", 1))
                self.assertEqual(stat.S_IMODE(manager.state_file.stat().st_mode), 0o600)

    def test_legacy_netops_plugin_group_and_metadata_remain_compatible(self):
        implementation = type("LegacyPlugin", (), {
            "NETOPS_PLUGIN_API_VERSION": "1",
            "NETOPS_PLUGIN_CAPABILITIES": (),
            "parse": staticmethod(lambda _parser_id, _text, _context=None: {}),
        })
        with tempfile.TemporaryDirectory() as directory:
            entry = FakeEntryPoint(group="netops.parsers", implementation=implementation)
            manager = PluginManager(Path(directory))
            with mock.patch("netops_platform.plugins.metadata.entry_points", return_value=FakeEntryPoints([entry])):
                enabled = manager.set_enabled("netops.parsers:fixture", True)
            self.assertEqual((enabled.group, enabled.load_status), ("netops.parsers", "loaded"))

    def test_incompatible_or_write_plugin_rolls_back_enablement(self):
        with tempfile.TemporaryDirectory() as directory:
            for implementation in (
                self.implementation("2"),
                self.implementation(capabilities=("Network_Write",)),
                self.implementation(capabilities=("network write",)),
                self.implementation(capabilities=("shell-execute",)),
            ):
                entry = FakeEntryPoint(implementation=implementation)
                manager = PluginManager(Path(directory) / str(entry.loads))
                with mock.patch("netops_platform.plugins.metadata.entry_points", return_value=FakeEntryPoints([entry])):
                    with self.assertRaisesRegex(ValueError, "could not be enabled"):
                        manager.set_enabled("netrune.parsers:fixture", True)
                    self.assertFalse(manager.discover()[0].enabled)

    def test_entry_point_collision_is_ambiguous(self):
        with tempfile.TemporaryDirectory() as directory:
            entries = FakeEntryPoints([FakeEntryPoint(implementation=self.implementation()), FakeEntryPoint(value="other:plugin", implementation=self.implementation())])
            manager = PluginManager(Path(directory))
            with mock.patch("netops_platform.plugins.metadata.entry_points", return_value=entries):
                self.assertTrue(all(row.load_status == "collision" for row in manager.discover()))
                with self.assertRaisesRegex(ValueError, "ambiguous"):
                    manager.set_enabled("netrune.parsers:fixture", True)

    def test_missing_enabled_plugin_and_unsafe_state_are_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            manager = PluginManager(Path(directory))
            manager._write_enabled({"netrune.parsers:missing"})
            with mock.patch("netops_platform.plugins.metadata.entry_points", return_value=FakeEntryPoints()):
                descriptor = manager.discover()[0]
                self.assertEqual((descriptor.load_status, descriptor.source), ("missing", "profile-state"))
                self.assertEqual(manager.load_enabled()[0].descriptor.load_status, "missing")
            manager.state_file.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "0600"):
                manager.discover()

    def test_plugin_ids_and_groups_are_strict(self):
        with tempfile.TemporaryDirectory() as directory:
            manager = PluginManager(Path(directory))
            with self.assertRaisesRegex(ValueError, "supported-group"):
                manager.set_enabled("unknown.group:fixture", True)
            with self.assertRaisesRegex(ValueError, "unsupported plugin group"):
                manager.load_enabled("unknown.group")

    def test_group_interface_is_checked_before_enablement(self):
        with tempfile.TemporaryDirectory() as directory:
            implementation = type("Plugin", (), {"NETRUNE_PLUGIN_API_VERSION": "1", "NETRUNE_PLUGIN_CAPABILITIES": ()})
            entry = FakeEntryPoint(implementation=implementation)
            manager = PluginManager(Path(directory))
            with mock.patch("netops_platform.plugins.metadata.entry_points", return_value=FakeEntryPoints([entry])):
                with self.assertRaisesRegex(ValueError, "must expose parse"):
                    manager.set_enabled("netrune.parsers:fixture", True)

    def test_device_driver_plugin_is_revalidated_and_profile_scoped(self):
        descriptor = PluginDescriptorV1(
            name="fixture",
            distribution="fixture-plugin",
            version="1.0",
            group="netrune.device_drivers",
            entry_point="fixture:driver",
            api_version="1",
            enabled=True,
            source="distribution:fixture-plugin",
            load_status="loaded",
        )
        driver = DeviceDriver(
            family="fixture-plugin-os",
            vendor="Example Networks",
            os_name="FixtureOS",
            device_kind="switch",
            support_level="claimed",
            pager_commands=("terminal length 0",),
            command_templates={"inventory": ("show system",)},
            capabilities={"inventory": "supported", "configuration": "firmware-gated"},
            parser_templates={"inventory": "fixture.inventory.v1"},
            detection_patterns={"platform": ("FixtureOS",)},
            detection_confidence=90,
            firmware_profiles=("fixture-1",),
            source="built-in",
        )
        registry = DEVICE_REGISTRY.clone()
        reports = registry.load_python_plugins([LoadedPlugin(descriptor, driver)])
        loaded = registry.get("fixture-plugin-os")
        self.assertEqual(reports[0]["status"], "loaded")
        self.assertEqual(loaded.source, "plugin:fixture-plugin:fixture")
        self.assertEqual(loaded.capability("configuration"), "unsupported")
        self.assertEqual(loaded.firmware_profiles, ())
        self.assertEqual(DEVICE_REGISTRY.detect(platform="FixtureOS").family, "unknown")

        unsafe = DeviceDriver(
            family="unsafe-plugin-os",
            vendor="Example Networks",
            os_name="UnsafeOS",
            device_kind="switch",
            support_level="claimed",
            command_templates={"inventory": ("configure terminal",)},
            capabilities={"inventory": "supported"},
            detection_patterns={"platform": ("UnsafeOS",)},
            detection_confidence=80,
        )
        rejected = registry.load_python_plugins([LoadedPlugin(descriptor, unsafe)])
        self.assertEqual(rejected[0]["status"], "rejected")
        self.assertEqual(registry.get("unsafe-plugin-os").family, "unknown")


class FakeConfig:
    def __init__(self):
        self.public = {"core_switch_ip": "192.0.2.1", "path_evidence_stale_seconds": "900"}


class FakePathApp:
    def __init__(self, state, *, blocked=False):
        self.state = state
        self.config = FakeConfig()
        self.blocked = blocked

    def resolve_device_record(self, value):
        rows = self.state.rows("SELECT * FROM devices WHERE ip=? OR lower(hostname)=lower(?)", (value, value))
        return (rows[0], []) if len(rows) == 1 else (None, rows)

    def inspect_vlan_node(self, device, vlan, mode, options):
        if device["ip"] == "192.0.2.1":
            carries = not self.blocked
            links = [{
                "port": "Gi1/0/48",
                "carries_vlan": carries,
                "neighbor": {"remote_ip": "192.0.2.2", "remote_name": "SITE-A-ACCESS-01"},
            }]
        else:
            links = [{
                "port": "Gi1/0/48",
                "carries_vlan": True,
                "neighbor": {"remote_ip": "192.0.2.1", "remote_name": "SITE-A-CORE-01"},
            }]
        return {
            "defined": True,
            "error": "",
            "links": links,
            "observed_at": 1_700_000_100,
            "state": "OK",
            "result": "PRESENT",
        }

    def inspect_path_forwarding_node(self, device, endpoint, vlan, options):
        if device["ip"] == "192.0.2.1":
            return {
                "observed_at": 1_700_000_108,
                "driver_family": "cisco-ios",
                "port": "Gi1/0/48",
                "selected": {"vlan": str(vlan), "port": "Gi1/0/48", "entry_type": "DYNAMIC"},
                "hits": [{"vlan": str(vlan), "port": "Gi1/0/48", "entry_type": "DYNAMIC"}],
                "neighbor": {"remote_ip": "192.0.2.2", "remote_name": "SITE-A-ACCESS-01", "remote_port": "Gi1/0/48"},
                "next_device": self.state.one("SELECT * FROM devices WHERE ip='192.0.2.2'"),
            }
        return {
            "observed_at": 1_700_000_109,
            "driver_family": "cisco-ios",
            "port": "Gi1/0/7",
            "selected": {"vlan": str(vlan), "port": "Gi1/0/7", "entry_type": "DYNAMIC"},
            "hits": [{"vlan": str(vlan), "port": "Gi1/0/7", "entry_type": "DYNAMIC"}],
            "neighbor": {},
            "next_device": {},
        }

    def inspect_path_layer3(self, device, vlan, options):
        return {
            "observed_at": 1_700_000_109,
            "driver_family": "cisco-ios",
            "interface": f"Vlan{vlan}",
            "exists": True,
            "state": "up",
            "parsed": True,
        }


class StpPathApp(FakePathApp):
    """A path app whose core switch reports the path port as STP blocking."""

    def __init__(self, state, *, stp_state="blocking"):
        super().__init__(state)
        self.stp_state = stp_state
        self.stp_calls = []

    def inspect_spanning_tree(self, device, options, *, vlan=0, interfaces=None, record=True):
        self.stp_calls.append((device["ip"], list(interfaces or [])))
        state = self.stp_state if device["ip"] == "192.0.2.1" else "forwarding"
        return {
            "observed_at": 1_700_000_109,
            "driver_family": "aruba-aos-switch",
            "parsed": True,
            "mode": "mstp",
            "is_root": False,
            "root_port": "Gi1/0/48",
            "ports": [
                {"port": "Gi1/0/48", "state": state, "role": "root", "edge": False,
                 "network_facing": state == "forwarding"},
            ],
            "uplinks": ["Gi1/0/48"] if state == "forwarding" else [],
        }


class PathInspectorTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.state = SQLiteState(Path(self.temp.name) / "path.sqlite3", PATH_SCHEMA)
        with self.state.connect() as connection:
            connection.executemany(
                "INSERT INTO devices VALUES(?,?,?,?,?,?,?,?)",
                [
                    ("192.0.2.1", "SITE-A-CORE-01", "Cisco IOS-XE 17.9", "C9500", "SYNTHETIC-CORE", "02:00:00:00:00:01", "ONLINE", 1_700_000_100),
                    ("192.0.2.2", "SITE-A-ACCESS-01", "Cisco IOS-XE 17.9", "C9300", "SYNTHETIC-EDGE", "02:00:00:00:00:02", "ONLINE", 1_700_000_100),
                ],
            )
            connection.execute("INSERT INTO neighbors VALUES(?,?,?,?,?,?)", ("192.0.2.1", "SITE-A-CORE-01", "Gi1/0/48", "SITE-A-ACCESS-01", "Gi1/0/48", "192.0.2.2"))
            connection.execute("INSERT INTO relationships_current(rel_type,subject_id,switch_ip,switch_name,switch_port,confidence,last_seen,updated_at,attrs_json,source,status) VALUES(?,?,?,?,?,?,?,?,?,?,?)", ("mac_location", "020000000025", "192.0.2.2", "SITE-A-ACCESS-01", "Gi1/0/7", 95, 1_700_000_100, 1_700_000_100, "{}", "fixture", "active"))
            connection.execute("INSERT INTO scan_runs VALUES(?,?,?,?)", ("scan-1", "topology", 1_700_000_000, 1_700_000_100))

    def tearDown(self):
        self.temp.cleanup()

    @mock.patch("netops_platform.path_inspector.time.time", return_value=1_700_000_110)
    def test_healthy_hybrid_path_is_complete_and_chronological(self, _clock):
        app = FakePathApp(self.state)
        inspector = PathInspector(app)
        result = inspector.inspect(PathRequestV1("02:00:00:00:00:25", 120, requested_at=1_700_000_110), object())
        payload = result.to_dict()
        self.assertEqual((result.status, len(result.hops)), ("COMPLETE", 2))
        self.assertEqual(payload["finished_at_iso"], "2023-11-14T22:15:10Z")
        self.assertEqual(payload["hops"][0]["device_name"], "SITE-A-ACCESS-01")
        self.assertEqual(payload["hops"][1]["device_name"], "SITE-A-CORE-01")
        self.assertEqual(payload["hops"][1]["layer"], "L2/L3")
        self.assertEqual(payload["hops"][1]["egress_interface"], "Vlan120")
        self.assertEqual(self.state.one("SELECT COUNT(*) AS count FROM path_runs")["count"], 1)
        self.assertEqual(len(inspector.history()), 1)
        self.assertEqual(inspector.show(result.run_id)["status"], "COMPLETE")
        run_ref = inspector.history("0200.0000.0025", 120)[0]["run_ref"]
        self.assertEqual(inspector.show(run_ref)["run_id"], result.run_id)
        self.assertEqual(inspector.show("02:00:00:00:00:25", 120)["run_id"], result.run_id)
        self.assertEqual(inspector.show("last", 120)["run_id"], result.run_id)

    @mock.patch("netops_platform.path_inspector.time.time", return_value=1_700_000_110)
    def test_stp_blocking_on_a_path_interface_blocks_the_hop(self, _clock):
        app = StpPathApp(self.state, stp_state="blocking")
        result = PathInspector(app).inspect(
            PathRequestV1("02:00:00:00:00:25", 120, requested_at=1_700_000_110), object()
        )
        codes = {finding.code for finding in result.findings}
        self.assertIn("STP_BLOCKING", codes)
        # Reported exactly once: the live read must not be re-judged from the
        # stored capability row.
        self.assertEqual(len([f for f in result.findings if f.code == "STP_BLOCKING"]), 1)
        core = next(hop for hop in result.hops if hop.device_name == "SITE-A-CORE-01")
        self.assertEqual(core.forwarding_state, "blocked")
        # The interfaces on the path are what gets asked about.
        self.assertIn(("192.0.2.1", ["Gi1/0/48"]), app.stp_calls)

    @mock.patch("netops_platform.path_inspector.time.time", return_value=1_700_000_110)
    def test_stp_forwarding_leaves_a_healthy_path_complete(self, _clock):
        app = StpPathApp(self.state, stp_state="forwarding")
        result = PathInspector(app).inspect(
            PathRequestV1("02:00:00:00:00:25", 120, requested_at=1_700_000_110), object()
        )
        self.assertEqual(result.status, "COMPLETE")
        self.assertNotIn("STP_BLOCKING", {finding.code for finding in result.findings})
        core = next(hop for hop in result.hops if hop.device_name == "SITE-A-CORE-01")
        self.assertEqual(core.forwarding_state, "forwarding")

    @mock.patch("netops_platform.path_inspector.time.time", return_value=1_700_000_110)
    def test_stp_inspection_failure_is_a_warning_not_a_crash(self, _clock):
        class BrokenStpApp(StpPathApp):
            def inspect_spanning_tree(self, device, options, **kwargs):
                raise RuntimeError("fixture stp transport timeout")

        result = PathInspector(BrokenStpApp(self.state)).inspect(
            PathRequestV1("02:00:00:00:00:25", 120, requested_at=1_700_000_110), object()
        )
        self.assertIn("STP_INSPECTION_FAILED", {finding.code for finding in result.findings})
        self.assertNotEqual(result.status, "ERROR")

    @mock.patch("netops_platform.path_inspector.time.time", return_value=1_700_000_110)
    def test_fresh_live_walk_supersedes_stale_cached_attachment(self, _clock):
        with self.state.connect() as connection:
            connection.execute(
                "UPDATE relationships_current SET last_seen=?,updated_at=? WHERE rel_type='mac_location'",
                (1_699_000_000, 1_699_000_000),
            )
        result = PathInspector(FakePathApp(self.state)).inspect(
            PathRequestV1("02:00:00:00:00:25", 120, requested_at=1_700_000_110), object()
        )
        self.assertEqual(result.status, "COMPLETE")
        self.assertNotIn("STALE_ENDPOINT_ATTACHMENT", {finding.code for finding in result.findings})

    @mock.patch("netops_platform.path_inspector.time.time", return_value=1_700_000_110)
    def test_partial_live_walk_is_not_collapsed_to_a_stale_shorter_attachment(self, _clock):
        vlan_inspections = []

        class PartialPathApp(FakePathApp):
            def inspect_path_forwarding_node(self, device, endpoint, vlan, options):
                if device["ip"] == "192.0.2.2":
                    return {
                        "observed_at": 1_700_000_109,
                        "driver_family": "cisco-ios",
                        "error": "fixture transport timeout",
                    }
                return super().inspect_path_forwarding_node(device, endpoint, vlan, options)

            def inspect_vlan_node(self, device, vlan, mode, options):
                vlan_inspections.append(device["ip"])
                return super().inspect_vlan_node(device, vlan, mode, options)

        with self.state.connect() as connection:
            connection.execute(
                "UPDATE relationships_current SET switch_ip=?,switch_name=?,switch_port=?,attrs_json=? "
                "WHERE rel_type='mac_location'",
                ("192.0.2.1", "SITE-A-CORE-01", "Gi1/0/9", json.dumps({"vlan": "120"})),
            )
        result = PathInspector(PartialPathApp(self.state)).inspect(
            PathRequestV1("02:00:00:00:00:25", 120, requested_at=1_700_000_110),
            object(),
        )
        self.assertEqual((result.status, len(result.hops)), ("PARTIAL", 2))
        self.assertEqual(result.hops[0].device_name, "SITE-A-ACCESS-01")
        self.assertNotIn("192.0.2.2", vlan_inspections)
        self.assertNotIn("STALE_ENDPOINT_ATTACHMENT", {finding.code for finding in result.findings})

    @mock.patch("netops_platform.path_inspector.time.time", return_value=1_700_000_110)
    def test_missing_trunk_is_a_confirmed_blocker(self, _clock):
        result = PathInspector(FakePathApp(self.state, blocked=True)).inspect(
            PathRequestV1("02:00:00:00:00:25", 120, requested_at=1_700_000_110), object()
        )
        self.assertEqual(result.status, "BLOCKED")
        self.assertIn("VLAN_MISSING_ON_TRUNK", {finding.code for finding in result.findings})

    @mock.patch("netops_platform.path_inspector.time.time", return_value=1_700_000_110)
    def test_cached_mode_and_ambiguous_attachment_are_partial(self, _clock):
        with self.state.connect() as connection:
            connection.execute("INSERT INTO relationships_current(rel_type,subject_id,switch_ip,switch_name,switch_port,confidence,last_seen,updated_at,attrs_json,source,status) VALUES(?,?,?,?,?,?,?,?,?,?,?)", ("mac_location", "020000000025", "192.0.2.1", "SITE-A-CORE-01", "Gi1/0/9", 80, 1_700_000_090, 1_700_000_090, "{}", "fixture", "active"))
        result = PathInspector(FakePathApp(self.state)).inspect(
            PathRequestV1("02:00:00:00:00:25", 120, mode="cached", requested_at=1_700_000_110), object()
        )
        self.assertEqual(result.status, "PARTIAL")
        self.assertIn("AMBIGUOUS_ENDPOINT_LOCATION", {finding.code for finding in result.findings})

    @mock.patch("netops_platform.path_inspector.time.time", return_value=1_700_000_110)
    def test_cached_attachment_from_another_vlan_is_not_used_as_a_path_edge(self, _clock):
        with self.state.connect() as connection:
            connection.execute(
                "UPDATE relationships_current SET attrs_json=? WHERE rel_type='mac_location'",
                (json.dumps({"vlan": "112"}),),
            )
        result = PathInspector(FakePathApp(self.state)).inspect(
            PathRequestV1(
                "02:00:00:00:00:25", 120, mode="cached", requested_at=1_700_000_110
            ),
            object(),
        )
        self.assertEqual((result.status, len(result.hops)), ("UNKNOWN", 0))
        self.assertIn(
            "CACHED_ENDPOINT_VLAN_MISMATCH",
            {finding.code for finding in result.findings},
        )

    @mock.patch("netops_platform.path_inspector.time.time", return_value=1_700_000_110)
    def test_unbound_stp_evidence_cannot_invent_a_block(self, _clock):
        with self.state.connect() as connection:
            connection.execute(
                "INSERT INTO capability_evidence(device_id,capability,state,observed_at,source,confidence,facts_json,raw_evidence_hash,driver_family,parser_version) VALUES(?,?,?,?,?,?,?,?,?,?)",
                ("192.0.2.1", "stp", "supported", 1_700_000_105, "fixture", 90, json.dumps({"state": "blocking", "interface": "Gi1/0/3"}), "hash", "cisco-ios", "fixture-v1"),
            )
        result = PathInspector(FakePathApp(self.state)).inspect(
            PathRequestV1("02:00:00:00:00:25", 120, requested_at=1_700_000_110), object()
        )
        self.assertEqual(result.status, "COMPLETE")
        self.assertNotIn("STP_BLOCKING", {finding.code for finding in result.findings})

    @mock.patch("netops_platform.path_inspector.time.time", return_value=1_700_000_110)
    def test_fresh_path_bound_stp_blocks_but_stale_evidence_does_not(self, _clock):
        with self.state.connect() as connection:
            connection.execute(
                "INSERT INTO capability_evidence(device_id,capability,state,observed_at,source,confidence,facts_json,raw_evidence_hash,driver_family,parser_version) VALUES(?,?,?,?,?,?,?,?,?,?)",
                ("192.0.2.1", "stp", "supported", 1_700_000_105, "fixture", 95, json.dumps({"state": "blocking", "interface": "Gi1/0/48"}), "fresh", "cisco-ios", "fixture-v1"),
            )
        blocked = PathInspector(FakePathApp(self.state)).inspect(
            PathRequestV1("02:00:00:00:00:25", 120, requested_at=1_700_000_110), object()
        )
        self.assertEqual(blocked.status, "BLOCKED")
        with self.state.connect() as connection:
            connection.execute("UPDATE capability_evidence SET observed_at=? WHERE raw_evidence_hash='fresh'", (1_699_998_000,))
        stale = PathInspector(FakePathApp(self.state)).inspect(
            PathRequestV1("02:00:00:00:00:25", 120, requested_at=1_700_000_110), object()
        )
        codes = {finding.code for finding in stale.findings}
        self.assertEqual(stale.status, "PARTIAL")
        self.assertIn("STALE_CAPABILITY_EVIDENCE", codes)
        self.assertNotIn("STP_BLOCKING", codes)

    @mock.patch("netops_platform.path_inspector.time.time", return_value=1_700_000_110)
    def test_a_stored_run_rebuilds_identically_from_the_normalised_tables(self, _clock):
        """The blob and the tables held the same run and could drift apart.
        Reads now come from the tables, so they must reproduce the live result
        exactly rather than approximately."""
        inspector = PathInspector(FakePathApp(self.state))
        live = inspector.inspect(
            PathRequestV1("02:00:00:00:00:25", 120, requested_at=1_700_000_110), object()
        ).to_dict()

        rebuilt = inspector.show(live["run_id"])
        self.assertEqual(rebuilt, live)

    @mock.patch("netops_platform.path_inspector.time.time", return_value=1_700_000_110)
    def test_reading_a_run_does_not_depend_on_the_stored_blob(self, _clock):
        inspector = PathInspector(FakePathApp(self.state))
        live = inspector.inspect(
            PathRequestV1("02:00:00:00:00:25", 120, requested_at=1_700_000_110), object()
        ).to_dict()
        # Corrupt the blob: the tables alone must still serve the run.
        with self.state.connect() as connection:
            connection.execute("UPDATE path_runs SET result_json='{\"corrupt\": true}' WHERE run_id=?", (live["run_id"],))
        rebuilt = inspector.show(live["run_id"])
        self.assertEqual(rebuilt["status"], live["status"])
        self.assertEqual(len(rebuilt["hops"]), len(live["hops"]))
        self.assertEqual([h["device_name"] for h in rebuilt["hops"]],
                         [h["device_name"] for h in live["hops"]])
        self.assertNotIn("corrupt", rebuilt)

    @mock.patch("netops_platform.path_inspector.time.time", return_value=1_700_000_110)
    def test_a_run_recorded_before_the_tables_were_authoritative_still_reads(self, _clock):
        inspector = PathInspector(FakePathApp(self.state))
        live = inspector.inspect(
            PathRequestV1("02:00:00:00:00:25", 120, requested_at=1_700_000_110), object()
        ).to_dict()
        # Legacy shape: blob present, normalised rows absent.
        with self.state.connect() as connection:
            connection.execute("DELETE FROM path_hops WHERE run_id=?", (live["run_id"],))
            connection.execute("DELETE FROM path_findings WHERE run_id=?", (live["run_id"],))
        rebuilt = inspector.show(live["run_id"])
        self.assertEqual(rebuilt["run_id"], live["run_id"])
        self.assertEqual(len(rebuilt["hops"]), len(live["hops"]))

    @mock.patch("netops_platform.path_inspector.time.time", return_value=1_700_000_110)
    def test_a_stalled_walk_falls_back_to_searching_every_switch(self, _clock):
        """A hop-by-hop walk follows one branch; a search covers all of them."""

        class StalledWalkApp(FakePathApp):
            def inspect_path_forwarding_node(self, device, endpoint, vlan, options):
                # The core knows nothing, so the walk cannot take a first step.
                return {"observed_at": 1_700_000_108, "driver_family": "cisco-ios",
                        "error": "MAC not learned"}

            def locate_endpoint_live(self, mac, vlan, options, jobs=0):
                return {
                    "found": True, "searched": 172, "uplink_data_available": True,
                    "attached": [{"switch_ip": "192.0.2.2", "switch_name": "SITE-A-ACCESS-01",
                                  "port": "Gi1/0/7", "vlan": str(vlan), "entry_type": "DYNAMIC"}],
                    "transit": [],
                }

        result = PathInspector(StalledWalkApp(self.state)).inspect(
            PathRequestV1("02:00:00:00:00:25", 120, requested_at=1_700_000_110), object()
        )
        codes = {finding.code for finding in result.findings}
        self.assertIn("ENDPOINT_RELOCATED_BY_SEARCH", codes)
        relocated = next(f for f in result.findings if f.code == "ENDPOINT_RELOCATED_BY_SEARCH")
        self.assertEqual(relocated.interface, "Gi1/0/7")
        self.assertIn("172 switches", relocated.message)
        # The path must now terminate at the switch the search actually found.
        self.assertEqual(result.hops[0].device_name, "SITE-A-ACCESS-01")

    @mock.patch("netops_platform.path_inspector.time.time", return_value=1_700_000_110)
    def test_an_endpoint_seen_only_on_uplinks_is_reported_as_such(self, _clock):
        class TransitOnlyApp(FakePathApp):
            def inspect_path_forwarding_node(self, device, endpoint, vlan, options):
                return {"observed_at": 1_700_000_108, "driver_family": "cisco-ios",
                        "error": "MAC not learned"}

            def locate_endpoint_live(self, mac, vlan, options, jobs=0):
                return {
                    "found": True, "searched": 100, "uplink_data_available": True,
                    "attached": [],
                    "transit": [{"switch_ip": "192.0.2.1", "switch_name": "SITE-A-CORE-01",
                                 "port": "Gi1/0/48", "vlan": str(vlan), "entry_type": "DYNAMIC"}],
                }

        result = PathInspector(TransitOnlyApp(self.state)).inspect(
            PathRequestV1("02:00:00:00:00:25", 120, requested_at=1_700_000_110), object()
        )
        finding = next(f for f in result.findings if f.code == "ENDPOINT_ONLY_SEEN_IN_TRANSIT")
        # Every hit on an uplink means the access switch is not being reached.
        self.assertIn("only on uplink ports", finding.message)
        self.assertIn("1 switch(es)", finding.message)

    @mock.patch("netops_platform.path_inspector.time.time", return_value=1_700_000_110)
    def test_a_completed_walk_does_not_pay_for_a_search(self, _clock):
        searches = []

        class CountingApp(FakePathApp):
            def locate_endpoint_live(self, mac, vlan, options, jobs=0):
                searches.append(mac)
                return {"found": False, "attached": [], "transit": [], "searched": 0}

        result = PathInspector(CountingApp(self.state)).inspect(
            PathRequestV1("02:00:00:00:00:25", 120, requested_at=1_700_000_110), object()
        )
        self.assertEqual(result.status, "COMPLETE")
        # Searching every switch is expensive; a walk that succeeded must not.
        self.assertEqual(searches, [])

    @mock.patch("netops_platform.path_inspector.time.time", return_value=1_700_000_110)
    def test_evidence_collected_during_the_run_is_not_called_future(self, _clock):
        # A long run records evidence after its own start. Comparing against
        # the start instead of the wall clock reported that fresh evidence as
        # "later than the current clock".
        with self.state.connect() as connection:
            connection.execute(
                "INSERT INTO capability_evidence(device_id,capability,state,observed_at,source,confidence,facts_json,raw_evidence_hash,driver_family,parser_version) VALUES(?,?,?,?,?,?,?,?,?,?)",
                ("192.0.2.1", "stp", "supported", 1_700_000_105, "fixture", 95,
                 json.dumps({"state": "forwarding", "interface": "Gi1/0/48"}), "midrun", "cisco-ios", "fixture-v1"),
            )
        result = PathInspector(FakePathApp(self.state)).inspect(
            # Requested well before the evidence was written, as a slow run does.
            PathRequestV1("02:00:00:00:00:25", 120, requested_at=1_700_000_000), object()
        )
        self.assertNotIn("FUTURE_CAPABILITY_TIMESTAMP", {finding.code for finding in result.findings})

    @mock.patch("netops_platform.path_inspector.time.time", return_value=1_700_000_110)
    def test_a_genuinely_future_timestamp_is_still_reported(self, _clock):
        with self.state.connect() as connection:
            connection.execute(
                "INSERT INTO capability_evidence(device_id,capability,state,observed_at,source,confidence,facts_json,raw_evidence_hash,driver_family,parser_version) VALUES(?,?,?,?,?,?,?,?,?,?)",
                ("192.0.2.1", "stp", "supported", 1_700_009_999, "fixture", 95,
                 json.dumps({"state": "forwarding", "interface": "Gi1/0/48"}), "ahead", "cisco-ios", "fixture-v1"),
            )
        result = PathInspector(FakePathApp(self.state)).inspect(
            PathRequestV1("02:00:00:00:00:25", 120, requested_at=1_700_000_110), object()
        )
        self.assertIn("FUTURE_CAPABILITY_TIMESTAMP", {finding.code for finding in result.findings})

    @mock.patch("netops_platform.path_inspector.time.time", return_value=1_700_000_110)
    def test_stale_evidence_about_an_unrelated_interface_is_not_reported(self, _clock):
        # Old spanning-tree evidence for a port this path never touches cannot
        # affect the verdict, so warning about it only buries real findings.
        with self.state.connect() as connection:
            connection.execute(
                "INSERT INTO capability_evidence(device_id,capability,state,observed_at,source,confidence,facts_json,raw_evidence_hash,driver_family,parser_version) VALUES(?,?,?,?,?,?,?,?,?,?)",
                ("192.0.2.1", "stp", "supported", 1_699_990_000, "fixture", 95,
                 json.dumps({"state": "blocking", "interface": "Gi1/0/99"}), "elsewhere", "cisco-ios", "fixture-v1"),
            )
        result = PathInspector(FakePathApp(self.state)).inspect(
            PathRequestV1("02:00:00:00:00:25", 120, requested_at=1_700_000_110), object()
        )
        codes = {finding.code for finding in result.findings}
        self.assertNotIn("STALE_CAPABILITY_EVIDENCE", codes)
        # And it must certainly not block a path it has nothing to do with.
        self.assertNotIn("STP_BLOCKING", codes)

    @mock.patch("netops_platform.path_inspector.time.time", return_value=1_700_000_110)
    def test_stale_evidence_on_a_path_interface_is_still_reported(self, _clock):
        with self.state.connect() as connection:
            connection.execute(
                "INSERT INTO capability_evidence(device_id,capability,state,observed_at,source,confidence,facts_json,raw_evidence_hash,driver_family,parser_version) VALUES(?,?,?,?,?,?,?,?,?,?)",
                ("192.0.2.1", "stp", "supported", 1_699_990_000, "fixture", 95,
                 json.dumps({"state": "blocking", "interface": "Gi1/0/48"}), "onpath", "cisco-ios", "fixture-v1"),
            )
        result = PathInspector(FakePathApp(self.state)).inspect(
            PathRequestV1("02:00:00:00:00:25", 120, requested_at=1_700_000_110), object()
        )
        stale = [f for f in result.findings if f.code == "STALE_CAPABILITY_EVIDENCE"]
        self.assertTrue(stale, "stale evidence on a path interface must be reported")
        # The message must say how old and against what limit, not just "stale".
        self.assertIn("minute", stale[0].message)
        self.assertGreater(stale[0].evidence.get("age_seconds", 0), 0)

    @mock.patch("netops_platform.path_inspector.time.time", return_value=1_700_000_110)
    def test_unknown_policy_semantics_and_partial_device_failure_remain_partial(self, _clock):
        with self.state.connect() as connection:
            connection.execute(
                "INSERT INTO capability_evidence(device_id,capability,state,observed_at,source,confidence,facts_json,raw_evidence_hash,driver_family,parser_version) VALUES(?,?,?,?,?,?,?,?,?,?)",
                ("192.0.2.1", "interface_policy", "supported", 1_700_000_105, "fixture", 80, json.dumps({"interface": "Gi1/0/48", "references": ["EDGE-IN"], "semantics_supported": False}), "policy", "cisco-ios", "fixture-v1"),
            )
        result = PathInspector(FakePathApp(self.state)).inspect(
            PathRequestV1("02:00:00:00:00:25", 120, requested_at=1_700_000_110), object()
        )
        self.assertEqual(result.status, "PARTIAL")
        self.assertIn("POLICY_SEMANTICS_UNKNOWN", {finding.code for finding in result.findings})

        class FailingPathApp(FakePathApp):
            def inspect_vlan_node(self, device, vlan, mode, options):
                if device["ip"] == "192.0.2.2":
                    raise RuntimeError("fixture timeout")
                return super().inspect_vlan_node(device, vlan, mode, options)

        failed = PathInspector(FailingPathApp(self.state)).inspect(
            PathRequestV1("02:00:00:00:00:25", 120, requested_at=1_700_000_110), object()
        )
        self.assertEqual(failed.status, "PARTIAL")
        self.assertIn("LIVE_INSPECTION_FAILED", {finding.code for finding in failed.findings})

    @mock.patch("netops_platform.path_inspector.time.time", return_value=1_700_000_110)
    def test_graph_loops_and_node_limits_are_bounded(self, _clock):
        with self.state.connect() as connection:
            connection.execute("INSERT INTO devices VALUES(?,?,?,?,?,?,?,?)", ("192.0.2.3", "SITE-A-ACCESS-02", "Aruba AOS-CX", "CX 6300", "SYNTHETIC-EDGE-2", "02:00:00:00:00:03", "ONLINE", 1_700_000_100))
            connection.executemany(
                "INSERT INTO neighbors VALUES(?,?,?,?,?,?)",
                [
                    ("192.0.2.2", "SITE-A-ACCESS-01", "Gi1/0/49", "SITE-A-ACCESS-02", "1/1/48", "192.0.2.3"),
                    ("192.0.2.3", "SITE-A-ACCESS-02", "1/1/47", "SITE-A-CORE-01", "Gi1/0/47", "192.0.2.1"),
                ],
            )
            connection.execute("INSERT INTO relationships_current(rel_type,subject_id,switch_ip,switch_name,switch_port,confidence,last_seen,updated_at,attrs_json,source,status) VALUES(?,?,?,?,?,?,?,?,?,?,?)", ("mac_location", "020000000026", "192.0.2.3", "SITE-A-ACCESS-02", "1/1/7", 95, 1_700_000_100, 1_700_000_100, "{}", "fixture", "active"))
        result = PathInspector(FakePathApp(self.state)).inspect(
            PathRequestV1("02:00:00:00:00:26", 120, depth=8, max_nodes=1, mode="cached", requested_at=1_700_000_110), object()
        )
        self.assertEqual(result.status, "UNKNOWN")
        self.assertIn("NODE_BUDGET_REACHED", {finding.code for finding in result.findings})


class PrivacyTest(unittest.TestCase):
    def test_public_export_uses_approved_disclosure_commit_message(self):
        self.assertEqual(PUBLIC_COMMIT_SUBJECT, "Public beta source release")
        self.assertIn("NetOps Platform v8.5 public beta.", PUBLIC_COMMIT_BODY)
        self.assertIn("Historical development commits are intentionally not included", PUBLIC_COMMIT_BODY)

    def test_public_export_keeps_tracked_ignored_assets_when_untracked_are_included(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            (root / ".gitignore").write_text("dist/\n", encoding="utf-8")
            asset = root / "webui" / "dist" / "index.html"
            asset.parent.mkdir(parents=True)
            asset.write_text("tracked build", encoding="utf-8")
            (root / "README.md").write_text("untracked source\n", encoding="utf-8")
            subprocess.run(["git", "add", ".gitignore"], cwd=root, check=True)
            subprocess.run(["git", "add", "-f", "webui/dist/index.html"], cwd=root, check=True)

            listed = repository_files(root, include_untracked=True)
            self.assertIn("webui/dist/index.html", listed)
            self.assertIn("README.md", listed)

            exported = root / "public"
            exported.mkdir()
            subprocess.run(["git", "init", "-q"], cwd=exported, check=True)
            (exported / ".gitignore").write_text("dist/\n", encoding="utf-8")
            copied_asset = exported / "webui" / "dist" / "index.html"
            copied_asset.parent.mkdir(parents=True)
            copied_asset.write_text("copied build", encoding="utf-8")
            stage_export(exported)
            staged = subprocess.run(
                ["git", "ls-files"], cwd=exported, check=True,
                stdout=subprocess.PIPE, text=True,
            ).stdout.splitlines()
            self.assertIn("webui/dist/index.html", staged)

    def test_private_only_markdown_never_reaches_the_public_export(self):
        text = f"# Netrune\n\n{PRIVATE_START}\ngit clone private-url\n{PRIVATE_END}\n\npublic text\n"
        self.assertEqual(strip_private(text, "README.md"), "# Netrune\n\npublic text\n")
        with self.assertRaises(RuntimeError):
            strip_private(f"{PRIVATE_START}\nunclosed\n", "README.md")

    def test_tree_archive_and_private_denylist_findings(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private_path = "/".join(("", "home", "example-user", "private"))
            (root / "public.txt").write_text(f"path={private_path}\nlegacy-prefix\n", encoding="utf-8")
            findings = scan_tree(root, ["legacy-prefix"])
            self.assertEqual({finding.code for finding in findings}, {"absolute-user-path", "denied-identifier"})
            archive = root / "fixture.tar.gz"
            with tarfile.open(archive, "w:gz") as output:
                output.add(root / "public.txt", arcname="public.txt")
            archive_findings = scan_archive(archive, ["legacy-prefix"])
            self.assertEqual({finding.code for finding in archive_findings}, {"absolute-user-path", "denied-identifier"})

    def test_paths_private_ipv4_and_clean_history_are_scanned(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private_file = root / "fixtures" / "legacy-prefix-switch.bin"
            private_file.parent.mkdir()
            private_file.write_bytes(b"binary fixture")
            address_file = root / "address.txt"
            private_address = ".".join(("10", "23", "45", "67"))
            address_file.write_text(f"device={private_address}\n", encoding="utf-8")
            findings = scan_tree(root, ["legacy-prefix"])
            self.assertIn("denied-path-identifier", {finding.code for finding in findings})
            self.assertIn("private-ip-literal", {finding.code for finding in findings})

            archive = root / "paths.tar.gz"
            with tarfile.open(archive, "w:gz") as output:
                output.add(private_file, arcname="fixtures/legacy-prefix-switch.bin")
            self.assertIn(
                "denied-path-identifier",
                {finding.code for finding in scan_archive(archive, ["legacy-prefix"])},
            )

            repository = root / "history"
            repository.mkdir()
            subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
            subprocess.run(["git", "config", "user.name", "NetOps maintainers"], cwd=repository, check=True)
            subprocess.run(["git", "config", "user.email", "public-beta@example.invalid"], cwd=repository, check=True)
            tracked = repository / "legacy-prefix.txt"
            tracked.write_text("neutral content\n", encoding="utf-8")
            subprocess.run(["git", "add", "."], cwd=repository, check=True)
            subprocess.run(["git", "commit", "-qm", "fixture"], cwd=repository, check=True)
            self.assertIn(
                "denied-path-identifier",
                {finding.code for finding in scan_git_history(repository, ["legacy-prefix"])},
            )

    def test_tracked_nested_dist_assets_are_scanned(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            nested = root / "webui" / "dist" / "asset.js"
            nested.parent.mkdir(parents=True)
            nested.write_text("legacy-prefix", encoding="utf-8")
            generated = root / "dist" / "artifact.js"
            generated.parent.mkdir()
            generated.write_text("legacy-prefix", encoding="utf-8")
            findings = scan_tree(root, ["legacy-prefix"])
            self.assertEqual(
                [finding.path for finding in findings if finding.code == "denied-identifier"],
                ["webui/dist/asset.js"],
            )

    def test_tree_and_archive_links_or_traversal_are_release_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.txt"
            target.write_text("public fixture\n", encoding="utf-8")
            (root / "link.txt").symlink_to(target)
            self.assertIn("symbolic-link", {finding.code for finding in scan_tree(root)})

            traversal = root / "traversal.tar.gz"
            with tarfile.open(traversal, "w:gz") as output:
                member = tarfile.TarInfo("../outside.txt")
                content = b"fixture\n"
                member.size = len(content)
                output.addfile(member, io.BytesIO(content))
            findings = scan_archive(traversal)
            self.assertEqual([finding.code for finding in findings], ["archive-invalid"])
            self.assertIn("unsafe archive member path", findings[0].detail)

            linked = root / "linked.tar.gz"
            with tarfile.open(linked, "w:gz") as output:
                member = tarfile.TarInfo("link.txt")
                member.type = tarfile.SYMTYPE
                member.linkname = "target.txt"
                output.addfile(member)
            self.assertEqual([finding.code for finding in scan_archive(linked)], ["archive-invalid"])


class SupportAndReleaseTest(unittest.TestCase):
    def test_support_bundle_contains_only_redacted_aggregates(self):
        private_root = Path("/", "home", "example-operator")

        class State:
            def db_status_payload(self):
                return {
                    "ok": True,
                    "db_path": str(private_root / ".local/share/netops/profiles/private/state.sqlite3"),
                    "cache_dir": str(private_root / ".cache/netops/private"),
                    "schema_version": "12",
                    "expected_schema_version": "12",
                    "counts": {"devices": 2},
                    "files": {"sqlite_bytes": 4096, "wal_bytes": 0, "shm_bytes": 0},
                }

            def integrity_check(self):
                return {"ok": True, "integrity_check": ["ok"], "quick_check": ["ok"]}

            def rows(self, _query):
                return []

        class Config:
            def public_safe(self):
                return {
                    "core_switch_ip": "192.0.2.1",
                    "password": "configured",
                    "ssh_host_key_mode": "strict",
                }

        class Plugins:
            def discover(self):
                return []

        with tempfile.TemporaryDirectory() as directory, mock.patch("netops_platform.support.time.time", return_value=1_700_000_000):
            root = Path(directory)
            app = type("App", (), {})()
            app.paths = type("Paths", (), {"data_dir": root, "profile": "private-estate"})()
            app.config = Config()
            app.state = State()
            app.device_drivers = DEVICE_REGISTRY.clone()
            app.driver_manifest_report = [{"status": "loaded", "family": "private-switch", "error": "host 192.0.2.99"}]
            app.plugin_manager = Plugins()
            output = root / "support.tar.gz"
            result = create_support_bundle(app, output)
            self.assertEqual(result["recorded_at_iso"], "2023-11-14T22:13:20Z")
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            self.assertEqual(scan_archive(output), [])
            with tarfile.open(output, "r:gz") as archive:
                payloads = {
                    Path(member.name).name: archive.extractfile(member).read()
                    for member in archive.getmembers()
                    if member.isfile()
                }
            database = json.loads(payloads["database.json"])
            self.assertNotIn("db_path", database)
            self.assertNotIn("cache_dir", database)
            system = json.loads(payloads["system.json"])
            self.assertNotEqual(system["profile"], "private-estate")
            combined = b"".join(payloads.values()).decode("utf-8")
            self.assertNotIn("private-switch", combined)
            self.assertNotIn("192.0.2.99", combined)
            manifest = json.loads(payloads["MANIFEST.sha256.json"])
            for name, digest in manifest.items():
                self.assertEqual(hashlib.sha256(payloads[name]).hexdigest(), digest)

    def test_support_bundles_in_the_default_directory_are_rotated(self):
        """Nothing removed an old bundle before: a directory nobody looked at
        grew by one file per 'netrune support bundle' call forever."""
        from netops_platform.support import KEPT_BUNDLES

        class State:
            def db_status_payload(self): return {"ok": True, "counts": {}, "files": {}}
            def integrity_check(self): return {"ok": True}
            def rows(self, _query): return []

        class Config:
            def public_safe(self): return {}

        class Plugins:
            def discover(self): return []

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app = type("App", (), {})()
            app.paths = type("Paths", (), {"data_dir": root, "profile": "private-estate"})()
            app.config = Config()
            app.state = State()
            app.device_drivers = DEVICE_REGISTRY.clone()
            app.driver_manifest_report = []
            app.plugin_manager = Plugins()
            import itertools
            stamps = itertools.count(1_700_000_000)
            # time.time() is mocked process-wide for the duration of the
            # 'with' block, not just support.py's own call, so more than one
            # value can be drawn per bundle -- only the path each call
            # actually wrote is a reliable stamp to assert against.
            written = []
            with mock.patch("netops_platform.support.time.time", side_effect=lambda: next(stamps)):
                for _ in range(KEPT_BUNDLES + 3):
                    written.append(Path(create_support_bundle(app)["path"]))
            remaining = set((root / "support").glob("netops-support-*.tar.gz"))
            self.assertEqual(len(remaining), KEPT_BUNDLES)
            # The ones kept are the newest, not an arbitrary subset.
            self.assertIn(written[-1], remaining)
            self.assertNotIn(written[0], remaining)
            self.assertEqual(remaining, set(written[-KEPT_BUNDLES:]))

    def test_a_custom_bundle_path_is_never_touched_by_rotation(self):
        class State:
            def db_status_payload(self): return {"ok": True, "counts": {}, "files": {}}
            def integrity_check(self): return {"ok": True}
            def rows(self, _query): return []

        class Config:
            def public_safe(self): return {}

        class Plugins:
            def discover(self): return []

        with tempfile.TemporaryDirectory() as directory, mock.patch("netops_platform.support.time.time", return_value=1_700_000_000):
            root = Path(directory)
            app = type("App", (), {})()
            app.paths = type("Paths", (), {"data_dir": root, "profile": "private-estate"})()
            app.config = Config()
            app.state = State()
            app.device_drivers = DEVICE_REGISTRY.clone()
            app.driver_manifest_report = []
            app.plugin_manager = Plugins()
            custom = root / "elsewhere" / "mine.tar.gz"
            create_support_bundle(app, custom)
            self.assertTrue(custom.is_file())

    def test_release_metadata_is_reproducible_and_validates_artifacts(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, {"SOURCE_DATE_EPOCH": "1700000000"}):
            root = Path(directory)
            wheel = root / "netrune-8.5.0b3-py3-none-any.whl"
            source = root / "netrune-8.5.0b3.tar.gz"
            wheel.write_bytes(b"wheel fixture")
            source.write_bytes(b"source fixture")
            first = release_metadata("8.5.0b3", [source, wheel])
            second = release_metadata("8.5.0b3", [wheel, source])
            self.assertEqual(first["sbom"]["serialNumber"], second["sbom"]["serialNumber"])
            self.assertEqual(first["sbom"]["metadata"]["component"]["name"], "netrune")
            metadata = first["provenance"]["predicate"]["runDetails"]["metadata"]
            self.assertEqual(metadata["startedOn"], "2023-11-14T22:13:20Z")
            self.assertEqual(metadata["finishedOn"], metadata["startedOn"])
            outputs = write_release_metadata("8.5.0b3", [wheel, source], root / "release")
            self.assertEqual(set(outputs), {"checksums", "sbom", "provenance"})
            self.assertEqual(scan_tree(root / "release"), [])

            linked = root / "linked.whl"
            linked.symlink_to(wheel)
            with self.assertRaisesRegex(ValueError, "regular file"):
                release_metadata("8.5.0b1", [linked])
            duplicate_root = root / "duplicate"
            duplicate_root.mkdir()
            duplicate = duplicate_root / wheel.name
            duplicate.write_bytes(b"other")
            with self.assertRaisesRegex(ValueError, "unique"):
                release_metadata("8.5.0b1", [wheel, duplicate])


if __name__ == "__main__":
    unittest.main()
