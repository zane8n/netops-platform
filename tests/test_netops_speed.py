import contextlib
import os
from pathlib import Path
import ssl
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest import mock

import netops_speed


@contextlib.contextmanager
def fake_trust(_ca_file=""):
    yield {"verified": True, "hostname_check": True, "source": "fixture", "ca_file": "fixture.pem"}


class NetOpsSpeedBackendTest(unittest.TestCase):
    def test_explicit_ca_file_must_exist(self):
        with self.assertRaisesRegex(RuntimeError, "does not exist"):
            netops_speed._ca_bundle("/definitely/missing/netops-ca.pem")

    def test_tls_compatibility_retains_verification_and_hostname_checks(self):
        original = ssl.create_default_context
        with mock.patch.object(netops_speed, "_ca_bundle", return_value=(None, "fixture", None)):
            with netops_speed._verified_tls() as trust:
                context = ssl.create_default_context()
                self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
                self.assertTrue(context.check_hostname)
                if hasattr(ssl, "VERIFY_X509_STRICT"):
                    self.assertFalse(context.verify_flags & ssl.VERIFY_X509_STRICT)
                self.assertTrue(trust["verified"])
        self.assertIs(ssl.create_default_context, original)

    def test_server_listing_has_stable_structured_contract(self):
        client = mock.Mock()
        client.get_closest_servers.return_value = [{"id": "42", "host": "test.example:8080", "sponsor": "Lab", "name": "Core", "country": "CD", "d": "1.25"}]
        with mock.patch.object(netops_speed, "_verified_tls", fake_trust), mock.patch.object(netops_speed, "_speedtest", return_value=client):
            payload = netops_speed.list_servers(3, 30, "", "")
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["scope"], "netops-host-to-internet")
        self.assertEqual(payload["servers"][0]["id"], 42)
        self.assertEqual(payload["servers"][0]["distance_km"], 1.25)

    def test_direction_run_reports_decimal_megabits_and_bytes(self):
        client = mock.Mock()
        client.get_best_server.return_value = {"id": "42", "host": "test.example:8080", "sponsor": "Lab", "name": "Core"}
        client.download.return_value = 125_000_000
        client.results = SimpleNamespace(dict=lambda: {"bytes_received": 25_000_000, "client": {"ip": "192.0.2.2"}})
        with mock.patch.object(netops_speed, "_verified_tls", fake_trust), mock.patch.object(netops_speed, "_speedtest", return_value=client):
            payload = netops_speed.run_server(42, "download", 30, "", "")
        self.assertEqual(payload["megabits_per_second"], 125.0)
        self.assertEqual(payload["bytes"], 25_000_000)
        client.download.assert_called_once_with()

    def test_zero_transfer_result_is_rejected(self):
        client = mock.Mock()
        client.get_best_server.return_value = {"id": "42", "host": "test.example:8080", "sponsor": "Lab", "name": "Core"}
        client.download.return_value = 0
        client.results = SimpleNamespace(dict=lambda: {"bytes_received": 0, "client": {"ip": "192.0.2.2"}})
        with mock.patch.object(netops_speed, "_verified_tls", fake_trust), mock.patch.object(netops_speed, "_speedtest", return_value=client):
            with self.assertRaisesRegex(RuntimeError, "zero-transfer"):
                netops_speed.run_server(42, "download", 30, "", "")

    def test_paired_run_reuses_one_client_and_keeps_phase_latency_separate(self):
        client = mock.Mock()
        client.get_best_server.return_value = {"id": "42", "host": "test.example:8080", "sponsor": "Lab", "name": "Core"}
        client.upload.return_value = 50_000_000
        client.download.return_value = 125_000_000
        client.results = SimpleNamespace(
            dict=mock.Mock(
                side_effect=[
                    {"bytes_sent": 10_000_000, "client": {"ip": "192.0.2.2"}},
                    {"bytes_received": 25_000_000, "client": {"ip": "192.0.2.2"}},
                ]
            )
        )
        phase = iter(({"available": True, "avg": 8.0, "jitter": 1.0, "packet_loss_pct": 0.0, "samples": 10}, {"available": True, "avg": 12.0, "jitter": 2.0, "packet_loss_pct": 0.0, "samples": 11}))

        def measure(_host, action):
            return action(), next(phase)

        with mock.patch.object(netops_speed, "_verified_tls", fake_trust), mock.patch.object(
            netops_speed, "_speedtest", return_value=client
        ) as speedtest, mock.patch.object(netops_speed, "_measure_loaded_latency", side_effect=measure):
            payload = netops_speed.run_server_pair(42, 30, "", "")
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["measurement_order"], ["upload", "download"])
        self.assertEqual(payload["directions"]["upload"]["megabits_per_second"], 50.0)
        self.assertEqual(payload["directions"]["download"]["megabits_per_second"], 125.0)
        self.assertEqual(payload["directions"]["upload"]["loaded_latency_ms"]["avg"], 8.0)
        self.assertEqual(payload["directions"]["download"]["loaded_latency_ms"]["avg"], 12.0)
        speedtest.assert_called_once_with(30, "")
        client.get_servers.assert_called_once_with([42])
        client.get_best_server.assert_called_once_with()

    def test_ping_metrics_report_jitter_and_missing_samples_explicitly(self):
        measured = netops_speed._ping_metrics("64 bytes time=10.0 ms\n64 bytes time=14.0 ms\n2 packets transmitted, 2 received, 0% packet loss")
        missing = netops_speed._ping_metrics("ping: permission denied")
        self.assertEqual((measured["avg"], measured["jitter"], measured["samples"]), (12.0, 4.0, 2))
        self.assertFalse(missing["available"])
        self.assertIsNone(missing["packet_loss_pct"])

    def test_loaded_latency_probe_is_reaped_after_transfer(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pid_file = root / "ping.pid"
            ping = root / "ping"
            ping.write_text(
                "#!/usr/bin/env bash\n"
                "printf '%s' \"$$\" > \"$PING_PID_FILE\"\n"
                "printf '64 bytes from fixture: time=3.5 ms\\n'\n"
                "exec sleep 30\n",
                encoding="utf-8",
            )
            ping.chmod(0o700)
            with mock.patch.dict(
                os.environ,
                {"PATH": f"{root}:{os.environ.get('PATH', '')}", "PING_PID_FILE": str(pid_file)},
                clear=False,
            ):
                result, metrics = netops_speed._measure_loaded_latency(
                    "speed.example:8080", lambda: (time.sleep(0.1), 42)[1]
                )
            self.assertEqual(result, 42)
            self.assertEqual(metrics["avg"], 3.5)
            child_pid = int(pid_file.read_text(encoding="utf-8"))
            with self.assertRaises(ProcessLookupError):
                os.kill(child_pid, 0)


if __name__ == "__main__":
    unittest.main()
