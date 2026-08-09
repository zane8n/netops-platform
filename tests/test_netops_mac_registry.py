import io
import json
import tempfile
import unittest
from pathlib import Path
from urllib.error import URLError

from netops_mac_registry import IeeeMacRegistry, SOURCES


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.close()


class IeeeMacRegistryTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        rows = {
            "MA-L": "Registry,Assignment,Organization Name,Organization Address\nMA-L,ACBBCC,Large Org,Large Address\n",
            "MA-M": "Registry,Assignment,Organization Name,Organization Address\nMA-M,ACBBCCD,Medium Org,Medium Address\n",
            "MA-S": "Registry,Assignment,Organization Name,Organization Address\nMA-S,ACBBCCDDE,Small Org,Small Address\n",
        }

        def opener(request, timeout=0):
            source = next(item for item in SOURCES if item.url == request.full_url)
            return FakeResponse(rows[source.registry].encode("utf-8"))

        self.registry = IeeeMacRegistry(self.base, opener=opener, clock=lambda: 1_700_000_000)

    def tearDown(self):
        self.temp.cleanup()

    def test_refresh_and_lookup_use_longest_authoritative_assignment(self):
        refreshed = self.registry.refresh(force=True)
        result = self.registry.lookup("ac:bb:cc:dd:ee:ff", online=False)
        self.assertTrue(refreshed["complete"])
        self.assertEqual(result["registry"], "MA-S")
        self.assertEqual(result["prefix_bits"], 36)
        self.assertEqual(result["organization"], "Small Org")
        self.assertEqual(result["block_size"], 4096)
        self.assertIn("not an exact device model", result["note"])
        manifest = json.loads((self.base / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["provider"], "IEEE Registration Authority")
        self.assertEqual((self.base / "manifest.json").stat().st_mode & 0o777, 0o600)

    def test_locally_administered_address_has_no_manufacturer_claim(self):
        result = self.registry.lookup("02:11:22:33:44:55")
        self.assertEqual(result["address_type"], "locally-administered")
        self.assertFalse(result["found"])
        self.assertFalse(list(self.base.glob("*.csv")))

    def test_failed_refresh_retains_and_identifies_stale_cache(self):
        self.registry.refresh(force=True)

        def unavailable(request, timeout=0):
            raise URLError("fixture registry unavailable")

        stale = IeeeMacRegistry(
            self.base,
            opener=unavailable,
            clock=lambda: 1_700_100_000,
        )
        result = stale.lookup("ac:bb:cc:dd:ee:ff", online=True, max_age_seconds=1)
        self.assertTrue(result["found"])
        self.assertEqual(result["organization"], "Small Org")
        self.assertFalse(result["refresh"]["complete"])
        self.assertTrue(all(row["status"] == "stale-cache" for row in result["refresh"]["rows"]))


if __name__ == "__main__":
    unittest.main()
