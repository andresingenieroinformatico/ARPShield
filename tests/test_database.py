from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from arpshield.database import DatabaseManager
from arpshield.monitor import ThreatMonitor


class DatabaseManagerTests(unittest.TestCase):
    def test_initialize_creates_tables(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db = DatabaseManager(Path(tmp_dir) / "arpshield.db")
            db.initialize()
            names = set(db.table_names())

            self.assertIn("trusted_baseline", names)
            self.assertIn("security_alerts", names)
            self.assertIn("audit_logs", names)

    def test_round_trip_baseline_and_alert(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db = DatabaseManager(Path(tmp_dir) / "arpshield.db")
            db.initialize()

            db.add_baseline_entry("192.168.1.1", "00:11:22:33:44:55", "GATEWAY", "gateway")
            baseline = db.list_baseline()
            self.assertEqual(len(baseline), 1)
            self.assertEqual(baseline[0]["ip_address"], "192.168.1.1")

            db.add_alert(
                "GATEWAY_SPOOFING",
                "HIGH",
                "AA:BB:CC:DD:EE:FF",
                "192.168.1.1",
                7,
                "MAC distinta detectada en la IP del gateway",
                0,
            )
            alerts = db.list_alerts()
            self.assertEqual(len(alerts), 1)
            self.assertEqual(alerts[0]["alert_type"], "GATEWAY_SPOOFING")


class ThreatMonitorTests(unittest.TestCase):
    def test_discover_local_network_handles_windows_arp_output(self):
        fake_output = (
            "Interface: 192.168.1.10 --- 0x12\r\n"
            "\r\n"
            "  Internet Address      Physical Address      Type\r\n"
            "  192.168.1.1     00-11-22-33-44-55     dynamic\r\n"
        ).encode("cp850")

        with tempfile.TemporaryDirectory() as tmp_dir:
            db = DatabaseManager(Path(tmp_dir) / "arpshield.db")
            db.initialize()
            monitor = ThreatMonitor(db)

            with patch("subprocess.run", return_value=subprocess.CompletedProcess(args=["arp", "-a"], returncode=0, stdout=fake_output, stderr=b"")):
                entries = monitor.discover_local_network()

            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0]["ip_address"], "192.168.1.1")
            self.assertEqual(entries[0]["mac_address"], "00:11:22:33:44:55")


if __name__ == "__main__":
    unittest.main()
