from __future__ import annotations

import json
import sqlite3
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

    def test_initialize_migrates_existing_alert_constraint(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "arpshield.db"
            connection = sqlite3.connect(path)
            connection.executescript(
                """
                CREATE TABLE security_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp_utc DATETIME DEFAULT CURRENT_TIMESTAMP,
                    alert_type TEXT CHECK(alert_type IN ('GATEWAY_SPOOFING', 'MULTIPLE_IPS_PER_MAC', 'ARP_BURST_UNSOLICITED', 'DNS_SPOOFING')) NOT NULL,
                    severity TEXT CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')) NOT NULL,
                    attacker_mac TEXT NOT NULL,
                    spoofed_ip TEXT NOT NULL,
                    packet_count INTEGER DEFAULT 1,
                    evidence_summary TEXT NOT NULL,
                    mitigation_applied INTEGER DEFAULT 0
                );
                INSERT INTO security_alerts (alert_type, severity, attacker_mac, spoofed_ip, evidence_summary)
                VALUES ('GATEWAY_SPOOFING', 'HIGH', '00:11:22:33:44:55', '192.168.1.1', 'Registro previo');
                """
            )
            connection.close()

            db = DatabaseManager(path)
            db.initialize()
            db.add_alert("DHCP_SPOOFING", "HIGH", "AA:BB:CC:DD:EE:FF", "192.168.1.2", 1, "Oferta sospechosa")

            alerts = db.list_alerts()
            self.assertEqual(len(alerts), 2)
            self.assertEqual({alert["alert_type"] for alert in alerts}, {"GATEWAY_SPOOFING", "DHCP_SPOOFING"})
            self.assertEqual(json.loads(alerts[0]["evidence_details"]), {})

    def test_initialize_migrates_device_types_and_preserves_baseline(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "arpshield.db"
            connection = sqlite3.connect(path)
            connection.executescript(
                """
                CREATE TABLE trusted_baseline (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL UNIQUE,
                    mac_address TEXT NOT NULL,
                    device_type TEXT CHECK(device_type IN ('GATEWAY', 'DNS_SERVER', 'KNOWN_HOST', 'OTHER')) NOT NULL,
                    hostname TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );
                INSERT INTO trusted_baseline (ip_address, mac_address, device_type, hostname)
                VALUES ('192.168.1.1', '00:11:22:33:44:55', 'KNOWN_HOST', 'router');
                """
            )
            connection.close()

            db = DatabaseManager(path)
            db.initialize()
            db.set_baseline_device_type("192.168.1.1", "DHCP_SERVER")

            baseline = db.list_baseline()
            self.assertEqual(len(baseline), 1)
            self.assertEqual(baseline[0]["hostname"], "router")
            self.assertEqual(baseline[0]["device_type"], "DHCP_SERVER")

            with self.assertRaises(ValueError):
                db.set_baseline_device_type("192.168.1.1", "UNSUPPORTED")

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
                {"capture_source": "test", "observed_mac": "AA:BB:CC:DD:EE:FF"},
            )
            alerts = db.list_alerts()
            self.assertEqual(len(alerts), 1)
            self.assertEqual(alerts[0]["alert_type"], "GATEWAY_SPOOFING")
            self.assertEqual(
                json.loads(alerts[0]["evidence_details"])["observed_mac"],
                "AA:BB:CC:DD:EE:FF",
            )

    def test_update_baseline_device_persists_alias_and_role(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db = DatabaseManager(Path(tmp_dir) / "arpshield.db")
            db.initialize()
            db.add_baseline_entry("192.168.1.1", "00:11:22:33:44:55", "KNOWN_HOST")

            db.update_baseline_device("192.168.1.1", "GATEWAY", "  Router principal  ")

            entry = db.list_baseline()[0]
            self.assertEqual(entry["hostname"], "Router principal")
            self.assertEqual(entry["device_type"], "GATEWAY")

            with self.assertRaises(ValueError):
                db.update_baseline_device("192.168.1.1", "GATEWAY", "R" * 121)

    def test_add_alert_deduplicates_same_signal_within_30_seconds(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db = DatabaseManager(Path(tmp_dir) / "arpshield.db")
            db.initialize()
            alert = {
                "alert_type": "ARP_SPOOFING",
                "severity": "HIGH",
                "attacker_mac": "AA:BB:CC:DD:EE:FF",
                "spoofed_ip": "192.168.1.1",
                "packet_count": 1,
                "evidence_summary": "Anuncio ARP conflictivo",
            }

            self.assertTrue(db.add_alert(**alert))
            self.assertFalse(db.add_alert(**{**alert, "attacker_mac": "aa:bb:cc:dd:ee:ff"}))
            self.assertEqual(len(db.list_alerts()), 1)

    def test_dashboard_snapshot_aggregates_and_limits_recent_alerts(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db = DatabaseManager(Path(tmp_dir) / "arpshield.db")
            db.initialize()
            db.add_baseline_entry("192.168.1.1", "00:11:22:33:44:55", "GATEWAY")
            db.add_alert("GATEWAY_SPOOFING", "HIGH", "AA:BB:CC:DD:EE:FF", "192.168.1.1", 1, "Cambio de MAC")
            db.add_alert("DNS_SPOOFING", "CRITICAL", "AA:BB:CC:DD:EE:00", "192.168.1.2", 1, "Respuesta inesperada")
            db.add_alert("DNS_SPOOFING", "LOW", "AA:BB:CC:DD:EE:01", "192.168.1.3", 1, "Alerta de prueba")

            snapshot = db.dashboard_snapshot(recent_limit=2, trend_days=12)

            self.assertEqual(snapshot["baseline_count"], 1)
            self.assertEqual(snapshot["alert_count"], 3)
            self.assertEqual(snapshot["high_severity_count"], 2)
            self.assertEqual(dict(snapshot["alert_type_counts"])["DNS_SPOOFING"], 2)
            self.assertEqual(len(snapshot["recent_alerts"]), 2)
            self.assertEqual(sum(snapshot["daily_counts"].values()), 3)

    def test_dashboard_starts_with_zero_alerts_for_each_database_session(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "arpshield.db"
            previous_session = DatabaseManager(path)
            previous_session.initialize()
            previous_session.add_alert(
                "ARP_SPOOFING", "HIGH", "AA:BB:CC:DD:EE:FF", "192.168.1.1", 1, "Alerta anterior"
            )

            current_session = DatabaseManager(path)
            current_session.initialize()
            snapshot = current_session.dashboard_snapshot()

            self.assertEqual(snapshot["alert_count"], 0)
            self.assertEqual(snapshot["high_severity_count"], 0)
            self.assertEqual(snapshot["alert_type_counts"], [])
            self.assertEqual(snapshot["recent_alerts"], [])

            current_session.add_alert(
                "DNS_SPOOFING", "CRITICAL", "AA:BB:CC:DD:EE:00", "192.168.1.2", 1, "Alerta actual"
            )
            self.assertEqual(current_session.dashboard_snapshot()["alert_count"], 1)

    def test_dashboard_snapshot_rejects_non_positive_limits(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db = DatabaseManager(Path(tmp_dir) / "arpshield.db")
            db.initialize()

            with self.assertRaises(ValueError):
                db.dashboard_snapshot(recent_limit=0)


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

    def test_refresh_baseline_does_not_replace_existing_trusted_mac(self):
        fake_output = (
            "Interface: 192.168.1.10 --- 0x12\r\n"
            "  192.168.1.1     AA-BB-CC-DD-EE-FF     dynamic\r\n"
        ).encode("cp850")

        with tempfile.TemporaryDirectory() as tmp_dir:
            db = DatabaseManager(Path(tmp_dir) / "arpshield.db")
            db.initialize()
            db.add_baseline_entry("192.168.1.1", "00:11:22:33:44:55", "GATEWAY")
            monitor = ThreatMonitor(db)

            with patch(
                "subprocess.run",
                return_value=subprocess.CompletedProcess(
                    args=["arp", "-a"], returncode=0, stdout=fake_output, stderr=b""
                ),
            ):
                baseline = monitor.refresh_baseline()

            self.assertEqual(baseline[0]["mac_address"], "00:11:22:33:44:55")
            self.assertEqual(baseline[0]["device_type"], "GATEWAY")

    def test_repeated_anomaly_check_does_not_return_or_store_duplicate_alert(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db = DatabaseManager(Path(tmp_dir) / "arpshield.db")
            db.initialize()
            db.add_baseline_entry("192.168.1.1", "00:11:22:33:44:55", "GATEWAY")
            monitor = ThreatMonitor(db)
            observed = [{
                "ip_address": "192.168.1.1",
                "mac_address": "AA:BB:CC:DD:EE:FF",
            }]
            with patch.object(monitor, "discover_local_network", return_value=observed):
                first_check = monitor.check_for_anomalies()
                second_check = monitor.check_for_anomalies()

            self.assertEqual(len(first_check), 1)
            self.assertEqual(second_check, [])
            self.assertEqual(len(db.list_alerts()), 1)


if __name__ == "__main__":
    unittest.main()
