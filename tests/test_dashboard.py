from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from arpshield.ui.dashboard import alert_details_text, format_colombia_timestamp


class DashboardAlertDetailsTests(unittest.TestCase):
    def test_alert_details_include_metadata_and_captured_packet_fields(self):
        rendered = alert_details_text({
            "id": 17,
            "timestamp_utc": "2026-11-10 14:00:00",
            "alert_type": "GATEWAY_SPOOFING",
            "severity": "HIGH",
            "spoofed_ip": "192.168.1.1",
            "attacker_mac": "AA:BB:CC:DD:EE:FF",
            "packet_count": 1,
            "mitigation_applied": 0,
            "evidence_summary": "Conflicto con la línea base",
            "evidence_details": json.dumps({
                "capture_source": "Captura en vivo (TShark)",
                "frame.number": "42",
                "arp.src.proto_ipv4": "192.168.1.1",
            }),
        })

        self.assertIn('"ID": 17', rendered)
        self.assertIn('"Fecha y hora Colombia (UTC-05:00)": "2026-11-10 09:00:00"', rendered)
        self.assertIn('"capture_source": "Captura en vivo (TShark)"', rendered)
        self.assertIn('"frame.number": "42"', rendered)
        self.assertIn('"arp.src.proto_ipv4": "192.168.1.1"', rendered)

    def test_colombia_timestamp_converts_timezone_aware_utc_and_preserves_invalid_values(self):
        self.assertEqual(
            format_colombia_timestamp("2026-11-16T17:36:27Z"),
            "2026-11-16 12:36:27",
        )
        self.assertEqual(format_colombia_timestamp("sin fecha"), "sin fecha")


if __name__ == "__main__":
    unittest.main()
