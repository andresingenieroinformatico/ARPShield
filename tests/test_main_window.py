from __future__ import annotations

import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from arpshield.ui.main_window import trusted_device_label


class TrustedDeviceLabelTests(unittest.TestCase):
    def test_device_label_shows_user_alias_and_network_identifiers(self):
        label = trusted_device_label({
            "hostname": "Laptop Ana",
            "device_type": "KNOWN_HOST",
            "ip_address": "192.168.1.25",
            "mac_address": "00:11:22:33:44:55",
        })

        self.assertIn("Laptop Ana", label)
        self.assertIn("IP 192.168.1.25", label)
        self.assertIn("MAC 00:11:22:33:44:55", label)

    def test_device_without_name_uses_readable_role_as_fallback(self):
        label = trusted_device_label({
            "hostname": None,
            "device_type": "DNS_SERVER",
            "ip_address": "192.168.1.53",
            "mac_address": "00:11:22:33:44:53",
        })

        self.assertIn("Servidor DNS (sin nombre)", label)
        self.assertIn("IP 192.168.1.53", label)


if __name__ == "__main__":
    unittest.main()
