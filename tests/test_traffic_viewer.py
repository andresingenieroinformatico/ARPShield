from __future__ import annotations

import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from arpshield.detection import CAPTURE_FIELDS
from arpshield.ui.traffic_viewer import (
    DEFAULT_CAPTURE_FILTER,
    MAX_PACKET_ROWS,
    PACKET_COLUMNS,
    TrafficViewerPanel,
    packet_fields_to_row,
    parse_interfaces,
)


class TrafficViewerTests(unittest.TestCase):
    def test_parse_tshark_interface_list(self):
        output = (
            "1. \\Device\\NPF_{12345678-1234-1234-1234-123456789012} (Ethernet)\n"
            "2. \\Device\\NPF_Loopback (Adapter for loopback traffic capture)\n"
            "TShark: Some warning\n"
        )

        self.assertEqual(
            parse_interfaces(output),
            [
                ("1", "\\Device\\NPF_{12345678-1234-1234-1234-123456789012} (Ethernet)"),
                ("2", "\\Device\\NPF_Loopback (Adapter for loopback traffic capture)"),
            ],
        )

    def test_packet_fields_are_formatted_as_analyzable_columns(self):
        fields = [
            "2026-11-02 14:00:00",
            "42",
            "eth:ethertype:arp",
            "00:11:22:33:44:55",
            "ff:ff:ff:ff:ff:ff",
            "1",
            "192.168.1.10",
            "00:11:22:33:44:55",
            "192.168.1.1",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
        ]

        row = packet_fields_to_row("\t".join(fields))

        self.assertEqual(len(PACKET_COLUMNS), 8)
        self.assertEqual(row[2], "ARP")
        self.assertEqual(row[3:5], ["192.168.1.10", "192.168.1.1"])
        self.assertIn("Solicitud ARP", row[7])

    def test_packet_history_is_bounded_for_low_memory_systems(self):
        self.assertEqual(MAX_PACKET_ROWS, 500)

    def test_capture_arguments_match_detector_field_schema(self):
        arguments = TrafficViewerPanel._packet_arguments(DEFAULT_CAPTURE_FILTER)
        capture_fields = [
            arguments[index + 1]
            for index, value in enumerate(arguments[:-1])
            if value == "-e"
        ]

        self.assertEqual(capture_fields, list(CAPTURE_FIELDS))


if __name__ == "__main__":
    unittest.main()
