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
    build_interface_options,
    capture_interface_target,
    interface_guid,
    packet_fields_to_row,
    parse_local_adapters,
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
        self.assertIn("udp.srcport", capture_fields)
        self.assertIn("udp.dstport", capture_fields)
        self.assertIn(("-E", "occurrence=a"), list(zip(arguments, arguments[1:])))

    def test_capture_uses_stable_local_device_name_not_interface_number(self):
        interface = r"\Device\NPF_{12345678-1234-1234-1234-123456789012} (Ethernet)"
        target = capture_interface_target(interface)

        self.assertEqual(
            target,
            r"\Device\NPF_{12345678-1234-1234-1234-123456789012}",
        )
        arguments = TrafficViewerPanel._live_capture_arguments(target, "arp")
        self.assertEqual(arguments[:2], ["-i", target])

    def test_capture_target_excludes_unconfigured_remote_sources(self):
        for interface in ("ciscodump (Cisco remote capture)", "sshdump (SSH remote capture)"):
            with self.subTest(interface=interface):
                self.assertIsNone(capture_interface_target(interface))

    def test_interface_options_show_unconfigured_extcap_without_enabling_capture(self):
        options = build_interface_options(
            [("4", "ciscodump (Cisco remote capture)")],
            {},
        )

        self.assertEqual(len(options), 1)
        self.assertIsNone(options[0][1])
        self.assertEqual(options[0][2], "extcap")
        self.assertIn("no configurado", options[0][0])

    def test_windows_local_adapter_data_includes_physical_and_virtual_interfaces(self):
        adapters = parse_local_adapters(
            '[{"Name":"Ethernet","Status":"Up","HardwareInterface":true,'
            '"InterfaceGuid":"{12345678-1234-1234-1234-123456789012}",'
            '"Addresses":["192.168.20.144"]},'
            '{"Name":"VirtualBox Host-Only","Status":"Up","HardwareInterface":false,'
            '"InterfaceGuid":"{87654321-4321-4321-4321-210987654321}",'
            '"Addresses":["192.168.56.1"]}]'
        )
        target = r"\Device\NPF_{12345678-1234-1234-1234-123456789012}"
        virtual_target = r"\Device\NPF_{87654321-4321-4321-4321-210987654321}"

        self.assertEqual(interface_guid(target), "12345678-1234-1234-1234-123456789012")
        self.assertEqual(adapters[interface_guid(target)]["hardware_interface"], True)
        self.assertEqual(adapters[interface_guid(virtual_target)]["hardware_interface"], False)
        self.assertEqual(adapters[interface_guid(virtual_target)]["status"], "Up")
        self.assertEqual(adapters[interface_guid(virtual_target)]["addresses"], "192.168.56.1")

    def test_interface_options_keep_unmapped_virtual_and_down_tshark_interfaces(self):
        interfaces = [
            ("1", r"\Device\NPF_{12345678-1234-1234-1234-123456789012} (VirtualBox)"),
            ("2", r"\Device\NPF_{87654321-4321-4321-4321-210987654321} (Disconnected)"),
            ("3", r"\Device\NPF_Loopback (Adapter for loopback traffic capture)"),
        ]
        adapters = parse_local_adapters(
            '[{"Name":"VirtualBox Host-Only","Status":"Up","HardwareInterface":false,'
            '"InterfaceGuid":"{12345678-1234-1234-1234-123456789012}",'
            '"Addresses":["192.168.56.1"]},'
            '{"Name":"Ethernet 5","Status":"Disconnected","HardwareInterface":false,'
            '"InterfaceGuid":"{87654321-4321-4321-4321-210987654321}","Addresses":[]}]'
        )

        options = build_interface_options(interfaces, adapters)

        self.assertEqual(len(options), 3)
        self.assertIn("192.168.56.1", options[0][0])
        self.assertIn("Up", options[0][0])
        self.assertIn("Disconnected", options[1][0])
        self.assertEqual(options[1][2], "Disconnected")
        self.assertIn("3.", options[2][0])
        self.assertEqual(options[2][2], "N/D")

    def test_packet_fields_format_dhcp_nbns_and_mdns_protocols_instead_of_generic_udp(self):
        dhcp_fields = [""] * len(CAPTURE_FIELDS)
        dhcp_fields[0] = "2026-11-16 10:00:00"
        dhcp_fields[1] = "10"
        dhcp_fields[2] = "eth:ethertype:ip:udp:dhcp"
        dhcp_fields[3] = "00:11:22:33:44:55"
        dhcp_fields[4] = "FF:FF:FF:FF:FF:FF"
        dhcp_fields[13] = "192.168.1.1"
        dhcp_fields[14] = "255.255.255.255"
        dhcp_fields[17] = "2"
        dhcp_fields[18] = "192.168.1.1"
        dhcp_fields[19] = "0x1234"

        row = packet_fields_to_row("\t".join(dhcp_fields))
        self.assertEqual(row[2], "DHCP")
        self.assertIn("DHCP Offer", row[7])
        self.assertIn("Servidor: 192.168.1.1", row[7])


if __name__ == "__main__":
    unittest.main()
