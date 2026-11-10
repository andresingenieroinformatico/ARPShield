from __future__ import annotations

import sys
import json
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from arpshield.detection import CAPTURE_FIELDS
from arpshield.database import DatabaseManager
from arpshield.monitor import ThreatMonitor


FIELD_COUNT = len(CAPTURE_FIELDS)


def capture_record(**values: str) -> str:
    fields = [""] * FIELD_COUNT
    fields[0] = values.get("timestamp", "2026-11-10 09:00:00")
    fields[1] = values.get("frame_number", "42")
    fields[2] = values.get("protocols", "")
    fields[3] = values.get("eth_src", "")
    fields[4] = values.get("eth_dst", "FF:FF:FF:FF:FF:FF")
    fields[5] = values.get("arp_opcode", "")
    fields[6] = values.get("arp_src_ip", "")
    fields[7] = values.get("arp_src_mac", "")
    fields[10] = values.get("dns_query", "")
    fields[11] = values.get("dns_response", "")
    fields[12] = values.get("dns_answer", "")
    fields[13] = values.get("ip_src", "")
    fields[14] = values.get("ip_dst", "")
    fields[17] = values.get("dhcp_message_type", "")
    fields[18] = values.get("dhcp_server_id", "")
    fields[19] = values.get("bootp_transaction_id", "")
    fields[20] = values.get("dns_id", "")
    fields[21] = values.get("nbns_id", "")
    fields[22] = values.get("nbns_response", "")
    fields[23] = values.get("nbns_name", "")
    fields[24] = values.get("nbns_address", "")
    fields[25] = values.get("icmpv6_type", "")
    fields[26] = values.get("ndp_na_target", "")
    fields[28] = values.get("dns_aaaa", "")
    fields[29] = values.get("dhcpv6_message_type", "")
    fields[30] = values.get("dhcpv6_transaction_id", "")
    fields[31] = values.get("udp_source_port", "")
    fields[32] = values.get("udp_destination_port", "")
    return "\t".join(fields)


class SpoofingDetectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.database = DatabaseManager(Path(self.tmp_dir.name) / "arpshield.db")
        self.database.initialize()

    def tearDown(self):
        self.tmp_dir.cleanup()

    def _monitor(self) -> ThreatMonitor:
        return ThreatMonitor(self.database)

    def test_detects_arp_mapping_conflicting_with_trusted_baseline(self):
        self.database.add_baseline_entry("192.168.1.1", "00:11:22:33:44:55", "GATEWAY")
        monitor = self._monitor()

        alerts = monitor.analyze_capture_record(
            capture_record(
                protocols="eth:arp",
                eth_src="AA:BB:CC:DD:EE:FF",
                arp_opcode="2",
                arp_src_ip="192.168.1.1",
                arp_src_mac="AA:BB:CC:DD:EE:FF",
            )
        )

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["alert_type"], "GATEWAY_SPOOFING")
        self.assertEqual(alerts[0]["severity"], "HIGH")
        self.assertEqual(alerts[0]["evidence_details"]["frame.number"], "42")
        stored = json.loads(self.database.list_alerts()[0]["evidence_details"])
        self.assertEqual(stored["capture_source"], "TShark")
        self.assertEqual(stored["arp.src.proto_ipv4"], "192.168.1.1")

    def test_detects_ip_spoofing_against_trusted_baseline(self):
        self.database.add_baseline_entry("192.168.1.20", "00:11:22:33:44:55", "KNOWN_HOST")
        monitor = self._monitor()

        alerts = monitor.analyze_capture_record(
            capture_record(
                protocols="eth:ethertype:ip:tcp",
                eth_src="AA:BB:CC:DD:EE:FF",
                ip_src="192.168.1.20",
            )
        )

        self.assertEqual(alerts[0]["alert_type"], "IP_SPOOFING")
        self.assertEqual(alerts[0]["severity"], "MEDIUM")

    def test_detects_trusted_mac_used_for_a_different_ip(self):
        self.database.add_baseline_entry("192.168.1.20", "00:11:22:33:44:55", "KNOWN_HOST")
        self.database.add_baseline_entry("192.168.1.30", "00:11:22:33:44:66", "KNOWN_HOST")
        monitor = self._monitor()

        alerts = monitor.analyze_capture_record(
            capture_record(
                protocols="eth:ethertype:ip:tcp",
                eth_src="00:11:22:33:44:66",
                ip_src="192.168.1.20",
            )
        )

        self.assertEqual({alert["alert_type"] for alert in alerts}, {"IP_SPOOFING", "MAC_SPOOFING"})
        self.assertTrue(all(alert["severity"] == "MEDIUM" for alert in alerts))

    def test_does_not_flag_multiple_trusted_ips_on_same_mac(self):
        self.database.add_baseline_entry("192.168.1.20", "00:11:22:33:44:55", "KNOWN_HOST")
        self.database.add_baseline_entry("192.168.1.21", "00:11:22:33:44:55", "KNOWN_HOST")
        monitor = self._monitor()

        alerts = monitor.analyze_capture_record(
            capture_record(
                protocols="eth:ethertype:ip:tcp",
                eth_src="00:11:22:33:44:55",
                ip_src="192.168.1.21",
            )
        )

        self.assertEqual(alerts, [])

    def test_detects_dns_response_from_untrusted_resolver(self):
        self.database.add_baseline_entry("192.168.1.53", "00:11:22:33:44:53", "DNS_SERVER")
        monitor = self._monitor()

        alerts = monitor.analyze_capture_record(
            capture_record(
                protocols="eth:ip:udp:dns",
                eth_src="AA:BB:CC:DD:EE:FF",
                dns_query="example.test",
                dns_response="1",
                dns_id="0x1234",
                ip_src="192.168.1.66",
            )
        )

        self.assertEqual(alerts[0]["alert_type"], "DNS_SPOOFING")
        self.assertEqual(alerts[0]["severity"], "MEDIUM")

    def test_detects_conflicting_dns_answers(self):
        monitor = self._monitor()
        common = {
            "protocols": "eth:ip:udp:dns",
            "dns_query": "example.test",
            "dns_response": "1",
            "dns_id": "0x1234",
            "ip_dst": "192.168.1.10",
        }
        monitor.analyze_capture_record(
            capture_record(**common, eth_src="00:11:22:33:44:53", dns_answer="203.0.113.10")
        )

        alerts = monitor.analyze_capture_record(
            capture_record(**common, eth_src="AA:BB:CC:DD:EE:FF", dns_answer="203.0.113.99")
        )

        self.assertEqual(alerts[0]["alert_type"], "DNS_SPOOFING")
        self.assertEqual(alerts[0]["severity"], "MEDIUM")

    def test_detects_competing_dhcp_servers_for_same_transaction(self):
        monitor = self._monitor()
        common = {
            "protocols": "eth:ip:udp:bootp:dhcp",
            "dhcp_message_type": "2",
            "bootp_transaction_id": "0xabc123",
        }
        monitor.analyze_capture_record(
            capture_record(**common, dhcp_server_id="192.168.1.1", eth_src="00:11:22:33:44:55")
        )

        alerts = monitor.analyze_capture_record(
            capture_record(**common, dhcp_server_id="192.168.1.66", eth_src="AA:BB:CC:DD:EE:FF")
        )

        self.assertEqual(alerts[0]["alert_type"], "DHCP_SPOOFING")

    def test_detects_dhcp_server_not_in_trusted_server_list(self):
        self.database.add_baseline_entry("192.168.1.1", "00:11:22:33:44:55", "DHCP_SERVER")
        monitor = self._monitor()

        alerts = monitor.analyze_capture_record(
            capture_record(
                protocols="eth:ip:udp:bootp:dhcp",
                dhcp_message_type="2",
                dhcp_server_id="192.168.1.66",
                bootp_transaction_id="0xabc123",
                eth_src="AA:BB:CC:DD:EE:FF",
            )
        )

        self.assertEqual(alerts[0]["alert_type"], "DHCP_SPOOFING")
        self.assertEqual(alerts[0]["severity"], "MEDIUM")
        self.assertEqual(len(self.database.list_alerts()), 1)

    def test_dns_answer_record_order_does_not_create_conflict(self):
        monitor = self._monitor()
        common = {
            "protocols": "eth:ip:udp:dns",
            "dns_query": "pool.example.test",
            "dns_response": "1",
            "dns_id": "0x1234",
            "ip_dst": "192.168.1.10",
        }
        monitor.analyze_capture_record(
            capture_record(**common, eth_src="00:11:22:33:44:53", dns_answer="192.0.2.10,192.0.2.11")
        )

        alerts = monitor.analyze_capture_record(
            capture_record(**common, eth_src="AA:BB:CC:DD:EE:FF", dns_answer="192.0.2.11,192.0.2.10")
        )

        self.assertEqual(alerts, [])

    def test_mdns_response_is_not_misclassified_as_untrusted_dns_resolver(self):
        self.database.add_baseline_entry("192.168.1.53", "00:11:22:33:44:53", "DNS_SERVER")
        monitor = self._monitor()

        alerts = monitor.analyze_capture_record(
            capture_record(
                protocols="eth:ip:udp:dns",
                eth_src="AA:BB:CC:DD:EE:FF",
                dns_query="printer.local",
                dns_response="1",
                dns_id="0x0000",
                dns_answer="192.168.1.20",
                udp_source_port="5353",
                udp_destination_port="5353",
            )
        )

        self.assertEqual(alerts, [])

    def test_dhcpv6_allowlist_uses_mac_not_ipv4_address(self):
        self.database.add_baseline_entry("192.168.1.1", "00:11:22:33:44:55", "DHCP_SERVER")
        monitor = self._monitor()

        alerts = monitor.analyze_capture_record(
            capture_record(
                protocols="eth:ipv6:udp:dhcpv6",
                eth_src="00:11:22:33:44:55",
                ip_src="fe80::1",
                dhcpv6_message_type="2",
                dhcpv6_transaction_id="0xabc123",
            )
        )

        self.assertEqual(alerts, [])

    def test_detects_competing_dhcpv6_servers_for_same_transaction(self):
        monitor = self._monitor()
        common = {
            "protocols": "eth:ipv6:udp:dhcpv6",
            "dhcpv6_message_type": "2",
            "dhcpv6_transaction_id": "0xabc123",
        }
        monitor.analyze_capture_record(
            capture_record(**common, eth_src="00:11:22:33:44:55")
        )

        alerts = monitor.analyze_capture_record(
            capture_record(**common, eth_src="AA:BB:CC:DD:EE:FF")
        )

        self.assertEqual(alerts[0]["alert_type"], "DHCPV6_SPOOFING")

    def test_detects_conflicting_nbns_and_mdns_answers(self):
        monitor = self._monitor()
        monitor.analyze_capture_record(
            capture_record(
                protocols="eth:ip:udp:nbns",
                eth_src="00:11:22:33:44:55",
                nbns_id="0x1001",
                nbns_response="1",
                nbns_name="WORKSTATION",
                nbns_address="192.168.1.20",
            )
        )
        nbns_alerts = monitor.analyze_capture_record(
            capture_record(
                protocols="eth:ip:udp:nbns",
                eth_src="AA:BB:CC:DD:EE:FF",
                nbns_id="0x1001",
                nbns_response="1",
                nbns_name="WORKSTATION",
                nbns_address="192.168.1.99",
            )
        )
        self.assertEqual(nbns_alerts[0]["alert_type"], "NBNS_SPOOFING")

        monitor.analyze_capture_record(
            capture_record(
                protocols="eth:ip:udp:mdns",
                eth_src="00:11:22:33:44:55",
                dns_query="printer.local",
                dns_response="1",
                dns_id="0x0000",
                dns_answer="192.168.1.20",
            )
        )
        mdns_alerts = monitor.analyze_capture_record(
            capture_record(
                protocols="eth:ip:udp:mdns",
                eth_src="AA:BB:CC:DD:EE:FF",
                dns_query="printer.local",
                dns_response="1",
                dns_id="0x0000",
                dns_answer="192.168.1.99",
            )
        )
        self.assertEqual(mdns_alerts[0]["alert_type"], "MDNS_SPOOFING")

    def test_detects_ipv6_router_advertisement_from_untrusted_mac(self):
        self.database.add_baseline_entry("192.168.1.1", "00:11:22:33:44:55", "GATEWAY")
        monitor = self._monitor()

        alerts = monitor.analyze_capture_record(
            capture_record(
                protocols="eth:ipv6:icmpv6",
                eth_src="AA:BB:CC:DD:EE:FF",
                icmpv6_type="134",
                ip_src="fe80::2",
            )
        )

        self.assertEqual(alerts[0]["alert_type"], "NDP_SPOOFING")
        self.assertEqual(alerts[0]["severity"], "MEDIUM")

    def test_flags_unregistered_ipv6_router_advertisement_for_review(self):
        monitor = self._monitor()

        alerts = monitor.analyze_capture_record(
            capture_record(
                protocols="eth:ipv6:icmpv6",
                eth_src="AA:BB:CC:DD:EE:FF",
                icmpv6_type="134",
                ip_src="fe80::2",
            )
        )

        self.assertEqual(alerts[0]["alert_type"], "NDP_SPOOFING")
        self.assertEqual(alerts[0]["severity"], "MEDIUM")


if __name__ == "__main__":
    unittest.main()
