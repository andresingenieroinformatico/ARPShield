from __future__ import annotations

import ipaddress
import re
import subprocess
from typing import Any

from .config import is_valid_ipv4, is_valid_mac
from .database import DatabaseManager


class ThreatMonitor:
    def __init__(self, database: DatabaseManager):
        self.database = database

    @staticmethod
    def _decode_command_output(raw_output: bytes | str | None) -> str:
        if raw_output is None:
            return ""
        if isinstance(raw_output, str):
            return raw_output
        return raw_output.decode("utf-8", errors="replace")

    @staticmethod
    def _normalize_mac(mac_value: str) -> str:
        return mac_value.replace("-", ":").upper()

    def refresh_baseline(self) -> list[dict[str, Any]]:
        discovered = self.discover_local_network()
        for item in discovered:
            self.database.add_baseline_entry(
                ip_address=item["ip_address"],
                mac_address=item["mac_address"],
                device_type=item.get("device_type", "KNOWN_HOST"),
                hostname=item.get("hostname"),
            )
            self.database.add_audit_event(
                "baseline_refresh",
                f"Actualizada línea base para {item['ip_address']}",
                "local-monitor",
            )
        return self.database.list_baseline()

    def discover_local_network(self) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        try:
            result = subprocess.run(["arp", "-a"], capture_output=True, check=False, shell=False)
        except FileNotFoundError:
            return entries

        if result is None:
            return entries

        stdout = self._decode_command_output(result.stdout)
        stderr = self._decode_command_output(result.stderr)
        if not stdout and stderr:
            return entries

        for line in stdout.splitlines():
            normalized = line.strip()
            if not normalized or "Interface" in normalized or "Internet" in normalized:
                continue
            parts = re.split(r"\s+", normalized)
            if len(parts) < 3:
                continue
            ip_value = parts[0]
            mac_value = self._normalize_mac(parts[1])
            if not is_valid_ipv4(ip_value) or not is_valid_mac(mac_value):
                continue
            entries.append(
                {
                    "ip_address": ip_value,
                    "mac_address": mac_value,
                    "device_type": "KNOWN_HOST",
                    "hostname": None,
                }
            )

        if not entries:
            gateway_ip = self._infer_gateway_from_ipv4()
            if gateway_ip:
                entries.append(
                    {
                        "ip_address": gateway_ip,
                        "mac_address": "00:00:00:00:00:00",
                        "device_type": "GATEWAY",
                        "hostname": "gateway",
                    }
                )

        return entries

    def _infer_gateway_from_ipv4(self) -> str | None:
        try:
            import socket

            host_name = socket.gethostname()
            local_ip = socket.gethostbyname(host_name)
            network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
            return str(network.network_address + 1)
        except OSError:
            return None

    def check_for_anomalies(self) -> list[dict[str, Any]]:
        observed = self.discover_local_network()
        baseline = self.database.list_baseline()
        baseline_index = {entry["ip_address"]: entry for entry in baseline}
        alerts: list[dict[str, Any]] = []

        for item in observed:
            recorded = baseline_index.get(item["ip_address"])
            if recorded and recorded["mac_address"].upper() != item["mac_address"].upper():
                alert = {
                    "alert_type": "GATEWAY_SPOOFING",
                    "severity": "HIGH",
                    "attacker_mac": item["mac_address"].upper(),
                    "spoofed_ip": item["ip_address"],
                    "packet_count": 1,
                    "evidence_summary": f"La MAC {item['mac_address']} no coincide con la línea base registrada para {item['ip_address']}",
                }
                alerts.append(alert)
                self.database.add_alert(**alert)
        return alerts
