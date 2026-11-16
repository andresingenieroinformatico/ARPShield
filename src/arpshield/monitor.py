from __future__ import annotations

import ipaddress
import os
import re
import socket
import subprocess
from typing import Any

from .config import is_valid_ipv4, is_valid_mac
from .database import DatabaseManager
from .detection import SpoofingDetector


class ThreatMonitor:
    def __init__(self, database: DatabaseManager):
        self.database = database
        self.detector = SpoofingDetector()
        self._trusted_baseline = self.database.list_baseline()

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

    @staticmethod
    def _is_usable_host_ip(ip_value: str) -> bool:
        if not is_valid_ipv4(ip_value):
            return False
        try:
            ip_obj = ipaddress.IPv4Address(ip_value)
        except ipaddress.AddressValueError:
            return False
        if (
            ip_obj.is_multicast
            or ip_obj.is_loopback
            or ip_obj.is_unspecified
            or ip_obj.is_link_local
            or ip_value == "255.255.255.255"
            or ip_value.endswith(".255")
        ):
            return False
        return True

    @classmethod
    def _is_usable_host_mac(cls, mac_value: str) -> bool:
        normalized = cls._normalize_mac(mac_value)
        if not is_valid_mac(normalized):
            return False
        if normalized in {"00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"}:
            return False
        if normalized.startswith(("01:00:5E:", "33:33:", "01:80:C2:")):
            return False
        return True

    def reset_detector(self) -> None:
        self.detector.reset()
        self.reload_baseline()

    def refresh_baseline(self) -> list[dict[str, Any]]:
        discovered = self.discover_local_network()
        self.database.set_session_device_count(len(discovered))
        trusted_by_ip = {entry["ip_address"]: entry for entry in self.reload_baseline()}
        for item in discovered:
            existing = trusted_by_ip.get(item["ip_address"])
            if existing:
                if existing["mac_address"].upper() != item["mac_address"].upper():
                    self.database.add_audit_event(
                        "baseline_conflict",
                        f"Se observó una MAC distinta para {item['ip_address']}; se conservó la línea base confiable.",
                        "local-monitor",
                    )
                continue
            if item["mac_address"] == "00:00:00:00:00:00":
                continue
            self.database.add_baseline_entry(
                ip_address=item["ip_address"],
                mac_address=item["mac_address"],
                device_type=item.get("device_type", "KNOWN_HOST"),
                hostname=item.get("hostname"),
            )
            self.database.add_audit_event(
                "baseline_entry_added",
                f"Se agregó {item['ip_address']} a la línea base; verifica el dispositivo antes de confiar en él.",
                "local-monitor",
            )
        return self.reload_baseline()

    def reload_baseline(self) -> list[dict[str, Any]]:
        self._trusted_baseline = self.database.list_baseline()
        return self._trusted_baseline

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

        gateway_ips = self._get_active_gateway_ips() or set()
        active_interface_ips = self._get_active_interface_ips()
        if active_interface_ips is None:
            default_interface_ip = self._get_default_interface_ip()
            active_interface_ips = {default_interface_ip} if default_interface_ip else None

        seen_ips: set[str] = set()
        current_interface_ip: str | None = None
        for line in stdout.splitlines():
            normalized = line.strip()
            if not normalized:
                continue
            if "Interface" in normalized or "Interfaz" in normalized:
                iface_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", normalized)
                current_interface_ip = iface_match.group(1) if iface_match else None
                if active_interface_ips and current_interface_ip not in active_interface_ips:
                    continue
                continue
            if active_interface_ips and current_interface_ip not in active_interface_ips:
                continue
            if "Internet" in normalized or "Direcci" in normalized:
                continue
            parts = re.split(r"\s+", normalized)
            if len(parts) < 3:
                continue
            ip_value = parts[0]
            mac_value = self._normalize_mac(parts[1])
            if not self._is_usable_host_ip(ip_value) or not self._is_usable_host_mac(mac_value):
                continue
            if ip_value in seen_ips:
                continue
            seen_ips.add(ip_value)
            is_gateway = ip_value in gateway_ips
            entries.append(
                {
                    "ip_address": ip_value,
                    "mac_address": mac_value,
                    "device_type": "GATEWAY" if is_gateway else "KNOWN_HOST",
                    "hostname": "gateway" if is_gateway else None,
                }
            )

        return entries

    @staticmethod
    def _get_default_interface_ip() -> str | None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route_socket:
                # TEST-NET address used only for local route selection; no packet is sent.
                route_socket.connect(("192.0.2.1", 1))
                local_ip = route_socket.getsockname()[0]
            if not ThreatMonitor._is_usable_host_ip(local_ip):
                return None
            return local_ip
        except OSError:
            return None

    @staticmethod
    def _get_active_interface_ips() -> set[str] | None:
        if os.name != "nt":
            return None
        command = (
            "Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | "
            "ForEach-Object { Get-NetIPAddress -InterfaceIndex $_.ifIndex "
            "-AddressFamily IPv4 -ErrorAction SilentlyContinue } | "
            "Where-Object { $_.AddressState -eq 'Preferred' } | "
            "Select-Object -ExpandProperty IPAddress"
        )
        try:
            result = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                shell=False,
                check=False,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        if result.returncode != 0:
            return None
        ips = {
            line.strip()
            for line in result.stdout.splitlines()
            if ThreatMonitor._is_usable_host_ip(line.strip())
        }
        return ips or None

    @staticmethod
    def _get_active_gateway_ips() -> set[str] | None:
        if os.name != "nt":
            return None
        command = (
            "Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' "
            "-ErrorAction SilentlyContinue | "
            "Where-Object { $_.NextHop -and $_.NextHop -ne '0.0.0.0' } | "
            "Select-Object -ExpandProperty NextHop -Unique"
        )
        try:
            result = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                shell=False,
                check=False,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        if result.returncode != 0:
            return None
        gateways = {
            line.strip()
            for line in ThreatMonitor._decode_command_output(result.stdout).splitlines()
            if ThreatMonitor._is_usable_host_ip(line.strip())
        }
        return gateways or None

    def check_for_anomalies(self) -> list[dict[str, Any]]:
        observed = self.discover_local_network()
        baseline = self.reload_baseline()
        baseline_index = {entry["ip_address"]: entry for entry in baseline}
        trusted_ips_by_mac: dict[str, set[str]] = {}
        for entry in baseline:
            mac = self._normalize_mac(str(entry.get("mac_address", "")))
            ip = str(entry.get("ip_address", ""))
            if mac and ip:
                trusted_ips_by_mac.setdefault(mac, set()).add(ip)

        alerts: list[dict[str, Any]] = []
        observed_ips_by_mac: dict[str, list[str]] = {}

        for item in observed:
            mac_upper = self._normalize_mac(item["mac_address"])
            observed_ips_by_mac.setdefault(mac_upper, []).append(item["ip_address"])
            recorded = baseline_index.get(item["ip_address"])
            if recorded and self._normalize_mac(recorded["mac_address"]) != mac_upper:
                alert = {
                    "alert_type": (
                        "GATEWAY_SPOOFING"
                        if recorded.get("device_type") == "GATEWAY"
                        else "ARP_SPOOFING"
                    ),
                    "severity": "HIGH" if recorded.get("device_type") == "GATEWAY" else "MEDIUM",
                    "attacker_mac": mac_upper,
                    "spoofed_ip": item["ip_address"],
                    "packet_count": 1,
                    "evidence_summary": (
                        f"La MAC {mac_upper} no coincide con la línea base registrada para "
                        f"{item['ip_address']}. Verifica que la asociación confiable no haya cambiado."
                    ),
                    "evidence_details": {
                        "capture_source": "Tabla ARP local",
                        "observed_ip": item["ip_address"],
                        "observed_mac": mac_upper,
                        "baseline_mac": recorded["mac_address"],
                        "device_type": recorded.get("device_type", "KNOWN_HOST"),
                    },
                }
                if self.database.add_alert(**alert):
                    alerts.append(alert)

        for mac_upper, ips in observed_ips_by_mac.items():
            unique_ips = sorted(set(ips))
            if len(unique_ips) < 2:
                continue
            trusted_for_mac = trusted_ips_by_mac.get(mac_upper, set())
            if set(unique_ips).issubset(trusted_for_mac):
                continue
            has_gateway = any(
                baseline_index.get(ip, {}).get("device_type") == "GATEWAY" for ip in unique_ips
            )
            multi_alert = {
                "alert_type": "MULTIPLE_IPS_PER_MAC",
                "severity": "HIGH" if has_gateway else "MEDIUM",
                "attacker_mac": mac_upper,
                "spoofed_ip": ", ".join(unique_ips),
                "packet_count": len(unique_ips),
                "evidence_summary": (
                    f"La MAC {mac_upper} está asociada simultáneamente a múltiples IPs en la tabla ARP: "
                    f"{', '.join(unique_ips)}."
                ),
                "evidence_details": {
                    "capture_source": "Tabla ARP local",
                    "observed_mac": mac_upper,
                    "associated_ips": unique_ips,
                },
            }
            if self.database.add_alert(**multi_alert):
                alerts.append(multi_alert)

        return alerts

    def analyze_capture_record(
        self,
        capture_record: str,
        capture_source: str = "TShark",
    ) -> list[dict[str, Any]]:
        alerts = self.detector.analyze(
            capture_record,
            self._trusted_baseline,
            capture_source=capture_source,
        )
        is_file_capture = capture_source.startswith("Archivo PCAP")
        persisted_alerts: list[dict[str, Any]] = []
        for alert in alerts:
            stored = self.database.add_alert(**alert)
            if stored or is_file_capture:
                persisted_alerts.append(alert)
        return persisted_alerts
