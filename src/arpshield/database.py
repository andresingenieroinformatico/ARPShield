from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Iterable


class DatabaseManager:
    CREATE_TABLES = """
    CREATE TABLE IF NOT EXISTS trusted_baseline (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT NOT NULL UNIQUE,
        mac_address TEXT NOT NULL,
        device_type TEXT CHECK(device_type IN ('GATEWAY', 'DNS_SERVER', 'KNOWN_HOST', 'OTHER')) NOT NULL,
        hostname TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS oui_catalog (
        mac_prefix TEXT PRIMARY KEY,
        vendor_name TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS security_alerts (
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

    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp_utc DATETIME DEFAULT CURRENT_TIMESTAMP,
        event_type TEXT NOT NULL,
        description TEXT NOT NULL,
        user_context TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_baseline_ip ON trusted_baseline(ip_address);
    CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON security_alerts(timestamp_utc);
    CREATE INDEX IF NOT EXISTS idx_alerts_attacker ON security_alerts(attacker_mac);
    """

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=DELETE")
        return connection

    def initialize(self) -> None:
        connection = self.connect()
        try:
            connection.executescript(self.CREATE_TABLES)
        finally:
            connection.close()

    def add_baseline_entry(
        self,
        ip_address: str,
        mac_address: str,
        device_type: str,
        hostname: str | None = None,
    ) -> None:
        connection = self.connect()
        try:
            connection.execute(
                """
                INSERT INTO trusted_baseline (ip_address, mac_address, device_type, hostname)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(ip_address) DO UPDATE SET
                    mac_address = excluded.mac_address,
                    device_type = excluded.device_type,
                    hostname = excluded.hostname,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (ip_address, mac_address, device_type, hostname),
            )
            connection.commit()
        finally:
            connection.close()

    def add_alert(
        self,
        alert_type: str,
        severity: str,
        attacker_mac: str,
        spoofed_ip: str,
        packet_count: int,
        evidence_summary: str,
        mitigation_applied: int = 0,
    ) -> None:
        connection = self.connect()
        try:
            connection.execute(
                """
                INSERT INTO security_alerts (
                    alert_type, severity, attacker_mac, spoofed_ip,
                    packet_count, evidence_summary, mitigation_applied
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (alert_type, severity, attacker_mac, spoofed_ip, packet_count, evidence_summary, mitigation_applied),
            )
            connection.commit()
        finally:
            connection.close()

    def add_audit_event(self, event_type: str, description: str, user_context: str) -> None:
        connection = self.connect()
        try:
            connection.execute(
                "INSERT INTO audit_logs (event_type, description, user_context) VALUES (?, ?, ?)",
                (event_type, description, user_context),
            )
            connection.commit()
        finally:
            connection.close()

    def list_baseline(self) -> list[dict[str, Any]]:
        connection = self.connect()
        try:
            rows = connection.execute(
                "SELECT id, ip_address, mac_address, device_type, hostname, created_at FROM trusted_baseline ORDER BY ip_address"
            ).fetchall()
            return [dict(row) for row in rows]
        finally:
            connection.close()

    def list_alerts(self) -> list[dict[str, Any]]:
        connection = self.connect()
        try:
            rows = connection.execute(
                "SELECT * FROM security_alerts ORDER BY timestamp_utc DESC"
            ).fetchall()
            return [dict(row) for row in rows]
        finally:
            connection.close()

    def dashboard_snapshot(self, recent_limit: int = 100, trend_days: int = 12) -> dict[str, Any]:
        if recent_limit < 1 or trend_days < 1:
            raise ValueError("recent_limit y trend_days deben ser mayores que cero")

        connection = self.connect()
        try:
            baseline_count = connection.execute(
                "SELECT COUNT(*) FROM trusted_baseline"
            ).fetchone()[0]
            summary = connection.execute(
                """
                SELECT
                    COUNT(*) AS alert_count,
                    COALESCE(SUM(CASE WHEN severity IN ('HIGH', 'CRITICAL') THEN 1 ELSE 0 END), 0)
                        AS high_severity_count,
                    COALESCE(SUM(CASE WHEN alert_type = 'GATEWAY_SPOOFING' THEN 1 ELSE 0 END), 0)
                        AS gateway_spoofing_count,
                    COALESCE(SUM(CASE WHEN alert_type = 'MULTIPLE_IPS_PER_MAC' THEN 1 ELSE 0 END), 0)
                        AS multiple_ips_count,
                    COALESCE(SUM(CASE WHEN alert_type = 'ARP_BURST_UNSOLICITED' THEN 1 ELSE 0 END), 0)
                        AS arp_burst_count,
                    COALESCE(SUM(CASE WHEN alert_type = 'DNS_SPOOFING' THEN 1 ELSE 0 END), 0)
                        AS dns_spoofing_count
                FROM security_alerts
                """
            ).fetchone()
            daily_counts = connection.execute(
                """
                SELECT date(timestamp_utc) AS alert_date, COUNT(*) AS count
                FROM security_alerts
                WHERE timestamp_utc >= datetime('now', ?)
                GROUP BY date(timestamp_utc)
                """,
                (f"-{trend_days - 1} days",),
            ).fetchall()
            recent_alerts = connection.execute(
                """
                SELECT * FROM security_alerts
                ORDER BY timestamp_utc DESC, id DESC
                LIMIT ?
                """,
                (recent_limit,),
            ).fetchall()
            return {
                "baseline_count": baseline_count,
                "alert_count": summary["alert_count"],
                "high_severity_count": summary["high_severity_count"],
                "alert_type_counts": [
                    ("GATEWAY_SPOOFING", summary["gateway_spoofing_count"]),
                    ("MULTIPLE_IPS_PER_MAC", summary["multiple_ips_count"]),
                    ("ARP_BURST_UNSOLICITED", summary["arp_burst_count"]),
                    ("DNS_SPOOFING", summary["dns_spoofing_count"]),
                ],
                "daily_counts": {row["alert_date"]: row["count"] for row in daily_counts},
                "recent_alerts": [dict(row) for row in recent_alerts],
            }
        finally:
            connection.close()

    def table_names(self) -> list[str]:
        connection = self.connect()
        try:
            rows = connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            ).fetchall()
            return [row["name"] for row in rows]
        finally:
            connection.close()
