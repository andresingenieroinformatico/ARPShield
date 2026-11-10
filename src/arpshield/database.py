from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Iterable


ALERT_TYPES = (
    "GATEWAY_SPOOFING",
    "MULTIPLE_IPS_PER_MAC",
    "ARP_BURST_UNSOLICITED",
    "DNS_SPOOFING",
    "ARP_SPOOFING",
    "IP_SPOOFING",
    "MAC_SPOOFING",
    "DHCP_SPOOFING",
    "LLMNR_SPOOFING",
    "NBNS_SPOOFING",
    "MDNS_SPOOFING",
    "NDP_SPOOFING",
    "DHCPV6_SPOOFING",
)
DEVICE_TYPES = ("GATEWAY", "DNS_SERVER", "DHCP_SERVER", "KNOWN_HOST", "OTHER")


class DatabaseManager:
    ALERT_TYPES_SQL = ", ".join(f"'{alert_type}'" for alert_type in ALERT_TYPES)
    DEVICE_TYPES_SQL = ", ".join(f"'{device_type}'" for device_type in DEVICE_TYPES)
    CREATE_TABLES = """
    CREATE TABLE IF NOT EXISTS trusted_baseline (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT NOT NULL UNIQUE,
        mac_address TEXT NOT NULL,
        device_type TEXT CHECK(device_type IN ({device_types})) NOT NULL,
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
        alert_type TEXT CHECK(alert_type IN ({alert_types})) NOT NULL,
        severity TEXT CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')) NOT NULL,
        attacker_mac TEXT NOT NULL,
        spoofed_ip TEXT NOT NULL,
        packet_count INTEGER DEFAULT 1,
        evidence_summary TEXT NOT NULL,
        evidence_details TEXT NOT NULL DEFAULT '{{}}',
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
    """.format(alert_types=ALERT_TYPES_SQL, device_types=DEVICE_TYPES_SQL)

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._session_alert_start_id: int | None = None

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=DELETE")
        return connection

    def initialize(self) -> None:
        connection = self.connect()
        try:
            connection.executescript(self.CREATE_TABLES)
            self._migrate_device_types(connection)
            self._migrate_alert_types(connection)
            self._migrate_alert_details(connection)
            if self._session_alert_start_id is None:
                self._session_alert_start_id = connection.execute(
                    "SELECT COALESCE(MAX(id), 0) FROM security_alerts"
                ).fetchone()[0]
        finally:
            connection.close()

    def _migrate_device_types(self, connection: sqlite3.Connection) -> None:
        row = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='trusted_baseline'"
        ).fetchone()
        table_sql = row["sql"] if row else ""
        if all(device_type in table_sql for device_type in DEVICE_TYPES):
            return

        connection.execute("BEGIN")
        try:
            connection.execute(
                f"""
                CREATE TABLE trusted_baseline_migrated (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL UNIQUE,
                    mac_address TEXT NOT NULL,
                    device_type TEXT CHECK(device_type IN ({self.DEVICE_TYPES_SQL})) NOT NULL,
                    hostname TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            connection.execute(
                """
                INSERT INTO trusted_baseline_migrated (
                    id, ip_address, mac_address, device_type, hostname, created_at, updated_at
                )
                SELECT id, ip_address, mac_address, device_type, hostname, created_at, updated_at
                FROM trusted_baseline
                """
            )
            connection.execute("DROP TABLE trusted_baseline")
            connection.execute("ALTER TABLE trusted_baseline_migrated RENAME TO trusted_baseline")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_baseline_ip ON trusted_baseline(ip_address)")
            connection.commit()
        except Exception:
            connection.rollback()
            raise

    def _migrate_alert_types(self, connection: sqlite3.Connection) -> None:
        row = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='security_alerts'"
        ).fetchone()
        table_sql = row["sql"] if row else ""
        if all(alert_type in table_sql for alert_type in ALERT_TYPES):
            return

        connection.execute("BEGIN")
        try:
            connection.execute(
                f"""
                CREATE TABLE security_alerts_migrated (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp_utc DATETIME DEFAULT CURRENT_TIMESTAMP,
                    alert_type TEXT CHECK(alert_type IN ({self.ALERT_TYPES_SQL})) NOT NULL,
                    severity TEXT CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')) NOT NULL,
                    attacker_mac TEXT NOT NULL,
                    spoofed_ip TEXT NOT NULL,
                    packet_count INTEGER DEFAULT 1,
                    evidence_summary TEXT NOT NULL,
                    evidence_details TEXT NOT NULL DEFAULT '{{}}',
                    mitigation_applied INTEGER DEFAULT 0
                )
                """
            )
            connection.execute(
                """
                INSERT INTO security_alerts_migrated (
                    id, timestamp_utc, alert_type, severity, attacker_mac,
                    spoofed_ip, packet_count, evidence_summary, mitigation_applied
                )
                SELECT id, timestamp_utc, alert_type, severity, attacker_mac,
                       spoofed_ip, packet_count, evidence_summary, mitigation_applied
                FROM security_alerts
                """
            )
            connection.execute("DROP TABLE security_alerts")
            connection.execute("ALTER TABLE security_alerts_migrated RENAME TO security_alerts")
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON security_alerts(timestamp_utc)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_alerts_attacker ON security_alerts(attacker_mac)"
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise

    @staticmethod
    def _migrate_alert_details(connection: sqlite3.Connection) -> None:
        columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(security_alerts)")
        }
        if "evidence_details" not in columns:
            connection.execute(
                "ALTER TABLE security_alerts ADD COLUMN evidence_details TEXT NOT NULL DEFAULT '{}'"
            )
            connection.commit()

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

    def set_baseline_device_type(self, ip_address: str, device_type: str) -> None:
        if device_type not in DEVICE_TYPES:
            raise ValueError(f"Tipo de dispositivo no compatible: {device_type}")

        connection = self.connect()
        try:
            cursor = connection.execute(
                """
                UPDATE trusted_baseline
                SET device_type = ?, updated_at = CURRENT_TIMESTAMP
                WHERE ip_address = ?
                """,
                (device_type, ip_address),
            )
            if cursor.rowcount != 1:
                raise ValueError(f"No existe la dirección IP en la línea base: {ip_address}")
            connection.commit()
        finally:
            connection.close()

    def update_baseline_device(
        self,
        ip_address: str,
        device_type: str,
        hostname: str | None,
    ) -> None:
        if device_type not in DEVICE_TYPES:
            raise ValueError(f"Tipo de dispositivo no compatible: {device_type}")
        normalized_hostname = hostname.strip() if hostname else None
        if normalized_hostname and len(normalized_hostname) > 120:
            raise ValueError("El nombre del dispositivo no puede superar 120 caracteres")

        connection = self.connect()
        try:
            cursor = connection.execute(
                """
                UPDATE trusted_baseline
                SET device_type = ?, hostname = ?, updated_at = CURRENT_TIMESTAMP
                WHERE ip_address = ?
                """,
                (device_type, normalized_hostname or None, ip_address),
            )
            if cursor.rowcount != 1:
                raise ValueError(f"No existe la dirección IP en la línea base: {ip_address}")
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
        evidence_details: dict[str, Any] | None = None,
    ) -> bool:
        connection = self.connect()
        try:
            cursor = connection.execute(
                """
                INSERT INTO security_alerts (
                    alert_type, severity, attacker_mac, spoofed_ip,
                    packet_count, evidence_summary, evidence_details, mitigation_applied
                )
                SELECT ?, ?, ?, ?, ?, ?, ?, ?
                WHERE NOT EXISTS (
                    SELECT 1
                    FROM security_alerts
                    WHERE alert_type = ?
                        AND attacker_mac = ? COLLATE NOCASE
                        AND spoofed_ip = ? COLLATE NOCASE
                        AND timestamp_utc >= datetime('now', '-30 seconds')
                )
                """,
                (
                    alert_type,
                    severity,
                    attacker_mac,
                    spoofed_ip,
                    packet_count,
                    evidence_summary,
                    json.dumps(evidence_details or {}, ensure_ascii=False, sort_keys=True),
                    mitigation_applied,
                    alert_type,
                    attacker_mac,
                    spoofed_ip,
                ),
            )
            connection.commit()
            return cursor.rowcount == 1
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
        if self._session_alert_start_id is None:
            raise RuntimeError("La base de datos debe inicializarse antes de consultar el dashboard")

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
                            AS high_severity_count
                    FROM security_alerts
                    WHERE id > ?
                    """,
                (self._session_alert_start_id,),
            ).fetchone()
            alert_type_counts = connection.execute(
                """
                SELECT alert_type, COUNT(*) AS count
                FROM security_alerts
                WHERE id > ?
                GROUP BY alert_type
                """,
                (self._session_alert_start_id,),
            ).fetchall()
            daily_counts = connection.execute(
                """
                SELECT date(timestamp_utc) AS alert_date, COUNT(*) AS count
                FROM security_alerts
                WHERE id > ? AND timestamp_utc >= datetime('now', ?)
                GROUP BY date(timestamp_utc)
                """,
                (self._session_alert_start_id, f"-{trend_days - 1} days"),
            ).fetchall()
            recent_alerts = connection.execute(
                """
                SELECT * FROM security_alerts
                WHERE id > ?
                ORDER BY timestamp_utc DESC, id DESC
                LIMIT ?
                """,
                (self._session_alert_start_id, recent_limit),
            ).fetchall()
            return {
                "baseline_count": baseline_count,
                "alert_count": summary["alert_count"],
                "high_severity_count": summary["high_severity_count"],
                "alert_type_counts": [
                    (row["alert_type"], row["count"]) for row in alert_type_counts
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
