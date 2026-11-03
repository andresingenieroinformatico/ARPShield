from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

REGEX_IPV4 = r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
REGEX_MAC = r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"

DEFAULT_DB_PATH = Path.home() / "AppData" / "Local" / "ARPShield" / "arpshield.db"


@dataclass(frozen=True)
class AppSettings:
    db_path: Path = DEFAULT_DB_PATH
    scan_interval_seconds: float = 5.0


def is_valid_ipv4(value: str) -> bool:
    return bool(re.fullmatch(REGEX_IPV4, value or ""))


def is_valid_mac(value: str) -> bool:
    return bool(re.fullmatch(REGEX_MAC, value or ""))
