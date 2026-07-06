"""Normalizovaný datový model událostí o útocích."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone


def utcnow_iso() -> str:
    """Aktuální čas v UTC v ISO 8601."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


# Kategorie útoku (normalizovaná taxonomie napříč senzory).
CATEGORY_UNKNOWN = "unknown"
CATEGORY_RECON = "recon"
CATEGORY_BRUTE_FORCE = "brute_force"
CATEGORY_CREDENTIAL_USE = "credential_use"
CATEGORY_COMMAND_EXEC = "command_exec"
CATEGORY_MALWARE_DOWNLOAD = "malware_download"
CATEGORY_EXPLOIT_ATTEMPT = "exploit_attempt"

CATEGORIES = (
    CATEGORY_UNKNOWN,
    CATEGORY_RECON,
    CATEGORY_BRUTE_FORCE,
    CATEGORY_CREDENTIAL_USE,
    CATEGORY_COMMAND_EXEC,
    CATEGORY_MALWARE_DOWNLOAD,
    CATEGORY_EXPLOIT_ATTEMPT,
)


@dataclass
class AttackEvent:
    """Jedna normalizovaná událost útoku napříč všemi senzory."""

    event_time: str
    sensor: str
    protocol: str
    event_type: str
    src_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    session_id: str | None = None
    username: str | None = None
    password: str | None = None
    payload: str | None = None
    category: str = CATEGORY_UNKNOWN
    severity: int = 0
    country: str | None = None
    asn: str | None = None
    org: str | None = None
    raw: str | None = None
    ingest_time: str = field(default_factory=utcnow_iso)

    def dedup_key(self) -> str:
        """Stabilní hash pro idempotentní ingest (INSERT OR IGNORE)."""
        parts = [
            self.sensor,
            self.event_time,
            self.event_type,
            self.session_id or "",
            self.src_ip or "",
            str(self.src_port or ""),
            self.username or "",
            self.password or "",
            self.payload or "",
        ]
        digest = hashlib.sha256("\x1f".join(parts).encode("utf-8"))
        return digest.hexdigest()

    def to_dict(self) -> dict:
        return asdict(self)


def event_columns() -> tuple[str, ...]:
    """Názvy sloupců v pořadí definice datové třídy."""
    return tuple(f.name for f in fields(AttackEvent))
