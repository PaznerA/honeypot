"""Parser pro Cowrie (SSH/Telnet honeypot) — formát JSON log (cowrie.json)."""

from __future__ import annotations

import json

from honeypot_collector.models import (
    CATEGORY_BRUTE_FORCE,
    CATEGORY_COMMAND_EXEC,
    CATEGORY_CREDENTIAL_USE,
    CATEGORY_MALWARE_DOWNLOAD,
    CATEGORY_RECON,
    CATEGORY_UNKNOWN,
    AttackEvent,
)
from honeypot_collector.parsers.base import Parser, as_int

# Mapování Cowrie eventid -> (normalizovaný event_type, kategorie, severity).
_EVENT_MAP: dict[str, tuple[str, str, int]] = {
    "cowrie.session.connect": ("connection", CATEGORY_RECON, 1),
    "cowrie.login.failed": ("login.failed", CATEGORY_BRUTE_FORCE, 2),
    "cowrie.login.success": ("login.success", CATEGORY_CREDENTIAL_USE, 3),
    "cowrie.command.input": ("command", CATEGORY_COMMAND_EXEC, 3),
    "cowrie.command.failed": ("command", CATEGORY_COMMAND_EXEC, 2),
    "cowrie.session.file_download": ("download", CATEGORY_MALWARE_DOWNLOAD, 4),
    "cowrie.session.file_upload": ("upload", CATEGORY_MALWARE_DOWNLOAD, 4),
    "cowrie.client.version": ("client.version", CATEGORY_RECON, 1),
    "cowrie.direct-tcpip.request": ("proxy.request", CATEGORY_RECON, 2),
}


class CowrieParser(Parser):
    name = "cowrie"

    def matches(self, record: dict) -> bool:
        eventid = record.get("eventid", "")
        return isinstance(eventid, str) and eventid.startswith("cowrie.")

    def parse(self, record: dict) -> list[AttackEvent]:
        eventid = record.get("eventid")
        if not isinstance(eventid, str) or not eventid.startswith("cowrie."):
            return []

        event_type, category, severity = _EVENT_MAP.get(
            eventid, (eventid.replace("cowrie.", ""), CATEGORY_UNKNOWN, 1)
        )

        payload = _payload_for(eventid, record)
        event = AttackEvent(
            event_time=str(record.get("timestamp") or ""),
            sensor=self.name,
            protocol=str(record.get("protocol") or "ssh"),
            event_type=event_type,
            src_ip=_str_or_none(record.get("src_ip")),
            src_port=as_int(record.get("src_port")),
            dst_port=as_int(record.get("dst_port")),
            session_id=_str_or_none(record.get("session")),
            username=_str_or_none(record.get("username")),
            password=_str_or_none(record.get("password")),
            payload=payload,
            category=category,
            severity=severity,
            raw=json.dumps(record, ensure_ascii=False, sort_keys=True),
        )
        return [event]


def _payload_for(eventid: str, record: dict) -> str | None:
    if eventid in ("cowrie.command.input", "cowrie.command.failed"):
        return _str_or_none(record.get("input"))
    if eventid in ("cowrie.session.file_download", "cowrie.session.file_upload"):
        return _str_or_none(record.get("url") or record.get("filename") or record.get("shasum"))
    if eventid == "cowrie.client.version":
        return _str_or_none(record.get("version"))
    return None


def _str_or_none(value: object) -> str | None:
    if value is None or value == "":
        return None
    return str(value)
