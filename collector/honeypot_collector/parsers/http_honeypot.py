"""Parser pro vlastní low-interaction HTTP honeypot (sensors/http-honeypot).

Formát je pod naší kontrolou: každý řádek je JSON objekt zapsaný honeypotem.
"""

from __future__ import annotations

import json

from honeypot_collector.models import (
    CATEGORY_EXPLOIT_ATTEMPT,
    CATEGORY_RECON,
    AttackEvent,
)
from honeypot_collector.parsers.base import Parser, as_int

# Vzory v cestě/těle, které silně indikují pokus o zneužití.
_EXPLOIT_MARKERS = (
    "../",
    "/etc/passwd",
    "wp-login",
    "wp-admin",
    "phpmyadmin",
    "/.env",
    "/.git",
    "eval(",
    "base64_decode",
    "union select",
    "<?php",
    "cmd=",
    "${jndi:",
    "/cgi-bin/",
    "wget ",
    "curl ",
    "/boaform/",
)


class HttpHoneypotParser(Parser):
    name = "http"

    def matches(self, record: dict) -> bool:
        return record.get("sensor") == "http-honeypot" or (
            "method" in record and "path" in record
        )

    def parse(self, record: dict) -> list[AttackEvent]:
        method = str(record.get("method") or "")
        path = str(record.get("path") or "")
        body = record.get("body") or ""
        haystack = f"{path}\n{body}".lower()

        is_exploit = any(marker in haystack for marker in _EXPLOIT_MARKERS)
        category = CATEGORY_EXPLOIT_ATTEMPT if is_exploit else CATEGORY_RECON
        severity = 4 if is_exploit else 1

        payload = f"{method} {path}".strip()
        event = AttackEvent(
            event_time=str(record.get("ts") or record.get("timestamp") or ""),
            sensor="http",
            protocol="http",
            event_type="http.request",
            src_ip=_str_or_none(record.get("src_ip")),
            src_port=as_int(record.get("src_port")),
            dst_port=as_int(record.get("dst_port")),
            username=_str_or_none(_basic_auth_user(record)),
            payload=payload,
            category=category,
            severity=severity,
            raw=json.dumps(record, ensure_ascii=False, sort_keys=True),
        )
        return [event]


def _basic_auth_user(record: dict) -> str | None:
    auth = record.get("auth") or {}
    if isinstance(auth, dict):
        return auth.get("username")
    return None


def _str_or_none(value: object) -> str | None:
    if value is None or value == "":
        return None
    return str(value)
