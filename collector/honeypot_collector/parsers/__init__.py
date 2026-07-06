"""Registr parserů senzorů."""

from __future__ import annotations

from honeypot_collector.parsers.base import Parser
from honeypot_collector.parsers.cowrie import CowrieParser
from honeypot_collector.parsers.http_honeypot import HttpHoneypotParser

_PARSERS: dict[str, Parser] = {
    p.name: p for p in (CowrieParser(), HttpHoneypotParser())
}


def available_sensors() -> list[str]:
    return sorted(_PARSERS)


def get_parser(sensor: str) -> Parser:
    try:
        return _PARSERS[sensor]
    except KeyError as exc:
        raise ValueError(
            f"Neznámý senzor '{sensor}'. Dostupné: {', '.join(available_sensors())}"
        ) from exc


def detect_parser(record: dict) -> Parser | None:
    for parser in _PARSERS.values():
        if parser.matches(record):
            return parser
    return None


__all__ = [
    "Parser",
    "CowrieParser",
    "HttpHoneypotParser",
    "available_sensors",
    "get_parser",
    "detect_parser",
]
