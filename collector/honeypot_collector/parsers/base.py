"""Rozhraní parserů senzorů."""

from __future__ import annotations

import abc

from honeypot_collector.models import AttackEvent


class Parser(abc.ABC):
    """Převádí surový záznam senzoru (dict z JSON řádku) na normalizované události."""

    #: Krátký, stabilní identifikátor senzoru (musí odpovídat CLI ``--sensor``).
    name: str = ""

    @abc.abstractmethod
    def parse(self, record: dict) -> list[AttackEvent]:
        """Vrátí seznam událostí (obvykle 0 nebo 1) z jednoho záznamu."""
        raise NotImplementedError

    def matches(self, record: dict) -> bool:
        """Heuristika pro autodetekci senzoru z tvaru záznamu."""
        return False


def as_int(value: object) -> int | None:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None
