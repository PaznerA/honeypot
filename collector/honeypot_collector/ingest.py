"""Ingest: čtení JSON log řádků senzorů → parse → enrich → uložení."""

from __future__ import annotations

import json
import os
from collections.abc import Iterable, Iterator
from dataclasses import dataclass

from honeypot_collector.enrichment import Enricher
from honeypot_collector.models import AttackEvent
from honeypot_collector.parsers import Parser, detect_parser
from honeypot_collector.storage import Storage


@dataclass
class IngestResult:
    read_lines: int = 0
    parsed_events: int = 0
    inserted: int = 0
    skipped_lines: int = 0

    def merge(self, other: IngestResult) -> None:
        self.read_lines += other.read_lines
        self.parsed_events += other.parsed_events
        self.inserted += other.inserted
        self.skipped_lines += other.skipped_lines


def records_to_events(
    records: Iterable[dict],
    parser: Parser | None,
    enricher: Enricher | None = None,
) -> Iterator[AttackEvent]:
    """Převede surové záznamy na obohacené události.

    Když ``parser`` je None, senzor se autodetekuje pro každý záznam.
    """
    for record in records:
        active = parser or detect_parser(record)
        if active is None:
            continue
        for event in active.parse(record):
            yield enricher.enrich(event) if enricher else event


def ingest_lines(
    storage: Storage,
    lines: Iterable[str],
    parser: Parser | None,
    enricher: Enricher | None = None,
) -> IngestResult:
    result = IngestResult()
    events: list[AttackEvent] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        result.read_lines += 1
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            result.skipped_lines += 1
            continue
        if not isinstance(record, dict):
            result.skipped_lines += 1
            continue
        active = parser or detect_parser(record)
        if active is None:
            result.skipped_lines += 1
            continue
        for event in active.parse(record):
            events.append(enricher.enrich(event) if enricher else event)
    result.parsed_events = len(events)
    result.inserted = storage.insert_events(events)
    return result


def ingest_file(
    storage: Storage,
    path: str,
    parser: Parser | None,
    enricher: Enricher | None = None,
    follow_offset: bool = True,
) -> IngestResult:
    """Ingest souboru s inkrementálním sledováním offsetu (idempotentní).

    Při rotaci logu (změna inode) se čte od začátku.
    """
    stat = os.stat(path)
    inode = stat.st_ino
    start = storage.get_ingest_offset(path, inode) if follow_offset else 0

    with open(path, encoding="utf-8", errors="replace") as fh:
        fh.seek(start)
        result = ingest_lines(storage, fh, parser, enricher)
        new_offset = fh.tell()

    if follow_offset:
        storage.set_ingest_offset(path, inode, new_offset)
    return result
