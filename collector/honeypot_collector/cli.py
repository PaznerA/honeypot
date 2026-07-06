"""Rozhraní příkazové řádky pro honeypot collector."""

from __future__ import annotations

import argparse
import csv
import json
import sys

from honeypot_collector import __version__
from honeypot_collector.enrichment import Enricher
from honeypot_collector.ingest import ingest_file, ingest_lines
from honeypot_collector.parsers import available_sensors, get_parser
from honeypot_collector.storage import Storage

DEFAULT_DB = "honeypot.sqlite"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="honeypot-collector",
        description="Sběr a analýza dat o kybernetických útocích ze senzorů honeypotu.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--db", default=DEFAULT_DB, help=f"Cesta k SQLite DB (výchozí: {DEFAULT_DB})"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("initdb", help="Vytvoří/aktualizuje schéma databáze")
    sub.add_parser("sensors", help="Vypíše podporované senzory")

    p_ingest = sub.add_parser("ingest", help="Nahraje události z log souboru nebo stdin")
    p_ingest.add_argument(
        "--sensor",
        choices=available_sensors(),
        help="Typ senzoru; při vynechání se autodetekuje z každého záznamu",
    )
    src = p_ingest.add_mutually_exclusive_group(required=True)
    src.add_argument("--file", help="Cesta k JSON-lines logu senzoru")
    src.add_argument("--stdin", action="store_true", help="Čte JSON-lines ze stdin")
    p_ingest.add_argument("--geoip-city-db", help="Cesta k MaxMind GeoLite2-City.mmdb")
    p_ingest.add_argument("--geoip-asn-db", help="Cesta k MaxMind GeoLite2-ASN.mmdb")
    p_ingest.add_argument(
        "--no-follow",
        action="store_true",
        help="Nesledovat offset (přečte celý soubor znovu; deduplikace zůstává)",
    )

    p_stats = sub.add_parser("stats", help="Souhrnné statistiky")
    p_stats.add_argument("--json", action="store_true", help="Výstup jako JSON")

    p_top = sub.add_parser("top", help="Nejčastější hodnoty ve sloupci")
    p_top.add_argument(
        "--by",
        default="src_ip",
        help="Sloupec (např. src_ip, country, username, password, category)",
    )
    p_top.add_argument("--limit", type=int, default=10)

    p_export = sub.add_parser("export", help="Export všech událostí")
    p_export.add_argument("--format", choices=("json", "csv"), default="json")
    p_export.add_argument("--out", help="Výstupní soubor (výchozí: stdout)")

    return parser


def _cmd_ingest(args: argparse.Namespace, storage: Storage) -> int:
    parser = get_parser(args.sensor) if args.sensor else None
    enricher = None
    if args.geoip_city_db or args.geoip_asn_db:
        enricher = Enricher(args.geoip_city_db, args.geoip_asn_db)

    if args.stdin:
        result = ingest_lines(storage, sys.stdin, parser, enricher)
    else:
        result = ingest_file(
            storage, args.file, parser, enricher, follow_offset=not args.no_follow
        )
    if enricher:
        enricher.close()

    print(
        f"přečteno={result.read_lines} události={result.parsed_events} "
        f"vloženo={result.inserted} přeskočeno={result.skipped_lines}"
    )
    return 0


def _cmd_stats(args: argparse.Namespace, storage: Storage) -> int:
    stats = storage.stats()
    if args.json:
        print(json.dumps(stats, ensure_ascii=False, indent=2))
        return 0
    print(f"Celkem událostí:     {stats['total_events']}")
    print(f"Unikátních zdroj IP: {stats['distinct_src_ips']}")
    for title, key in (("Senzory", "by_sensor"), ("Kategorie", "by_category"),
                       ("Protokoly", "by_protocol")):
        print(f"\n{title}:")
        for name, n in stats[key].items():
            print(f"  {name:<20} {n}")
    return 0


def _cmd_top(args: argparse.Namespace, storage: Storage) -> int:
    try:
        rows = storage.top(args.by, args.limit)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    for value, n in rows:
        print(f"{n:>8}  {value}")
    return 0


def _write_export(out, fmt: str, storage: Storage) -> None:
    with storage.iter_events() as cur:
        if fmt == "json":
            json.dump([dict(row) for row in cur], out, ensure_ascii=False, indent=2)
            out.write("\n")
        else:
            rows = list(cur)
            writer = csv.writer(out)
            if rows:
                writer.writerow(rows[0].keys())
                for row in rows:
                    writer.writerow(list(row))


def _cmd_export(args: argparse.Namespace, storage: Storage) -> int:
    if args.out:
        with open(args.out, "w", encoding="utf-8", newline="") as out:
            _write_export(out, args.format, storage)
    else:
        _write_export(sys.stdout, args.format, storage)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "sensors":
        print("\n".join(available_sensors()))
        return 0

    storage = Storage(args.db)
    try:
        storage.init_db()
        if args.command == "initdb":
            print(f"Inicializováno: {args.db}")
            return 0
        if args.command == "ingest":
            return _cmd_ingest(args, storage)
        if args.command == "stats":
            return _cmd_stats(args, storage)
        if args.command == "top":
            return _cmd_top(args, storage)
        if args.command == "export":
            return _cmd_export(args, storage)
    finally:
        storage.close()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
