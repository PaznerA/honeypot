"""Obohacování událostí — geolokace zdrojové IP (volitelně přes MaxMind GeoIP2).

GeoIP databáze (.mmdb) není součástí repozitáře (licence + velikost). Pokud
cesta k databázi není nastavena nebo knihovna ``geoip2`` chybí, obohacení
geolokací se přeskočí — pipeline funguje i bez ní.
"""

from __future__ import annotations

import ipaddress

from honeypot_collector.models import AttackEvent


class Enricher:
    def __init__(self, geoip_city_db: str | None = None, geoip_asn_db: str | None = None):
        self._city_reader = None
        self._asn_reader = None
        if geoip_city_db or geoip_asn_db:
            self._try_open(geoip_city_db, geoip_asn_db)

    def _try_open(self, city_db: str | None, asn_db: str | None) -> None:
        try:
            import geoip2.database  # noqa: PLC0415
        except ImportError:
            return
        if city_db:
            try:
                self._city_reader = geoip2.database.Reader(city_db)
            except OSError:
                self._city_reader = None
        if asn_db:
            try:
                self._asn_reader = geoip2.database.Reader(asn_db)
            except OSError:
                self._asn_reader = None

    def enrich(self, event: AttackEvent) -> AttackEvent:
        if not event.src_ip or not _is_public_ip(event.src_ip):
            return event
        if self._city_reader is not None and event.country is None:
            try:
                resp = self._city_reader.city(event.src_ip)
                event.country = resp.country.iso_code
            except Exception:  # noqa: BLE001 - GeoIP miss nesmí shodit ingest
                pass
        if self._asn_reader is not None and event.asn is None:
            try:
                resp = self._asn_reader.asn(event.src_ip)
                event.asn = f"AS{resp.autonomous_system_number}"
                event.org = resp.autonomous_system_organization
            except Exception:  # noqa: BLE001
                pass
        return event

    def close(self) -> None:
        for reader in (self._city_reader, self._asn_reader):
            if reader is not None:
                reader.close()


def _is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast)
