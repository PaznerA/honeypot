# Honeypot — replikovatelná platforma pro sběr dat o kybernetických útocích

Replikovatelné prostředí (definované v **Ansible**) pro nasazení honeypot
senzorů na VPS, sběr a normalizaci dat o kybernetických útocích a jejich
analýzu. Účel je **defenzivní**: získávat threat intelligence o útočnících
(zejména automatizované útoky, brute-force, skenování, pokusy o zneužití)
pro obranu infrastruktury.

> ⚠️ **Rozsah:** Toto je samostatný projekt určený pro provoz na dedikované
> VPS. Veškerý kód i dokumentace patří do tohoto repozitáře.

## Co to dělá

1. **Provisioning** — Ansible playbook připraví čistou VPS: zpevní hostitele
   (přesun reálného SSH, firewall, fail2ban), nainstaluje Docker a nasadí
   senzory i collector.
2. **Senzory** zachytávají interakce útočníků a logují je jako JSON:
   - **Cowrie** — nízko/středně-interakční SSH a Telnet honeypot (na portech 22/23).
   - **HTTP honeypot** — vlastní low-interaction HTTP senzor (port 80),
     zaznamenává požadavky a klasifikuje pokusy o zneužití.
3. **Collector** (`collector/`) — vlastní Python balíček: normalizuje logy
   senzorů do jednotného modelu, volitelně obohacuje (GeoIP) a ukládá do SQLite.
4. **Analýza** — CLI pro statistiky, žebříčky (top IP / hesla / země / kategorie)
   a export (JSON/CSV).

```text
                    VPS (provisioned Ansiblem)
  ┌───────────────────────────────────────────────────────────┐
  │  Docker                                                     │
  │   ┌──────────┐   ┌──────────────┐                          │
  │   │  Cowrie  │   │ HTTP honeypot │   ── JSON logy ──┐       │
  │   │  22/23   │   │      80       │                  │       │
  │   └──────────┘   └──────────────┘                  ▼       │
  │                                            ┌────────────┐  │
  │  systemd timer ── run-ingest.sh ──────────▶│  collector │  │
  │                                            │  (SQLite)  │  │
  │  reálné admin SSH: port 2222 (fail2ban, jen klíče)  └──────┘  │
  │  nftables: default-drop, honeypot porty otevřené          │
  └───────────────────────────────────────────────────────────┘
```

Podrobnosti viz [`docs/architecture.md`](docs/architecture.md).

## Struktura repozitáře

```text
ansible/     Replikovatelné provisioning (playbook site.yml + role)
sensors/     Definice senzorů (docker-compose + vlastní HTTP honeypot)
collector/   Vlastní Python balíček pro normalizaci a ukládání dat
tests/       Testy collectoru (pytest)
docs/        Dokumentace (architektura, deployment, data, threat model, provoz)
```

## Rychlý start

**Lokální vyzkoušení collectoru** (bez VPS):

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
honeypot-collector --db /tmp/hp.sqlite initdb
honeypot-collector --db /tmp/hp.sqlite ingest --sensor cowrie --file tests/fixtures/cowrie.sample.jsonl
honeypot-collector --db /tmp/hp.sqlite stats
```

**Nasazení na VPS** — viz [`docs/deployment.md`](docs/deployment.md).

## Dokumentace

| Dokument | Obsah |
|----------|-------|
| [architecture.md](docs/architecture.md) | Komponenty, tok dat, návrhová rozhodnutí |
| [deployment.md](docs/deployment.md) | Krok za krokem nasazení na VPS přes Ansible |
| [data-model.md](docs/data-model.md) | Normalizovaný model událostí, DB schéma, rozšíření o senzory |
| [threat-model.md](docs/threat-model.md) | Co honeypot chytá, rizika a jejich zmírnění |
| [operations.md](docs/operations.md) | Provoz, monitoring, zálohy, retence |
| [legal-and-data-protection.md](docs/legal-and-data-protection.md) | Právní a GDPR aspekty |

## Bezpečnostní upozornění

Honeypot je **záměrně** vystaven útokům. Provozujte ho na **dedikované,
izolované VPS** odděleně od produkční infrastruktury a řiďte se
[threat modelem](docs/threat-model.md) a [provozními pokyny](docs/operations.md).

## Licence

MIT — viz [LICENSE](LICENSE).
