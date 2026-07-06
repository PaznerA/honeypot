# honeypot-collector

Vlastní Python balíček pro sběr dat o kybernetických útocích. Čte JSON logy
senzorů honeypotu (Cowrie, HTTP honeypot), **normalizuje** je do jednotného
datového modelu, volitelně **obohacuje** (GeoIP) a **ukládá** do SQLite.
Součástí je CLI pro ingest, statistiky a export.

## Instalace (vývoj)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"        # z kořene repozitáře
```

Runtime nemá žádné povinné závislosti (pouze standardní knihovna). GeoIP je
volitelný extra: `pip install -e ".[geoip]"`.

## Použití

```bash
# inicializace databáze
honeypot-collector --db honeypot.sqlite initdb

# ingest logu konkrétního senzoru (idempotentní, sleduje offset)
honeypot-collector --db honeypot.sqlite ingest --sensor cowrie --file cowrie.json
honeypot-collector --db honeypot.sqlite ingest --sensor http   --file http.json

# ingest ze stdin s autodetekcí senzoru
cat mixed.jsonl | honeypot-collector --db honeypot.sqlite ingest --stdin

# analýza
honeypot-collector --db honeypot.sqlite stats
honeypot-collector --db honeypot.sqlite top --by src_ip --limit 20
honeypot-collector --db honeypot.sqlite top --by password
honeypot-collector --db honeypot.sqlite export --format csv --out events.csv
```

## Struktura

| Modul | Odpovědnost |
|-------|-------------|
| `models` | Normalizovaný `AttackEvent`, taxonomie kategorií, deduplikační klíč |
| `parsers/` | Převod surových záznamů senzorů na `AttackEvent` (Cowrie, HTTP, ...) |
| `enrichment` | Geolokace zdrojové IP (volitelně MaxMind GeoIP2) |
| `storage` | SQLite úložiště, dedup, sledování offsetu ingestu, dotazy |
| `ingest` | Čtení log řádků → parse → enrich → uložení |
| `cli` | Rozhraní příkazové řádky |

Přidání nového senzoru = nová třída `Parser` v `parsers/` zaregistrovaná v
`parsers/__init__.py`. Viz [../docs/data-model.md](../docs/data-model.md).
