# Datový model

## Normalizovaná událost `AttackEvent`

Každá interakce zachycená libovolným senzorem se převádí na jednotný záznam.
Definice: `collector/honeypot_collector/models.py`.

| Pole | Typ | Popis |
|------|-----|-------|
| `event_time` | str (ISO 8601) | Čas události dle senzoru |
| `sensor` | str | Zdrojový senzor (`cowrie`, `http`) |
| `protocol` | str | `ssh`, `telnet`, `http` |
| `event_type` | str | Normalizovaný typ (viz níže) |
| `src_ip` | str? | Zdrojová IP útočníka |
| `src_port` | int? | Zdrojový port |
| `dst_port` | int? | Cílový port na senzoru |
| `session_id` | str? | Identifikátor relace (u Cowrie) |
| `username` | str? | Zkoušené uživatelské jméno |
| `password` | str? | Zkoušené heslo |
| `payload` | str? | Příkaz, URL ke stažení, HTTP metoda+cesta, ... |
| `category` | str | Kategorie útoku (taxonomie níže) |
| `severity` | int | 0–4 (0 = info, 4 = kritické) |
| `country` | str? | ISO kód země (GeoIP, volitelné) |
| `asn` | str? | ASN zdroje (GeoIP, volitelné) |
| `org` | str? | Organizace ASN (GeoIP, volitelné) |
| `raw` | str | Původní záznam senzoru (JSON) pro forenzní dohledatelnost |
| `ingest_time` | str (ISO 8601) | Kdy collector událost zpracoval |

### Taxonomie kategorií

| Kategorie | Význam |
|-----------|--------|
| `recon` | Skenování, navázání spojení, banner grabbing |
| `brute_force` | Neúspěšné pokusy o přihlášení |
| `credential_use` | Úspěšné přihlášení zkoušenými údaji |
| `command_exec` | Spuštění příkazu v relaci |
| `malware_download` | Stažení/nahrání souboru (payload) |
| `exploit_attempt` | Pokus o zneužití (path traversal, známé CVE cesty, injection) |
| `unknown` | Nezařazeno |

### Typy událostí podle senzoru

**Cowrie** (mapování `eventid` → `event_type`, kategorie, severity):

| Cowrie `eventid` | `event_type` | kategorie | sev |
|------------------|--------------|-----------|-----|
| `cowrie.session.connect` | `connection` | recon | 1 |
| `cowrie.login.failed` | `login.failed` | brute_force | 2 |
| `cowrie.login.success` | `login.success` | credential_use | 3 |
| `cowrie.command.input` | `command` | command_exec | 3 |
| `cowrie.session.file_download` | `download` | malware_download | 4 |
| `cowrie.session.file_upload` | `upload` | malware_download | 4 |
| `cowrie.client.version` | `client.version` | recon | 1 |

**HTTP honeypot:** každý požadavek → `http.request`. Pokud cesta/tělo
obsahuje vzor zneužití (`../`, `/etc/passwd`, `wp-login`, `${jndi:`,
`union select`, ...), je `exploit_attempt` (sev 4), jinak `recon` (sev 1).

## Databázové schéma (SQLite)

Definice: `collector/honeypot_collector/storage.py`.

```sql
CREATE TABLE attack_events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    dedup_key  TEXT NOT NULL UNIQUE,   -- SHA-256 z významných polí
    event_time TEXT, sensor TEXT, protocol TEXT, event_type TEXT,
    src_ip TEXT, src_port TEXT, dst_port TEXT, session_id TEXT,
    username TEXT, password TEXT, payload TEXT,
    category TEXT, severity TEXT,
    country TEXT, asn TEXT, org TEXT,
    raw TEXT, ingest_time TEXT
);
-- indexy: src_ip, event_time, category, country

CREATE TABLE ingest_state (            -- inkrementální ingest
    path TEXT PRIMARY KEY, inode INTEGER, offset INTEGER
);
```

Hodnoty se ukládají jako `TEXT` kvůli jednotnosti; typování řeší aplikační
vrstva. `dedup_key` zajišťuje idempotentní ingest přes `INSERT OR IGNORE`.

## Přidání nového senzoru

1. Vytvoř třídu v `collector/honeypot_collector/parsers/` odvozenou od
   `Parser`, implementuj `parse(record) -> list[AttackEvent]` a volitelně
   `matches(record)` pro autodetekci.
2. Zaregistruj instanci v `parsers/__init__.py` (`_PARSERS`).
3. Přidej testy a fixture do `tests/`.
4. Pokud jde o novou dockerizovanou službu, přidej ji do
   `sensors/docker-compose.yml` a její log do `collector_sources`
   (role `collector`).
