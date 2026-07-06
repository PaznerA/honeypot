# Provoz

## Kde co běží

| Komponenta | Umístění na VPS |
|------------|-----------------|
| Definice senzorů | `/opt/honeypot/sensors/` (docker-compose + `.env`) |
| Data senzorů (JSON logy) | `/opt/honeypot/data/{cowrie,http}/` |
| Balíček collectoru | `/opt/honeypot/collector/` |
| venv collectoru | `/opt/honeypot/collector-venv/` |
| Databáze | `/opt/honeypot/data/collector/honeypot.sqlite` |
| Ingest skript | `/opt/honeypot/bin/run-ingest.sh` |
| Timer / service | `honeypot-ingest.timer`, `honeypot-ingest.service` |

## Běžné příkazy

```bash
# stav senzorů
sudo docker compose -f /opt/honeypot/sensors/docker-compose.yml ps
sudo docker compose -f /opt/honeypot/sensors/docker-compose.yml logs -f cowrie

# stav ingestu
sudo systemctl status honeypot-ingest.timer
sudo systemctl list-timers honeypot-ingest.timer
journalctl -u honeypot-ingest.service --since "1 hour ago"

# ruční ingest
sudo /opt/honeypot/bin/run-ingest.sh

# analýza (CLI collectoru)
DB=/opt/honeypot/data/collector/honeypot.sqlite
PY=/opt/honeypot/collector-venv/bin/python
sudo PYTHONPATH=/opt/honeypot/collector $PY -m honeypot_collector.cli --db $DB stats
sudo PYTHONPATH=/opt/honeypot/collector $PY -m honeypot_collector.cli --db $DB top --by src_ip
sudo PYTHONPATH=/opt/honeypot/collector $PY -m honeypot_collector.cli --db $DB top --by password
```

## Monitoring

Sleduj minimálně:

- **Běh timeru** — zpoždění/selhání `honeypot-ingest.service` (journalctl).
- **Růst dat** — velikost `data/` a databáze; nastav alert na volné místo.
- **Odchozí provoz** — neočekávaný odchozí traffic může znamenat zneužití VPS
  (viz [threat-model.md](threat-model.md), R2).
- **fail2ban** — `sudo fail2ban-client status sshd` pro přehled banů admin SSH.

## Zálohování

Databáze je jeden SQLite soubor. Konzistentní záloha za běhu:

```bash
sudo /opt/honeypot/collector-venv/bin/python - <<'PY'
import sqlite3
src = sqlite3.connect("/opt/honeypot/data/collector/honeypot.sqlite")
dst = sqlite3.connect("/opt/honeypot/data/collector/backup.sqlite")
with dst:
    src.backup(dst)
print("záloha hotová")
PY
```

Zálohu přenes mimo VPS (útočník má potenciálně přístup k hostiteli). Zvaž
periodický export do centrálního úložiště (viz agregace v
[architecture.md](architecture.md)).

## Retence dat

`raw_log_retention_days` (výchozí 90) je zamýšlená doba uchování surových
logů. Doporučený postup:

- Surové JSON logy senzorů rotuj/maž po uplynutí retence (`logrotate` nebo
  cron), agregované/anonymizované metriky lze držet déle.
- Retenci slaď s právním posouzením — viz
  [legal-and-data-protection.md](legal-and-data-protection.md).

## Řešení potíží

| Příznak | Kde hledat |
|---------|-----------|
| Žádné nové události | Běží senzory? Vzniká `cowrie.json`/`http.json`? Běží timer? |
| Ingest selhává | `journalctl -u honeypot-ingest.service` |
| Nedostupné admin SSH | Ověř `admin_ssh_port`, `admin_allowed_cidrs`, fail2ban ban |
| Port 22 neodpovídá jako honeypot | Kontejner Cowrie běží? Koliduje reálné SSH stále na 22? |
