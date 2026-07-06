# Architektura

## Přehled

Platforma se skládá ze tří vrstev, které jsou všechny součástí tohoto
repozitáře:

1. **Provisioning (Ansible)** — deklarativní, replikovatelné nastavení VPS.
2. **Senzory (Docker)** — služby vystavené útočníkům, které logují interakce.
3. **Collector (Python)** — zpracování logů senzorů do jednotné databáze.

Cílem je, aby libovolnou novou VPS šlo z čistého systému uvést do provozu
jediným během `ansible-playbook` a aby data byla napříč senzory jednotná
a analyzovatelná.

## Tok dat

```text
útočník ─▶ senzor (Cowrie / HTTP honeypot) ─▶ JSON log soubor
                                                   │
                       systemd timer (každých 5 min)│
                                                   ▼
                            run-ingest.sh ─▶ honeypot_collector
                                                   │  parse → normalize → enrich
                                                   ▼
                                          SQLite (attack_events)
                                                   │
                                                   ▼
                               CLI: stats / top / export (JSON, CSV)
```

Senzory **pouze zapisují** JSON řádky do bind-mount adresářů na hostiteli.
Collector běží na hostiteli (mimo kontejnery senzorů) a logy čte read-only
s inkrementálním sledováním offsetu — je tedy idempotentní a odolný vůči
opakovanému spuštění i rotaci logů.

## Komponenty

### Ansible (`ansible/`)

Playbook `site.yml` aplikuje role v tomto pořadí:

| Role | Odpovědnost |
|------|-------------|
| `common` | Časové pásmo, základní balíčky, automatické bezpečnostní aktualizace, chrony |
| `hardening` | Přesun reálného SSH na jiný port, zákaz hesel a root loginu, sysctl, fail2ban |
| `firewall` | nftables: default-drop input, admin SSH jen z povolených CIDR, honeypot porty otevřené |
| `docker` | Instalace Docker Engine + compose plugin z oficiálního repozitáře |
| `honeypot` | Nasazení stacku senzorů (`docker compose up`) |
| `collector` | Nasazení collectoru, systemd service + timer pro periodický ingest |

Globální proměnné jsou v `inventory/group_vars/all.yml` (šablona
`all.example.yml`). Citlivé hodnoty patří do Ansible Vault.

### Senzory (`sensors/`)

Spravováno přes `docker-compose.yml`:

- **Cowrie** (`cowrie/cowrie` image) — SSH/Telnet honeypot. Zaznamenává
  pokusy o přihlášení, spouštěné příkazy a stahované soubory do
  `cowrie.json`. Kontejner běží s `cap_drop: ALL`, `no-new-privileges`
  a read-only rootfs.
- **HTTP honeypot** (`sensors/http-honeypot/`, vlastní kód) — low-interaction
  HTTP server (pouze standardní knihovna). Loguje každý požadavek a vrací
  neškodnou návnadu. **Nikdy nevykonává** nic z požadavku.

### Collector (`collector/`)

Vlastní Python balíček `honeypot_collector`. Návrhová rozhodnutí:

- **SQLite** jako úložiště: nulová správa, WAL pro odolnost, snadné zálohování
  a přenos jednoho souboru. Pro flotilu senzorů lze jednotlivé DB agregovat
  (viz níže).
- **Jednotný model** `AttackEvent` napříč senzory umožňuje dotazovat se stejně
  na SSH i HTTP útoky.
- **Deduplikace** přes SHA-256 klíč z významných polí (`INSERT OR IGNORE`).
- **Sledování offsetu** ukládané v tabulce `ingest_state`, s detekcí rotace
  logu podle inode.
- **Runtime bez závislostí** (jen stdlib); GeoIP je volitelný extra.

## Škálování na více VPS

Model je „jeden senzor = jedna VPS = jedna SQLite DB". Pro centralizaci:

- **Pull agregace:** periodicky stahovat `honeypot.sqlite` z každé VPS na
  analytický uzel a slučovat (`export` do JSON/CSV nebo `ATTACH DATABASE`).
- **Push do SIEM:** exportovaný JSON posílat do Elasticsearch/OpenSearch nebo
  do centrálního data lake.

Normalizovaný formát událostí je pro obě varianty klíčový — analytická vrstva
nemusí znát specifika jednotlivých senzorů.

## Návrhové kompromisy

- **Low-interaction** senzory minimalizují riziko zneužití hostitele oproti
  high-interaction honeypotům, za cenu menší hloubky zachycených dat.
- **SQLite** je záměrně jednoduchý default; pro velké objemy nebo více
  senzorů je určena agregační vrstva, nikoli vertikální škálování SQLite.
