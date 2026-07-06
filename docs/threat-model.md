# Threat model

## Účel a rozsah

Platforma je **defenzivní** nástroj pro sběr threat intelligence. Honeypot
je záměrně vystaven internetu, aby zachytil a zaznamenal chování útočníků:
automatizované skenování, brute-force, pokusy o zneužití a distribuci malwaru.
Data slouží k obraně infrastruktury (blokační seznamy IP, detekční pravidla,
analýza kampaní).

**Toto NENÍ útočný nástroj.** Neobsahuje a nesmí obsahovat funkce pro útoky,
exfiltraci cizích dat ani zpětné pronikání do systémů útočníků.

## Co honeypot zachytává

| Senzor | Zachytává |
|--------|-----------|
| Cowrie (SSH/Telnet) | Zdrojové IP, zkoušené kombinace jméno/heslo, spouštěné příkazy, stahované payloady, SSH klientské otisky |
| HTTP honeypot | Zdrojové IP, HTTP metody a cesty, hlavičky, těla, User-Agent, pokusy o zneužití |

## Hlavní rizika a jejich zmírnění

### R1: Kompromitace hostitele přes senzor

Senzor je bod kontaktu s útočníky.

- Používáme **low-interaction** senzory (Cowrie emuluje shell, HTTP honeypot
  nikdy nevykonává vstup).
- Kontejnery běží s `cap_drop: ALL`, `no-new-privileges`, read-only rootfs
  a omezeným logováním.
- Reálné administrátorské SSH je **přesunuto** z portu 22 a chráněno klíči +
  fail2ban; port 22 patří honeypotu.
- Provoz na **dedikované, izolované VPS** odděleně od produkce.

### R2: Zneužití VPS jako odrazového můstku

Útočník by mohl chtít VPS použít k dalším útokům (pivoting, DDoS).

- `nftables` default-drop na vstupu; výstup lze dále omezit dle potřeby.
- Cowrie neumožňuje skutečné síťové spojení ven z emulované relace.
- Monitoring odchozího provozu (viz [operations.md](operations.md)).

### R3: Distribuce malwaru zachyceného honeypotem

Stažené payloady jsou potenciálně škodlivé.

- Payloady se ukládají do izolovaného adresáře, **nikdy se nespouštějí**.
- S artefakty pracuj pouze v izolovaném/analytickém prostředí (sandbox).

### R4: Únik/citlivost sbíraných dat

Data obsahují IP adresy (osobní údaj dle GDPR) a mohou obsahovat přihlašovací
údaje omylem zadané legitimními uživateli.

- Přístup k databázi jen pro správce, VPS zpevněná.
- Retence dat (`raw_log_retention_days`) a právní rámec viz
  [legal-and-data-protection.md](legal-and-data-protection.md).

### R5: Detekce honeypotu / cílené obcházení

Pokročilý útočník honeypot rozpozná a vyhne se mu.

- Přijímané omezení low-interaction přístupu. Realističnost lze zvýšit
  konfigurací Cowrie (falešný filesystem, bannery) a dalšími senzory.

## Mimo rozsah

- Ochrana proti státem sponzorovaným cíleným útokům na samotnou platformu.
- High-interaction honeypoty s reálnými zranitelnými službami (vyšší riziko,
  vyžadují samostatný návrh a izolaci).
