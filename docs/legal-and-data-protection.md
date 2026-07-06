# Právní a datová ochrana

> ⚠️ **Upozornění:** Tento dokument je technické shrnutí, **nikoli právní
> poradenství**. Před produkčním nasazením konzultuj s právním oddělením
> a případně s dohledovým úřadem (v ČR ÚOOÚ).

## Sbíraná data a GDPR

Honeypot zaznamenává mimo jiné **zdrojové IP adresy**, které jsou dle GDPR
osobním údajem. Logy mohou navíc obsahovat přihlašovací údaje, User-Agent
a další identifikátory.

### Právní základ

Pro provoz honeypotu se typicky uplatní **oprávněný zájem** správce
(čl. 6 odst. 1 písm. f GDPR) — zajištění bezpečnosti sítí a informací.
Recitál 49 GDPR výslovně uznává zpracování pro účely síťové a informační
bezpečnosti jako oprávněný zájem. Je vhodné provést a zdokumentovat
**test proporcionality (balancing test)**.

### Zásady, které dodržet

- **Minimalizace** — sbírej jen data nutná pro bezpečnostní účel.
- **Omezení uložení** — nastav a dodržuj retenci (`raw_log_retention_days`);
  po jejím uplynutí data maž nebo anonymizuj.
- **Zabezpečení** — přístup jen pro správce, zpevněná VPS, šifrované zálohy
  mimo hostitele.
- **Účelové omezení** — data používej výhradně k obraně a threat intelligence.
- **Záznam o činnostech zpracování** (čl. 30) — veď dokumentaci zpracování.

### Data legitimních uživatelů

Honeypot nemá legitimní uživatele — jakýkoli přístup je nevyžádaný. Přesto se
mohou objevit údaje omylem zadané člověkem (např. heslo omylem zkopírované do
špatného terminálu). S nálezy nakládej jako s citlivými a neprodleně je maž,
pokud nejsou relevantní pro bezpečnostní účel.

## Entrapment / navádění

Honeypot je **pasivní** — pouze zaznamenává nevyžádané pokusy o přístup.
Nesmí útočníky aktivně navádět ani provokovat k jednání nad rámec toho, co by
sami podnikli. Platforma neobsahuje žádné útočné ani protiútočné funkce
(žádný „hack back").

## Sdílení dat

Sdílení indikátorů kompromitace (IoC) s partnery (např. národní CERT/CSIRT —
v ČR NÚKIB, GovCERT.CZ) je pro obranu žádoucí. Před sdílením:

- preferuj sdílení **agregovaných IoC** (IP, hashe, vzory), ne surových logů;
- ověř soulad se smluvními a právními závazky;
- používej standardní formáty (STIX/TAXII, MISP), pokud je to možné.

## Doporučený postup před nasazením

1. Proveď a zdokumentuj balancing test oprávněného zájmu.
2. Nastav retenci a proces mazání.
3. Zajisti zabezpečení přístupu a záloh.
4. Zaeviduj zpracování do záznamů o činnostech zpracování.
5. Konzultuj s DPO / právním oddělením.
