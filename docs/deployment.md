# Nasazení na VPS

Krok za krokem od čisté VPS k běžícímu honeypotu.

## Předpoklady

- **VPS** s čistou instalací Ubuntu 22.04 (jammy) nebo 24.04 (noble),
  veřejná IP, **dedikovaná** pouze pro honeypot.
- **Řídicí stroj** (tvůj počítač) s nainstalovaným:
  - Ansible (`pip install ansible`) ≥ 2.15
  - SSH klíč, jehož veřejnou část přidáš jako `admin_authorized_keys`.
- Na VPS existuje neprivilegovaný účet s `sudo` (např. `deploy`) a tvým
  veřejným klíčem, dostupný přes SSH.

> ⚠️ **Pozor na uzamčení:** Role `hardening` přesune reálné SSH z portu 22
> (ten převezme Cowrie) na `admin_ssh_port` (výchozí 2222) a **zakáže
> přihlášení heslem**. Než playbook spustíš, ověř, že máš funkční přístup
> klíčem, a že firewall povolí nový port ze tvé sítě.

## 1. Příprava řídicího stroje

```bash
git clone <tento-repozitar> honeypot && cd honeypot
python -m venv .venv && source .venv/bin/activate
pip install ansible ansible-lint

cd ansible
ansible-galaxy collection install -r requirements.yml
```

## 2. Konfigurace inventáře a proměnných

```bash
cp inventory/hosts.example.ini inventory/hosts.ini
cp inventory/group_vars/all.example.yml inventory/group_vars/all.yml
```

Uprav `inventory/hosts.ini`:

```ini
[honeypots]
sensor-01 ansible_host=<VEŘEJNÁ_IP>

[honeypots:vars]
ansible_user=deploy
ansible_port=22        # PRVNÍ běh: reálné SSH je ještě na 22
```

Uprav `inventory/group_vars/all.yml` — minimálně:

```yaml
admin_ssh_port: 2222
admin_authorized_keys:
  - "ssh-ed25519 AAAA... ty@organizace"
admin_allowed_cidrs:
  - "<TVŮJ_ROZSAH>/32"   # ZUŽ z 0.0.0.0/0 na svou síť!
```

Citlivé hodnoty šifruj Vaultem:

```bash
ansible-vault encrypt inventory/group_vars/all.yml
```

## 3. První nasazení

```bash
# ověření spojení
ansible -i inventory/hosts.ini honeypots -m ping

# suchý běh (co by se změnilo)
ansible-playbook site.yml --check --diff

# ostré nasazení
ansible-playbook site.yml --ask-become-pass
```

## 4. Přepnutí na admin SSH port

Po prvním úspěšném běhu naslouchá reálné SSH na `admin_ssh_port`. Uprav
`inventory/hosts.ini`:

```ini
[honeypots:vars]
ansible_user=deploy
ansible_port=2222      # DALŠÍ běhy: admin SSH na novém portu
```

Ověř přístup: `ssh -p 2222 deploy@<IP>`.

## 5. Ověření

```bash
# na VPS
sudo docker compose -f /opt/honeypot/sensors/docker-compose.yml ps
sudo systemctl status honeypot-ingest.timer
sudo /opt/honeypot/collector-venv/bin/python -m honeypot_collector.cli \
    --db /opt/honeypot/data/collector/honeypot.sqlite stats
```

Do několika minut (dle `collector_interval`) se v databázi začnou objevovat
první události — internetové skenování je nepřetržité.

## Selektivní běh přes tagy

```bash
ansible-playbook site.yml --tags hardening        # jen hardening
ansible-playbook site.yml --tags sensors          # jen (re)deploy senzorů
ansible-playbook site.yml --tags collector        # jen collector
```

## Aktualizace

Změny v `sensors/` nebo `collector/` se na VPS promítnou opětovným během
příslušných tagů. Cowrie image aktualizuješ přes `cowrie_image_tag` a
`--tags sensors`.

## GeoIP (volitelné)

Pro geolokaci stáhni MaxMind GeoLite2 databáze (vyžaduje bezplatný účet),
nahraj `.mmdb` na VPS a nastav v `group_vars/all.yml`:

```yaml
geoip_city_db: /opt/honeypot/geoip/GeoLite2-City.mmdb
geoip_asn_db: /opt/honeypot/geoip/GeoLite2-ASN.mmdb
```

Role `collector` pak doinstaluje `geoip2` a ingest začne doplňovat zemi/ASN.
