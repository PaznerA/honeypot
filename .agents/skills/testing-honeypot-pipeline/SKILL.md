---
name: testing-honeypot-pipeline
description: Test the honeypot sensor -> collector pipeline end-to-end (HTTP honeypot classification/dedup, Cowrie fixture mapping, CSV export). Use when verifying changes to sensors/, collector/, or parsers.
---

# Testing the honeypot pipeline

Defensive honeypot platform: sensors log JSON -> `honeypot_collector` normalizes,
classifies, dedups into SQLite. No VPS/Docker needed to test the data pipeline locally.

## Setup

```bash
cd <repo> && . .venv/bin/activate   # venv has honeypot_collector installed (editable)
# If venv missing: python3 -m pip install -e ".[dev]" ansible-lint yamllint
```

Blueprint already installs Ansible + lint/test tooling and `pip install -e ".[dev]"`.

## Lint / unit tests

```bash
ruff check .
pytest              # 17 unit tests
yamllint . && ansible-lint
```

## End-to-end pipeline test

1. Start the live HTTP honeypot (pick a FREE port; 8080 may be held by a stale run):
   ```bash
   HONEYPOT_PORT=8080 HONEYPOT_LOG=/tmp/demo/http.json python sensors/http-honeypot/app.py &
   ```
   Start it in a DEDICATED background exec shell (timeout:0) so it isn't killed mid-command.
2. Generate traffic. Via browser (recordable) or curl:
   - benign: `GET /`  -> classified `recon`
   - attacks: `?page=../../../../etc/passwd`, `/wp-login.php`, POST body `${jndi:ldap://...}` -> `exploit_attempt`
   - NOTE: a real browser auto-fetches `/favicon.ico` -> extra `recon` events (benign noise, expected). Account for these in exact counts.
3. The honeypot always returns the decoy `<h1>It works!</h1>` and NEVER executes input
   (path traversal must NOT return `/etc/passwd`). That is the key security assertion.
4. Ingest + verify classification:
   ```bash
   python -m honeypot_collector.cli --db /tmp/demo/hp.sqlite initdb
   python -m honeypot_collector.cli --db /tmp/demo/hp.sqlite ingest --sensor http --file /tmp/demo/http.json
   python -m honeypot_collector.cli --db /tmp/demo/hp.sqlite stats
   ```
   Assert exploit_attempt count == number of attack requests, recon == benign requests.
5. Idempotency: re-run `ingest ... --no-follow` -> must report `vloženo=0` (SHA-256 dedup_key).
6. Cowrie mapping (fixture, no live sensor): `ingest --sensor cowrie --file tests/fixtures/cowrie.sample.jsonl`
   then `top --by category` -> brute_force / credential_use / command_exec / malware_download / recon.
7. Export: `export --format csv` -> header + `raw` column with original JSON.

Classification logic lives in `collector/honeypot_collector/parsers/http_honeypot.py`
(`_EXPLOIT_MARKERS`) and `parsers/cowrie.py` (`_EVENT_MAP`). If counts are wrong, check these.

## Gotchas

- `pkill -f app.py` in the exec tool sometimes kills the exec shell itself (exit -1).
  Prefer killing the dedicated background shell (kill_shell) or `fuser -k <port>/tcp`.
- Port 8080 may stay bound by a previous run; check with a socket connect_ex before starting,
  or just use a different port via `HONEYPOT_PORT`.
- CLI output is Czech (`přečteno`/`události`/`vloženo`/`přeskočeno` = read/events/inserted/skipped).

## Devin Secrets Needed

None. Fully local; no credentials or external services required.
