"""Low-interaction HTTP honeypot.

Zaznamenává KAŽDÝ příchozí HTTP požadavek jako JSON řádek (formát, který umí
číst ``honeypot_collector``) a vrací neškodnou návnadu. Server záměrně
NEVYKONÁVÁ nic z požadavku — jen loguje. Určeno k běhu v izolovaném kontejneru.

Konfigurace přes proměnné prostředí:
  HONEYPOT_BIND        adresa pro bind (výchozí 0.0.0.0)
  HONEYPOT_PORT        port (výchozí 8080)
  HONEYPOT_LOG         cesta k log souboru (výchozí /var/log/honeypot/http.json)
  HONEYPOT_SERVER_HDR  hodnota hlavičky Server (výchozí Apache/2.4.41 (Ubuntu))
  HONEYPOT_MAX_BODY    maximální počet bajtů těla k zalogování (výchozí 8192)
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BIND = os.environ.get("HONEYPOT_BIND", "0.0.0.0")  # noqa: S104 - honeypot musí naslouchat všude
PORT = int(os.environ.get("HONEYPOT_PORT", "8080"))
LOG_PATH = os.environ.get("HONEYPOT_LOG", "/var/log/honeypot/http.json")
SERVER_HDR = os.environ.get("HONEYPOT_SERVER_HDR", "Apache/2.4.41 (Ubuntu)")
MAX_BODY = int(os.environ.get("HONEYPOT_MAX_BODY", "8192"))

_DECOY_HTML = (
    "<!doctype html><html><head><title>Index of /</title></head>"
    "<body><h1>It works!</h1></body></html>"
)


def _utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class _Logger:
    def __init__(self, path: str):
        self.path = path
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        self._fh = open(path, "a", encoding="utf-8")  # noqa: SIM115 - drženo po dobu běhu

    def write(self, record: dict) -> None:
        self._fh.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
        self._fh.flush()


class HoneypotHandler(BaseHTTPRequestHandler):
    server_version = "Apache"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    logger: _Logger

    def _record(self) -> None:
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = b""
        if 0 < length <= MAX_BODY:
            body = self.rfile.read(length)
        elif length > MAX_BODY:
            body = self.rfile.read(MAX_BODY)

        client_ip, client_port = self.client_address[:2]
        record = {
            "sensor": "http-honeypot",
            "ts": _utcnow(),
            "src_ip": client_ip,
            "src_port": client_port,
            "dst_port": PORT,
            "method": self.command,
            "path": self.path,
            "http_version": self.request_version,
            "headers": dict(self.headers.items()),
            "user_agent": self.headers.get("User-Agent"),
            "body": body.decode("utf-8", errors="replace"),
        }
        self.logger.write(record)

    def _respond(self) -> None:
        payload = _DECOY_HTML.encode("utf-8")
        self.send_response(200)
        self.send_header("Server", SERVER_HDR)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def _handle(self) -> None:
        try:
            self._record()
        finally:
            self._respond()

    do_GET = _handle
    do_POST = _handle
    do_HEAD = _handle
    do_PUT = _handle
    do_DELETE = _handle
    do_PATCH = _handle
    do_OPTIONS = _handle

    def log_message(self, *args) -> None:  # noqa: D401 - potlačí stderr spam
        return


def main() -> int:
    HoneypotHandler.logger = _Logger(LOG_PATH)
    server = ThreadingHTTPServer((BIND, PORT), HoneypotHandler)
    print(f"[http-honeypot] naslouchám na {BIND}:{PORT}, loguji do {LOG_PATH}", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
