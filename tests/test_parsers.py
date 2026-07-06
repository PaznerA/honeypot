import json

from honeypot_collector.models import (
    CATEGORY_BRUTE_FORCE,
    CATEGORY_EXPLOIT_ATTEMPT,
    CATEGORY_MALWARE_DOWNLOAD,
    CATEGORY_RECON,
)
from honeypot_collector.parsers import detect_parser, get_parser


def test_cowrie_login_failed_maps_to_brute_force():
    rec = {
        "eventid": "cowrie.login.failed",
        "src_ip": "203.0.113.10",
        "username": "root",
        "password": "123456",
        "session": "s1",
        "timestamp": "2026-07-06T10:00:01Z",
    }
    (event,) = get_parser("cowrie").parse(rec)
    assert event.category == CATEGORY_BRUTE_FORCE
    assert event.event_type == "login.failed"
    assert event.username == "root"
    assert event.password == "123456"
    assert event.protocol == "ssh"
    assert event.severity == 2


def test_cowrie_file_download_is_malware_high_severity():
    rec = {
        "eventid": "cowrie.session.file_download",
        "src_ip": "203.0.113.10",
        "url": "http://malware.example/x.sh",
        "timestamp": "2026-07-06T10:00:04Z",
    }
    (event,) = get_parser("cowrie").parse(rec)
    assert event.category == CATEGORY_MALWARE_DOWNLOAD
    assert event.severity == 4
    assert event.payload == "http://malware.example/x.sh"


def test_cowrie_ignores_non_cowrie_record():
    assert get_parser("cowrie").parse({"eventid": "suricata.alert"}) == []


def test_http_exploit_detection():
    rec = {
        "sensor": "http-honeypot",
        "ts": "2026-07-06T11:00:02Z",
        "src_ip": "198.51.100.7",
        "method": "GET",
        "path": "/index.php?page=../../../../etc/passwd",
        "body": "",
    }
    (event,) = get_parser("http").parse(rec)
    assert event.category == CATEGORY_EXPLOIT_ATTEMPT
    assert event.severity == 4
    assert event.payload.startswith("GET /index.php")


def test_http_benign_request_is_recon():
    rec = {"sensor": "http-honeypot", "method": "GET", "path": "/", "body": ""}
    (event,) = get_parser("http").parse(rec)
    assert event.category == CATEGORY_RECON
    assert event.severity == 1


def test_detect_parser_by_shape():
    cowrie_rec = {"eventid": "cowrie.session.connect"}
    http_rec = {"method": "GET", "path": "/"}
    assert detect_parser(cowrie_rec).name == "cowrie"
    assert detect_parser(http_rec).name == "http"
    assert detect_parser({"foo": "bar"}) is None


def test_raw_is_roundtrippable_json():
    rec = {"eventid": "cowrie.session.connect", "src_ip": "203.0.113.10", "session": "s1"}
    (event,) = get_parser("cowrie").parse(rec)
    assert json.loads(event.raw)["session"] == "s1"
