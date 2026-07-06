import pathlib

from honeypot_collector.cli import main
from honeypot_collector.ingest import ingest_file
from honeypot_collector.parsers import get_parser
from honeypot_collector.storage import Storage

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def test_ingest_file_cowrie(tmp_path):
    with Storage(tmp_path / "t.sqlite") as st:
        st.init_db()
        result = ingest_file(st, str(FIXTURES / "cowrie.sample.jsonl"), get_parser("cowrie"))
        assert result.read_lines == 5
        assert result.inserted == 5
        assert st.count() == 5


def test_ingest_file_offset_prevents_reread(tmp_path):
    src = tmp_path / "cowrie.json"
    src.write_text((FIXTURES / "cowrie.sample.jsonl").read_text(), encoding="utf-8")
    with Storage(tmp_path / "t.sqlite") as st:
        st.init_db()
        r1 = ingest_file(st, str(src), get_parser("cowrie"))
        assert r1.inserted == 5
        # bez nových řádků => nic nového
        r2 = ingest_file(st, str(src), get_parser("cowrie"))
        assert r2.read_lines == 0
        # dopsaný řádek se zpracuje
        with open(src, "a", encoding="utf-8") as fh:
            fh.write('{"eventid": "cowrie.session.connect", "src_ip": "1.2.3.4", '
                     '"session": "z9", "timestamp": "2026-07-06T10:05:00Z"}\n')
        r3 = ingest_file(st, str(src), get_parser("cowrie"))
        assert r3.read_lines == 1
        assert r3.inserted == 1
        assert st.count() == 6


def test_ingest_autodetect_mixed(tmp_path):
    src = tmp_path / "mixed.jsonl"
    lines = (FIXTURES / "cowrie.sample.jsonl").read_text()
    lines += (FIXTURES / "http.sample.jsonl").read_text()
    src.write_text(lines, encoding="utf-8")
    with Storage(tmp_path / "t.sqlite") as st:
        st.init_db()
        result = ingest_file(st, str(src), parser=None)  # autodetekce
        assert result.inserted == 8


def test_cli_end_to_end(tmp_path, capsys):
    db = str(tmp_path / "cli.sqlite")
    assert main(["--db", db, "initdb"]) == 0
    assert main(["--db", db, "ingest", "--sensor", "cowrie",
                 "--file", str(FIXTURES / "cowrie.sample.jsonl")]) == 0
    capsys.readouterr()
    assert main(["--db", db, "top", "--by", "src_ip", "--limit", "5"]) == 0
    out = capsys.readouterr().out
    assert "203.0.113.10" in out
    assert main(["--db", db, "stats", "--json"]) == 0
    assert '"total_events": 5' in capsys.readouterr().out


def test_cli_export_csv(tmp_path, capsys):
    db = str(tmp_path / "cli.sqlite")
    main(["--db", db, "initdb"])
    main(["--db", db, "ingest", "--sensor", "http",
          "--file", str(FIXTURES / "http.sample.jsonl")])
    capsys.readouterr()
    out_file = tmp_path / "out.csv"
    assert main(["--db", db, "export", "--format", "csv", "--out", str(out_file)]) == 0
    content = out_file.read_text(encoding="utf-8")
    assert "src_ip" in content.splitlines()[0]
    assert "198.51.100.7" in content
