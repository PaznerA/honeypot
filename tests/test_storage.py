from honeypot_collector.models import AttackEvent
from honeypot_collector.storage import Storage


def _event(**kw):
    base = {
        "event_time": "2026-07-06T10:00:00Z",
        "sensor": "cowrie",
        "protocol": "ssh",
        "event_type": "login.failed",
        "src_ip": "203.0.113.10",
        "username": "root",
        "password": "123456",
        "category": "brute_force",
    }
    base.update(kw)
    return AttackEvent(**base)


def test_insert_and_count(tmp_path):
    with Storage(tmp_path / "t.sqlite") as st:
        st.init_db()
        assert st.insert_event(_event()) is True
        assert st.count() == 1


def test_dedup_is_idempotent(tmp_path):
    with Storage(tmp_path / "t.sqlite") as st:
        st.init_db()
        ev = _event()
        assert st.insert_event(ev) is True
        assert st.insert_event(ev) is False  # stejný dedup_key
        assert st.count() == 1


def test_top_and_stats(tmp_path):
    with Storage(tmp_path / "t.sqlite") as st:
        st.init_db()
        st.insert_events([
            _event(password="a"),
            _event(password="b", src_ip="203.0.113.11"),
            _event(password="c", src_ip="203.0.113.11", event_type="command",
                   category="command_exec"),
        ])
        top_ip = dict(st.top("src_ip"))
        assert top_ip["203.0.113.11"] == 2
        stats = st.stats()
        assert stats["total_events"] == 3
        assert stats["distinct_src_ips"] == 2
        assert stats["by_category"]["brute_force"] == 2


def test_top_rejects_unknown_column(tmp_path):
    with Storage(tmp_path / "t.sqlite") as st:
        st.init_db()
        try:
            st.top("bogus; DROP TABLE attack_events")
        except ValueError:
            return
        raise AssertionError("očekávána ValueError pro neznámý sloupec")


def test_ingest_offset_roundtrip(tmp_path):
    with Storage(tmp_path / "t.sqlite") as st:
        st.init_db()
        assert st.get_ingest_offset("/var/log/x", 1) == 0
        st.set_ingest_offset("/var/log/x", 1, 4096)
        assert st.get_ingest_offset("/var/log/x", 1) == 4096
        # jiný inode (rotace) => offset se resetuje
        assert st.get_ingest_offset("/var/log/x", 2) == 0
