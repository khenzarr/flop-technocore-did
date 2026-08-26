import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from worker import connect, escape_like, ingest, normalize_payload, normalize_rooms


class IndexerTests(unittest.TestCase):
    def test_normalizes_only_valid_rooms(self):
        self.assertEqual(normalize_rooms({"rooms": [{"name": "lobby"}, {"room": "d-build"}, {"name": "Bad Room"}, "x"]}), ["lobby", "d-build"])

    def test_rejects_invalid_payload(self):
        with self.assertRaises(ValueError):
            normalize_payload({"messages": "not-a-list"})

    def test_ingest_is_idempotent_and_records_inferred_gap(self):
        with tempfile.TemporaryDirectory() as directory:
            db = connect(Path(directory) / "index.sqlite3")
            payload = {"first_seq": 8, "last_seq": 9, "messages": [{"seq": 8, "ts": "2026-01-01T00:00:00Z", "from": "~a", "text": "hello"}, {"seq": 9, "ts": "2026-01-01T00:00:01Z", "from": "did:key:z6MkTest", "nonce": 9, "text": "world"}]}
            self.assertEqual(ingest(db, "lobby", payload, 5), 9)
            self.assertEqual(ingest(db, "lobby", payload, 9), 9)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM messages").fetchone()[0], 2)
            coverage = db.execute("SELECT gap_detected,gap_reason,last_observed_seq FROM coverage WHERE room='lobby'").fetchone()
            self.assertEqual(tuple(coverage), (1, "cursor_discontinuity", 9))
            db.close()

    def test_payload_rejects_coerced_oversized_and_invalid_sequence_values(self):
        messages, first, last, gap = normalize_payload({
            "first_seq": 1,
            "last_seq": 3,
            "messages": [
                {"seq": "1", "ts": "t", "from": "~a", "text": "coerced"},
                {"seq": -1, "ts": "t", "from": "~a", "text": "negative"},
                {"seq": 2, "ts": "t", "from": "~a", "text": "ok"},
                {"seq": 3, "ts": "t", "from": "~a", "text": "x" * 20_000},
            ],
        })
        self.assertEqual([message["seq"] for message in messages], [2])
        self.assertEqual((first, last, gap), (1, 3, False))

    def test_initial_and_internal_unknown_history_is_recorded(self):
        with tempfile.TemporaryDirectory() as directory:
            db = connect(Path(directory) / "index.sqlite3")
            payload = {
                "first_seq": 4,
                "last_seq": 7,
                "messages": [
                    {"seq": 4, "ts": "t", "from": "~a", "text": "first"},
                    {"seq": 7, "ts": "t", "from": "~a", "text": "later"},
                ],
            }
            self.assertEqual(ingest(db, "lobby", payload, 0), 7)
            coverage = db.execute("SELECT gap_detected,gap_reason FROM coverage WHERE room='lobby'").fetchone()
            self.assertEqual(tuple(coverage), (1, "history_before_initial_window_unknown"))
            db.close()

    def test_worker_state_schema_is_initialized(self):
        with tempfile.TemporaryDirectory() as directory:
            db = connect(Path(directory) / "index.sqlite3")
            state = db.execute("SELECT singleton,consecutive_failures FROM worker_state").fetchone()
            self.assertEqual(tuple(state), (1, 0))
            db.close()

    def test_like_escape(self):
        self.assertEqual(escape_like("a%b_c\\d"), "a\\%b\\_c\\\\d")


if __name__ == "__main__":
    unittest.main()
