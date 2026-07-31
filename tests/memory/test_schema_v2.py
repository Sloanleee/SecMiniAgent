import sqlite3
import unittest

from secminiagent.memory.schema import create_v2_schema, validate_v2_structure


class SchemaV2Test(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.execute("PRAGMA foreign_keys=ON")
        create_v2_schema(self.db)
        self._session()
        self._thread()

    def tearDown(self):
        self.db.close()

    def test_schema_v2_creates_required_tables_and_indexes(self):
        validation = validate_v2_structure(self.db)
        self.assertTrue(validation.valid, validation)

    def test_schema_v2_rejects_invalid_scope_parent_columns(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self._memory("bad", scope="workspace", session_id="s", thread_id=None, run_id=None, thread_sequence=None, run_sequence=None)

    def test_schema_v2_allows_only_one_running_run_per_thread(self):
        self._run("r1", 1)
        with self.assertRaises(sqlite3.IntegrityError):
            self._run("r2", 2)

    def test_schema_v2_allocates_unique_sequences(self):
        self._run("r1", 1)
        self._memory("m1", run_id="r1", thread_sequence=1, run_sequence=1)
        with self.assertRaises(sqlite3.IntegrityError):
            self._memory("m2", run_id="r1", thread_sequence=1, run_sequence=2)

    def test_schema_v2_allows_only_one_active_summary(self):
        self._memory("sum1", memory_type="thread_summary", thread_sequence=1, run_id=None, run_sequence=None)
        with self.assertRaises(sqlite3.IntegrityError):
            self._memory("sum2", memory_type="thread_summary", thread_sequence=2, run_id=None, run_sequence=None)

    def test_schema_v2_enforces_composite_ancestry(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute(
                "INSERT INTO runs VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                ("w", "other", "t", "r", 1, "running", 1, 1, b"m", None, None, 0, "2026", None, None, None, None),
            )

    def _session(self):
        self.db.execute(
            "INSERT INTO sessions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("w", "s", 2, "active", 1, 1, b"m", 1, "AES-256-GCM", b"c", b"n", "2026", "2026", None),
        )

    def _thread(self):
        self.db.execute(
            "INSERT INTO threads VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("w", "s", "t", 2, "active", 1, 1, 1, 1, b"m", 1, "AES-256-GCM", b"c", b"n", "2026", "2026", None),
        )

    def _run(self, run_id, run_no):
        self.db.execute(
            "INSERT INTO runs VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("w", "s", "t", run_id, run_no, "running", 1, 1, b"m", None, None, 0, "2026", None, None, None, None),
        )

    def _memory(
        self, memory_id, *, scope="thread", session_id="s", thread_id="t", run_id=None,
        thread_sequence=1, run_sequence=None, memory_type="user_note",
    ):
        self.db.execute(
            """
            INSERT INTO memories (
              id,schema_version,workspace_id,session_id,thread_id,run_id,scope,memory_type,note_kind,
              classification,verification_status,lifecycle_status,source_type,policy_action,
              policy_reason_codes_json,record_revision,provenance_digest,importance_millis,key_version,
              algorithm,ciphertext,nonce,index_status,thread_sequence,run_sequence,state_version,state_mac,
              pinned,created_at,updated_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                memory_id,2,"w",session_id,thread_id,run_id,scope,memory_type,None,"internal","unknown","active",
                "test","allow",'["TEST"]',1,b"p",500,1,"AES-256-GCM",b"c",b"n","not_indexed",
                thread_sequence,run_sequence,1,b"m",0,"2026","2026",
            ),
        )


if __name__ == "__main__":
    unittest.main()
