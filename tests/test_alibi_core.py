from __future__ import print_function

import base64
import json
import os
import shutil
import sqlite3
import unittest
from pathlib import Path
from unittest import mock

import alibi_core as core


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SANDBOX_ROOT = PROJECT_ROOT / ".sandbox-test"


class DigitalAlibiTests(unittest.TestCase):
    def setUp(self):
        self.old_cwd = Path.cwd()
        self.work = SANDBOX_ROOT / self.id().replace(".", "_")
        if self.work.exists():
            shutil.rmtree(str(self.work))
        self.work.mkdir(parents=True)
        os.chdir(str(self.work))

    def tearDown(self):
        os.chdir(str(self.old_cwd))
        if self.work.exists():
            shutil.rmtree(str(self.work))

    def test_bssid_normalization_and_deduplication(self):
        observed = core.extract_macs("BSSID 0a:0b:0c:0d:0e:0f\nBSSID 0A-0B-0C-0D-0E-0F\n")
        # Native Windows may present hyphen-delimited BSSIDs. Both native forms
        # normalize into a single canonical colon-delimited record.
        self.assertEqual(observed, ["0A:0B:0C:0D:0E:0F"])

    def test_canonical_compressed_hash_is_repeatable(self):
        payload = {"schema": core.SCHEMA, "numbers": [2, 1], "unicode": "é"}
        raw1, compressed1, digest1 = core.compressed_evidence(payload)
        raw2, compressed2, digest2 = core.compressed_evidence({"unicode": "é", "numbers": [2, 1], "schema": core.SCHEMA})
        self.assertEqual(raw1, raw2)
        self.assertEqual(compressed1, compressed2)
        self.assertEqual(digest1, digest2)
        self.assertEqual(digest1, core.sha256_hex(compressed1))

    def test_merkle_root_is_order_independent_and_odd_nodes_duplicate(self):
        leaves = [core.sha256_hex(b"one"), core.sha256_hex(b"two"), core.sha256_hex(b"three")]
        self.assertEqual(core.merkle_root(leaves), core.merkle_root(list(reversed(leaves))))
        self.assertEqual(len(core.merkle_root(leaves)), 64)
        with self.assertRaises(core.DigitalAlibiError):
            core.merkle_root([])

    def test_rfc3161_request_and_minimal_granted_response(self):
        digest = "ab" * 32
        request = core.build_timestamp_request(digest, nonce=7)
        tag, contents, end = core._read_der_element(request)
        self.assertEqual(tag, 0x30)
        self.assertEqual(end, len(request))
        self.assertIn(bytes.fromhex(digest), contents)
        status_info = core.der(0x30, core.der_integer(0))
        pretend_content_info = core.der(0x30, b"")
        response = core.der(0x30, status_info + pretend_content_info)
        self.assertEqual(core.timestamp_response_status(response), 0)

    def test_store_blocks_path_escape(self):
        store = core.EvidenceStore()
        with self.assertRaises(core.DigitalAlibiError):
            store.path("..", "outside")

    def test_offline_capture_writes_only_to_working_directory_and_verifies(self):
        with mock.patch.object(core, "scan_wifi", return_value=([], {"method": "test"})), mock.patch.object(
            core, "scan_ble", return_value=([], {"method": "test"})
        ), mock.patch.object(core, "capture_audio_digest", return_value=({"sha256": "cd" * 32, "seconds": 0}, {"method": "test"})):
            self.assertEqual(core.main(["capture", "--no-tsa", "--capture-id", "unit-capture", "--note", "test note"]), 0)
        self.assertEqual(core.main(["verify", "--capture-id", "unit-capture"]), 0)
        expected = {core.DB_NAME, core.KEY_NAME, core.PUBLIC_KEY_NAME}
        self.assertEqual({entry.name for entry in self.work.iterdir()}, expected)
        conn = sqlite3.connect(str(self.work / core.DB_NAME))
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM captures WHERE capture_id='unit-capture'").fetchone()
        batch = conn.execute("SELECT * FROM merkle_batches").fetchone()
        conn.close()
        self.assertEqual(row["tsa_status"], "LOCAL_SEALED")
        self.assertIsNotNone(batch)
        self.assertEqual(row["compressed_sha256"], row["tsa_message_imprint"])

    def test_local_merkle_signature_verifies_with_recorded_public_key(self):
        store = core.EvidenceStore()
        conn = store.connect()
        try:
            for capture_id, digest in (("one", core.sha256_hex(b"one")), ("two", core.sha256_hex(b"two"))):
                payload = {"schema": core.SCHEMA, "capture_id": capture_id}
                compressed = b"x"
                conn.execute(
                    """INSERT INTO captures(capture_id,captured_at_utc,payload_json,compressed_payload_b64,compressed_sha256,compressed_size,
                    source_summary_json,tsa_status,tsa_message_imprint,created_at_utc)
                    VALUES (?, '2026-01-01T00:00:00Z', ?, ?, ?, 1, '{}', 'PENDING', ?, '2026-01-01T00:00:00Z')""",
                    (capture_id, json.dumps(payload, sort_keys=True, separators=(",", ":")), base64.b64encode(compressed).decode("ascii"), digest, digest),
                )
            conn.commit()
            batch_id = core.locally_seal_pending(conn, core.LocalSigner(store))
            batch = conn.execute("SELECT * FROM merkle_batches WHERE batch_id=?", (batch_id,)).fetchone()
        finally:
            conn.close()

        from cryptography.hazmat.primitives import serialization
        from cryptography.exceptions import InvalidSignature

        public = serialization.load_der_public_key(base64.b64decode(batch["public_key_b64"]))
        envelope = {
            "purpose": "digital-alibi.merkle-root/v1",
            "batch_id": batch["batch_id"],
            "created_at_utc": batch["created_at_utc"],
            "leaf_count": batch["leaf_count"],
            "merkle_root": batch["merkle_root"],
        }
        try:
            public.verify(base64.b64decode(batch["signature_b64"]), core.canonical_json(envelope))
        except InvalidSignature:
            self.fail("recorded Merkle signature did not verify")
        leaves = json.loads(batch["leaf_hashes_json"])
        self.assertEqual(core.merkle_root(leaves), batch["merkle_root"])

    def test_recalculation_detects_payload_tampering(self):
        with mock.patch.object(core, "scan_wifi", return_value=([], {"method": "test"})), mock.patch.object(
            core, "scan_ble", return_value=([], {"method": "test"})
        ), mock.patch.object(core, "capture_audio_digest", return_value=(None, {"method": "test"})):
            self.assertEqual(core.main(["capture", "--no-tsa", "--capture-id", "tamper"]), 0)
        conn = sqlite3.connect(core.DB_NAME)
        conn.execute("UPDATE captures SET payload_json='{}' WHERE capture_id='tamper'")
        conn.commit()
        conn.close()
        self.assertEqual(core.main(["verify", "--capture-id", "tamper"]), 3)

    def test_failed_tsa_submission_is_locally_sealed(self):
        with mock.patch.object(core, "scan_wifi", return_value=([], {"method": "test"})), mock.patch.object(
            core, "scan_ble", return_value=([], {"method": "test"})
        ), mock.patch.object(core, "capture_audio_digest", return_value=(None, {"method": "test"})), mock.patch.object(
            core, "obtain_timestamp", side_effect=core.DigitalAlibiError("test TSA offline")
        ):
            self.assertEqual(core.main(["capture", "--capture-id", "deferred"]), 0)
        conn = sqlite3.connect(core.DB_NAME)
        row = conn.execute("SELECT tsa_status, tsa_error, merkle_batch_id FROM captures WHERE capture_id='deferred'").fetchone()
        conn.close()
        self.assertEqual(row[0], "LOCAL_SEALED")
        self.assertIn("test TSA offline", row[1])
        self.assertTrue(row[2])

    def test_invalid_watch_interval_is_rejected_without_creating_evidence(self):
        self.assertEqual(core.main(["watch", "--interval", "0"]), 2)
        self.assertEqual(list(self.work.iterdir()), [])

    def test_flush_url_override_takes_precedence_over_stored_endpoint(self):
        store = core.EvidenceStore()
        conn = store.connect()
        try:
            payload = core.build_payload("override", [], [], None, {"test": True})
            _, compressed, digest = core.compressed_evidence(payload)
            core.insert_capture(conn, payload, compressed, digest, "https://stored.example/tsr", {})
            with mock.patch.object(core, "obtain_timestamp", return_value=b"test-token") as timestamp:
                result = core.submit_pending_timestamps(conn, store, "https://override.example/tsr")
            self.assertEqual(result, {"submitted": 1, "sealed": 1, "failed": 0})
            timestamp.assert_called_once_with("https://override.example/tsr", digest)
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
