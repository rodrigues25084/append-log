import os
import struct
import tempfile
import unittest

from append_log import AppendLog, Record, LogCorruptError
from append_log.core import _crc32c, _HEADER_SIZE


class AppendLogTests(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.mkdtemp()
        self.path = os.path.join(self._dir, "log.bin")

    def tearDown(self):
        # Clean up any open handles we forgot.
        import gc
        gc.collect()
        for f in os.listdir(self._dir):
            os.unlink(os.path.join(self._dir, f))
        os.rmdir(self._dir)

    def test_append_and_read_single_record(self):
        with AppendLog(self.path) as log:
            rec = log.append(b"hello")
            self.assertEqual(rec.seq, 0)
            self.assertEqual(rec.payload, b"hello")
            self.assertEqual(log.next_seq, 1)
        with AppendLog(self.path) as log:
            records = list(log.read_all())
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].seq, 0)
        self.assertEqual(records[0].payload, b"hello")

    def test_append_multiple_records_preserves_order(self):
        with AppendLog(self.path) as log:
            for i in range(5):
                log.append(f"rec-{i}".encode())
        with AppendLog(self.path) as log:
            records = list(log.read_all())
        self.assertEqual([r.seq for r in records], [0, 1, 2, 3, 4])
        self.assertEqual(
            [r.payload for r in records],
            [b"rec-0", b"rec-1", b"rec-2", b"rec-3", b"rec-4"],
        )

    def test_reopen_resumes_sequence(self):
        with AppendLog(self.path) as log:
            log.append(b"a")
            log.append(b"b")
        with AppendLog(self.path) as log:
            self.assertEqual(log.next_seq, 2)
            rec = log.append(b"c")
            self.assertEqual(rec.seq, 2)
        with AppendLog(self.path) as log:
            records = list(log.read_all())
        self.assertEqual([r.payload for r in records], [b"a", b"b", b"c"])

    def test_empty_payload_is_valid(self):
        with AppendLog(self.path) as log:
            log.append(b"")
        with AppendLog(self.path) as log:
            records = list(log.read_all())
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].payload, b"")
        self.assertEqual(records[0].seq, 0)

    def test_truncated_record_is_dropped_on_reopen(self):
        with AppendLog(self.path) as log:
            log.append(b"first")
            log.append(b"second")
        # Truncate the file mid-way through the second record.
        size = os.path.getsize(self.path)
        with open(self.path, "r+b") as f:
            f.truncate(size - 2)
        with AppendLog(self.path) as log:
            records = list(log.read_all())
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].payload, b"first")
        self.assertEqual(log.next_seq, 1)

    def test_corrupted_payload_crc_is_dropped_on_reopen(self):
        with AppendLog(self.path) as log:
            log.append(b"good")
            log.append(b"corrupt-me")
        # Flip a byte in the second record's payload.
        with open(self.path, "r+b") as f:
            data = f.read()
        # First record: header(8) + "good"(4) = 12 bytes.
        corrupt_at = _HEADER_SIZE + 4 + _HEADER_SIZE + 2
        data = data[:corrupt_at] + bytes([data[corrupt_at] ^ 0xFF]) + data[corrupt_at + 1:]
        with open(self.path, "wb") as f:
            f.write(data)
        with AppendLog(self.path) as log:
            records = list(log.read_all())
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].payload, b"good")

    def test_corrupted_length_field_is_dropped_on_reopen(self):
        with AppendLog(self.path) as log:
            log.append(b"first")
            log.append(b"second")
        # Corrupt the length field of the second record so it points beyond EOF.
        with open(self.path, "r+b") as f:
            data = f.read()
        second_rec_offset = _HEADER_SIZE + 5  # first record total
        # Overwrite the length with a huge value.
        bad_len = struct.pack("<I", 0xFFFFFFFF)
        data = (
            data[:second_rec_offset]
            + bad_len
            + data[second_rec_offset + 4:]
        )
        with open(self.path, "wb") as f:
            f.write(data)
        with AppendLog(self.path) as log:
            records = list(log.read_all())
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].payload, b"first")

    def test_read_all_raises_on_corruption_mid_log(self):
        with AppendLog(self.path) as log:
            log.append(b"first")
            log.append(b"second")
            log.append(b"third")
        # Corrupt the second record's payload, but leave the third intact.
        with open(self.path, "r+b") as f:
            data = f.read()
        second_payload_start = _HEADER_SIZE + 5 + _HEADER_SIZE
        data = (
            data[:second_payload_start]
            + bytes([data[second_payload_start] ^ 0x01])
            + data[second_payload_start + 1:]
        )
        with open(self.path, "wb") as f:
            f.write(data)
        with AppendLog(self.path) as log:
            with self.assertRaises(LogCorruptError):
                list(log.read_all())

    def test_append_after_recovery_continues_sequence(self):
        with AppendLog(self.path) as log:
            log.append(b"a")
            log.append(b"b")
        # Truncate to drop the second record.
        size = os.path.getsize(self.path)
        with open(self.path, "r+b") as f:
            f.truncate(size - 3)
        with AppendLog(self.path) as log:
            self.assertEqual(log.next_seq, 1)
            rec = log.append(b"c")
            self.assertEqual(rec.seq, 1)
        with AppendLog(self.path) as log:
            records = list(log.read_all())
        self.assertEqual([r.payload for r in records], [b"a", b"c"])

    def test_empty_log_is_valid(self):
        with AppendLog(self.path) as log:
            self.assertEqual(log.next_seq, 0)
            self.assertEqual(list(log.read_all()), [])

    def test_new_file_created_on_open(self):
        self.assertFalse(os.path.exists(self.path))
        with AppendLog(self.path) as log:
            self.assertTrue(os.path.exists(self.path))
            log.append(b"data")
        with AppendLog(self.path) as log:
            records = list(log.read_all())
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].payload, b"data")

    def test_large_payload_roundtrips(self):
        payload = bytes(range(256)) * 100  # 25600 bytes
        with AppendLog(self.path) as log:
            log.append(payload)
        with AppendLog(self.path) as log:
            records = list(log.read_all())
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].payload, payload)

    def test_record_is_frozen(self):
        with AppendLog(self.path) as log:
            rec = log.append(b"x")
        with self.assertRaises(Exception):
            rec.payload = b"y"  # type: ignore

    def test_append_rejects_non_bytes(self):
        with AppendLog(self.path) as log:
            with self.assertRaises(TypeError):
                log.append("not bytes")  # type: ignore

    def test_crc32c_known_vector(self):
        # CRC-32C of "123456789" is 0xE3069283.
        self.assertEqual(_crc32c(b"123456789"), 0xE3069283)


if __name__ == "__main__":
    unittest.main()
