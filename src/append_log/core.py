from __future__ import annotations

import os
import struct
from dataclasses import dataclass
from typing import Iterator, List, Optional


_CRC_POLY = 0x82F63B78  # CRC-32C (Castagnoli) reflected polynomial
_CRC_TABLE: List[int] = []


def _build_crc_table() -> None:
    for i in range(256):
        crc = i
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ _CRC_POLY
            else:
                crc >>= 1
        _CRC_TABLE.append(crc)


_build_crc_table()


def _crc32c(data: bytes, crc: int = 0) -> int:
    """Compute CRC-32C (Castagnoli).

    We use CRC-32C rather than the zlib.crc32 polynomial because CRC-32C has
    better burst-error detection properties and is the standard checksum for
    network and storage framing. We implement it by hand because the standard
    library does not expose CRC-32C directly.
    """
    crc ^= 0xFFFFFFFF
    for b in data:
        crc = (crc >> 8) ^ _CRC_TABLE[(crc ^ b) & 0xFF]
    return crc ^ 0xFFFFFFFF


# Record framing: 4-byte length, 4-byte CRC32C of length+payload, payload.
_HEADER = struct.Struct("<II")
_HEADER_SIZE = _HEADER.size
_MAGIC = b"APLG"


class LogCorruptError(Exception):
    """Raised when the log contains a record that fails validation."""


@dataclass(frozen=True)
class Record:
    """A single log record: raw payload bytes plus its 0-based sequence number."""

    seq: int
    payload: bytes


class AppendLog:
    """An append-only log with crash-safe record framing.

    Each record is written as: [length:u32][crc32c(length+payload):u32][payload].
    The CRC covers the length field and the payload, so a torn write that
    produces a plausible-but-wrong length is still detected.

    On open, the log is scanned from the beginning. If a trailing record is
    truncated or fails its CRC, it is discarded and the file is truncated to the
    last good record. This makes the log safe under crash during append: you
    recover the prefix of records that were fully written and fsync'd.

    Interpretation chosen: the log is a single file. There is no rotation, no
    compaction, no random-access by offset. Records are addressed by a
    monotonically increasing 0-based sequence number.
    """

    def __init__(self, path: str) -> None:
        self._path = path
        self._seq = 0
        self._fp = open(path, "a+b")
        self._fp.close()
        self._fp = open(path, "r+b")
        self._recover()

    def _recover(self) -> None:
        """Scan existing file, drop any trailing corrupt record, truncate."""
        self._fp.seek(0, os.SEEK_END)
        size = self._fp.tell()
        good_end = 0
        offset = 0
        seq = 0
        self._fp.seek(0)
        while offset < size:
            self._fp.seek(offset)
            header = self._fp.read(_HEADER_SIZE)
            if len(header) < _HEADER_SIZE:
                break
            length, crc = _HEADER.unpack(header)
            payload = self._fp.read(length)
            if len(payload) < length:
                break
            if _crc32c(header[:4] + payload) != crc:
                # CRC failure: if a valid record follows, this is mid-log
                # corruption (leave for read_all to raise). Otherwise it is
                # trailing damage (truncate).
                next_off = offset + _HEADER_SIZE + length
                if next_off < size and self._valid_record_at(next_off, size):
                    good_end = size
                break
            good_end = offset + _HEADER_SIZE + length
            offset = good_end
            seq += 1
        if good_end < size:
            self._fp.truncate(good_end)
            self._fp.flush()
            os.fsync(self._fp.fileno())
        self._seq = seq
        self._fp.seek(0, os.SEEK_END)

    def _valid_record_at(self, offset: int, size: int) -> bool:
        self._fp.seek(offset)
        header = self._fp.read(_HEADER_SIZE)
        if len(header) < _HEADER_SIZE:
            return False
        length, crc = _HEADER.unpack(header)
        if offset + _HEADER_SIZE + length > size:
            return False
        payload = self._fp.read(length)
        return _crc32c(header[:4] + payload) == crc

    def append(self, payload: bytes) -> Record:
        """Append a record and return it. The write is fsync'd before returning."""
        if not isinstance(payload, (bytes, bytearray)):
            raise TypeError("payload must be bytes")
        payload = bytes(payload)
        length = len(payload)
        length_bytes = struct.pack("<I", length)
        crc = _crc32c(length_bytes + payload)
        frame = _HEADER.pack(length, crc) + payload
        self._fp.seek(0, os.SEEK_END)
        self._fp.write(frame)
        self._fp.flush()
        os.fsync(self._fp.fileno())
        rec = Record(seq=self._seq, payload=payload)
        self._seq += 1
        return rec

    def read_all(self) -> Iterator[Record]:
        """Yield all valid records in sequence order."""
        self._fp.seek(0)
        offset = 0
        seq = 0
        while True:
            header = self._fp.read(_HEADER_SIZE)
            if len(header) < _HEADER_SIZE:
                break
            length, crc = _HEADER.unpack(header)
            payload = self._fp.read(length)
            if len(payload) < length:
                raise LogCorruptError(
                    f"truncated payload at seq {seq}"
                )
            if _crc32c(header[:4] + payload) != crc:
                raise LogCorruptError(
                    f"crc mismatch at seq {seq}"
                )
            yield Record(seq=seq, payload=payload)
            seq += 1

    def close(self) -> None:
        if not self._fp.closed:
            self._fp.flush()
            self._fp.close()

    def __enter__(self) -> "AppendLog":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    @property
    def path(self) -> str:
        return self._path

    @property
    def next_seq(self) -> int:
        """The sequence number that will be assigned to the next appended record."""
        return self._seq
