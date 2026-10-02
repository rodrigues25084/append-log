# Append Log

An append-only log with crash-safe record framing. Each record is written as a
4-byte length, a 4-byte CRC-32C of the length field plus payload, and the
payload itself. On open, any trailing record that is truncated or fails its CRC
is discarded and the file is truncated to the last good record.

## Usage

```python
from append_log import AppendLog

with AppendLog("events.log") as log:
    log.append(b'{"event": "start"}')
    log.append(b'{"event": "stop"}')

with AppendLog("events.log") as log:
    for record in log.read_all():
        print(record.seq, record.payload)
```

## Why

The problem this solves is storing a sequence of opaque byte payloads in a way
that survives crashes during writes. A naive `[length][payload]` framing is
unsafe because a crash mid-write leaves a length field that points past the end
of the file, or a payload that is only partially on disk. The next reader then
either reads garbage or throws.

The trade-off: every record pays an 8-byte framing overhead and every append
pays an `fsync`. In return, reopening the log always yields a clean prefix of
fully-written records, and a torn trailing record is silently discarded rather
than raising.

## Edge cases

- **Corruption mid-log is fatal.** Recovery only discards trailing damage. If a
  byte is flipped in the middle of the file, `read_all()` raises
  `LogCorruptError` rather than silently skipping the record, because a
  mid-file corruption means something is wrong with the storage layer and
  guessing at the right recovery is dangerous.

- **No compaction.** The file only grows. If you need to reclaim space, copy the
  records you want to a new file and replace the old one.

- **Single file, single writer.** There is no locking. If two processes open
  the same path, appends will interleave and the log will corrupt.

## Performance

The window keeps a bounded buffer, so `push` is constant time and memory does not
grow with the length of the stream. `peak` and `trough` are linear in the window
size, which is the trade that keeps `push` cheap.

