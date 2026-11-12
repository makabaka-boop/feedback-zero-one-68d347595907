#!/usr/bin/env python3
"""Independent acceptance harness for ecd.py (standard library only).

Fixtures are built with a deliberately different, bitwise GF(256) encoder, not
with ecd's own tables.  The CLI is exercised in a subprocess for every case so
that exit status, stderr reporting and output publication are checked too.

Run: python3 -I acceptance.py
"""

from __future__ import annotations

import hashlib
import itertools
import json
import os
import shutil
import subprocess
import sys
import tempfile
import zlib

ROOT = os.path.dirname(os.path.abspath(__file__))
ECD = os.path.join(ROOT, "ecd.py")

FAILURES: list[str] = []
CHECKS = 0


def check(cond: bool, label: str, detail: object = "") -> None:
    global CHECKS
    CHECKS += 1
    if not cond:
        FAILURES.append(f"{label}" + (f": {detail}" if detail else ""))


def eq(actual: object, expected: object, label: str) -> None:
    check(actual == expected, label, f"got {actual!r}, want {expected!r}")


# ---------------------------------------------------------------------------
# Independent field arithmetic (bit-by-bit, not table based).
# ---------------------------------------------------------------------------


def gmul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1D
        b >>= 1
    return p


def encode(raw: bytes) -> list[bytes]:
    w = (len(raw) + 3) // 4
    padded = raw + b"\x00" * (4 * w - len(raw))
    d = [padded[i * w:(i + 1) * w] for i in range(4)]
    out = [bytes(x) for x in d]
    p = bytes(a ^ b ^ c ^ e for a, b, c, e in zip(d[0], d[1], d[2], d[3]))
    q = bytes(gmul(1, a) ^ gmul(2, b) ^ gmul(4, c) ^ gmul(8, e)
              for a, b, c, e in zip(d[0], d[1], d[2], d[3]))
    return out + [p, q]


# ---------------------------------------------------------------------------
# Fixture writers.
# ---------------------------------------------------------------------------

TMP = tempfile.mkdtemp(prefix="ecd-acc-")
CASES = 0
_seq = itertools.count()


def write_manifest(dirpath, capture_id, blocks, extra_blocks=None) -> str:
    path = os.path.join(dirpath, f"manifest-{next(_seq)}.json")
    obj = {
        "version": 1,
        "capture_id": capture_id,
        "blocks": [
            {
                "block_no": i,
                "raw_length": len(b),
                "sha256": hashlib.sha256(b).hexdigest(),
            }
            for i, b in enumerate(blocks)
        ],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2)
        fh.write("\n")
    return path


def write_raw_manifest(dirpath, obj: dict, name: str | None = None) -> str:
    path = os.path.join(dirpath, name or f"manifest-{next(_seq)}.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh)
    return path


def row(capture_id, block_no, shard_index, content: bytes, **over) -> dict:
    rec = {
        "capture_id": capture_id,
        "block_no": block_no,
        "shard_index": shard_index,
        "data_hex": content.hex(),
        "crc32": zlib.crc32(content) & 0xFFFFFFFF,
    }
    rec.update(over)
    return rec


def write_capture(dirpath, rows: list[dict] | list[bytes]) -> str:
    path = os.path.join(dirpath, f"capture-{next(_seq)}.jsonl")
    with open(path, "wb") as fh:
        for r in rows:
            if isinstance(r, (bytes, bytearray)):
                fh.write(r + b"\n")
            else:
                fh.write(json.dumps(r).encode("utf-8") + b"\n")
    return path


def run(manifest, capture, out=None):
    global CASES
    CASES += 1
    if out is None:
        out = os.path.join(TMP, f"out-{next(_seq)}.json")
    proc = subprocess.run(
        [sys.executable, "-I", ECD, "recover", "--manifest", manifest,
         "--capture", capture, "--output", out],
        capture_output=True, text=True,
    )
    parsed = None
    if os.path.exists(out):
        try:
            with open(out, encoding="utf-8") as fh:
                parsed = json.load(fh)
        except (ValueError, OSError):
            parsed = None  # pre-existing non-JSON target, e.g. "DO NOT TOUCH"
    return proc.returncode, proc.stderr.strip(), parsed, out


def expect_ok(manifest, capture, label) -> dict:
    code, err, out, path = run(manifest, capture)
    check(code == 0, f"{label}: exit 0", err)
    check(out is not None, f"{label}: output published")
    check(not err, f"{label}: clean stderr", err)
    return out or {}


def expect_fail(manifest, capture, label, code_name: str | None = None) -> dict:
    code, err, out, path = run(manifest, capture)
    check(code != 0, f"{label}: nonzero exit", err)
    check(out is None, f"{label}: output not published")
    check(not os.path.exists(path), f"{label}: target absent")
    check(len(err.splitlines()) == 1, f"{label}: single stderr line", err)
    try:
        e = json.loads(err.splitlines()[-1])["error"]
    except (ValueError, KeyError, IndexError) as exc:
        check(False, f"{label}: stderr is JSON", f"{err!r} ({exc})")
        return {}
    if code_name:
        eq(e.get("code"), code_name, f"{label}: error code")
    return e


def all_capture_rows(cid, blocks, skip=()):
    return [
        row(cid, bi, si, shard)
        for bi, block in enumerate(blocks)
        for si, shard in enumerate(encode(block))
        if (bi, si) not in skip
    ]


# ---------------------------------------------------------------------------
# Business row helpers.
# ---------------------------------------------------------------------------


def biz(record_id, sensor_id="sensor-A", timestamp_ns=1, value_uv=None) -> dict:
    return {
        "record_id": record_id,
        "sensor_id": sensor_id,
        "timestamp_ns": timestamp_ns,
        "value_uv": value_uv,
    }


def bizline(obj) -> bytes:
    """Serialize one business row, terminated by LF."""
    return json.dumps(obj, ensure_ascii=False).encode("utf-8") + b"\n"


def expect_business_fail(label, content: bytes, code_name: str, **fields) -> None:
    cid = f"cap-biz-{next(_seq)}"
    manifest = write_manifest(TMP, cid, [content])
    cap = write_capture(TMP, all_capture_rows(cid, [content]))
    e = expect_fail(manifest, cap, label, code_name)
    for k, v in fields.items():
        eq(e.get(k), v, f"{label}: error {k}")


# ---------------------------------------------------------------------------
# Tests.
# ---------------------------------------------------------------------------


def test_all_double_erasures() -> None:
    blocks = [
        bizline(biz("r1", "温度", 1, None)) + bizline(biz("r2", "x", 2, -5)),
        bizline(biz("r3", "y", 3, 7)),
        bizline(biz("r4", "z" * 64, (1 << 63) - 1, -(1 << 63))),
    ]
    cid = "cap-erasure"
    manifest = write_manifest(TMP, cid, blocks)
    shards = [encode(b) for b in blocks]

    out = expect_ok(manifest, write_capture(TMP, all_capture_rows(cid, blocks)), "all shards")
    eq(out["capture_id"], cid, "capture_id echoed")
    eq([r["record_id"] for r in out["rows"]], ["r1", "r2", "r3", "r4"], "row order")
    eq(out["rows"][0]["sensor_id"], "温度", "unicode sensor")
    eq(out["rows"][0]["value_uv"], None, "null value")
    eq(out["rows"][1]["value_uv"], -5, "negative value")
    eq(out["rows"][3]["timestamp_ns"], (1 << 63) - 1, "timestamp max")
    eq(out["rows"][3]["value_uv"], -(1 << 63), "value min")
    eq(len(out["rows"][3]["sensor_id"]), 64, "64-code-point sensor")
    eq(
        out["blocks"],
        [
            {"block_no": bi, "available": [0, 1, 2, 3, 4, 5], "missing": [],
             "conflicts": [], "recovered": [], "bad_crc_lines": []}
            for bi in range(len(blocks))
        ],
        "audit with everything present",
    )

    for combo in itertools.combinations(range(6), 2):
        cap = write_capture(
            TMP,
            [
                row(cid, bi, si, shard)
                for bi, block in enumerate(blocks)
                for si, shard in enumerate(encode(block))
                if si not in combo
            ],
        )
        out = expect_ok(manifest, cap, f"double erasure {combo}")
        eq(out["blocks"][0]["missing"], list(combo), f"missing {combo}")
        eq(out["blocks"][0]["recovered"], list(combo), f"recovered {combo}")
        eq(out["blocks"][0]["available"], [i for i in range(6) if i not in combo],
           f"available {combo}")
        eq([r["record_id"] for r in out["rows"]], ["r1", "r2", "r3", "r4"], f"rows {combo}")

    # Every block can lose a different pair (matrix of block-specific erasures).
    cap = write_capture(
        TMP,
        [
            row(cid, bi, si, shard)
            for bi, block in enumerate(blocks)
            for si, shard in enumerate(encode(block))
            if si not in ({bi, (bi + 3) % 6})
        ],
    )
    out = expect_ok(manifest, cap, "per-block erasures")
    for bi in range(len(blocks)):
        eq(out["blocks"][bi]["recovered"], sorted({bi, (bi + 3) % 6}), f"per-block {bi}")

    # Three losses leave three shards: below the four-shard floor.
    cap = write_capture(
        TMP,
        [
            row(cid, bi, si, shard)
            for bi, block in enumerate(blocks)
            for si, shard in enumerate(encode(block))
            if si not in {0, 1, 2} or bi != 0
        ],
    )
    e = expect_fail(manifest, cap, "three losses on one block", "insufficient_shards")
    eq(e.get("block_no"), 0, "insufficient block_no")

    # Only metadata rows, no data at all.
    expect_fail(manifest, write_capture(TMP, []), "empty capture", "insufficient_shards")

    # One parity row whose CRC is wrong: it is only a bad line, not content.
    rows = [
        row(cid, bi, si, shard)
        for bi, block in enumerate(blocks)
        for si, shard in enumerate(encode(block))
        if si != 5 or bi != 1
    ]
    bad = row(cid, 1, 5, shards[1][5])
    bad["crc32"] = (bad["crc32"] ^ 0xFFFFFFFF) or 1
    rows.append(bad)
    out = expect_ok(manifest, write_capture(TMP, rows), "bad-CRC parity row")
    eq(out["blocks"][1]["missing"], [5], "bad CRC leaves missing")
    eq(out["blocks"][1]["bad_crc_lines"], [len(rows)], "bad CRC line number")
    eq(out["blocks"][0]["bad_crc_lines"], [], "other block clean")


def test_arbitration() -> None:
    raw = bizline(biz("r1", "s", 0, 1))
    cid = "cap-arb"
    manifest = write_manifest(TMP, cid, [raw])
    s = encode(raw)
    base = [row(cid, 0, i, x) for i, x in enumerate(s)]

    # Two distinct CRC-valid contents for an index: conflict, all discarded.
    alt0 = bytes([s[0][0] ^ 1]) + s[0][1:]
    rows = base + [row(cid, 0, 0, alt0)]
    out = expect_ok(manifest, write_capture(TMP, rows), "conflict on index 0")
    eq(out["blocks"][0]["conflicts"], [0], "conflict record")
    eq(out["blocks"][0]["available"], [1, 2, 3, 4, 5], "available excludes conflict")
    eq(out["blocks"][0]["missing"], [], "conflict is not missing")
    eq(out["blocks"][0]["recovered"], [0], "conflict shard recovered")
    eq(len(out["rows"]), 1, "row intact")

    # Conflicts on two indices leave four usable shards: still recoverable.
    alt4 = bytes([s[4][0] ^ 0x22]) + s[4][1:]
    rows = base + [row(cid, 0, 0, alt0), row(cid, 0, 4, alt4)]
    out = expect_ok(manifest, write_capture(TMP, rows), "two conflicts, four usable")
    eq(out["blocks"][0]["conflicts"], [0, 4], "both conflicts recorded")
    eq(out["blocks"][0]["available"], [1, 2, 3, 5], "four usable remain")

    # Three conflicts leave only three usable shards: reject.
    alt2 = bytes([s[2][0] ^ 0x44]) + s[2][1:]
    rows = base + [row(cid, 0, 0, alt0), row(cid, 0, 4, alt4), row(cid, 0, 2, alt2)]
    expect_fail(manifest, write_capture(TMP, rows), "three conflicts", "insufficient_shards")

    # Duplicates of identical content never add weight: one value is one shard.
    rows = [row(cid, 0, 0, s[0]), row(cid, 0, 0, s[0]), row(cid, 0, 1, s[1]),
            row(cid, 0, 2, s[2]), row(cid, 0, 4, s[4]), row(cid, 0, 4, s[4])]
    out = expect_ok(manifest, write_capture(TMP, rows), "duplicates do not add weight")
    eq(out["blocks"][0]["available"], [0, 1, 2, 4], "available after duplicates")

    # Bad CRC does not create a conflict with the good copy.
    badcrc_alt = row(cid, 0, 0, alt0)
    badcrc_alt["crc32"] = (badcrc_alt["crc32"] + 1) & 0xFFFFFFFF
    rows = base + [badcrc_alt]
    out = expect_ok(manifest, write_capture(TMP, rows), "bad CRC is not a conflict")
    eq(out["blocks"][0]["conflicts"], [], "no conflict from bad CRC")
    eq(out["blocks"][0]["available"], [0, 1, 2, 3, 4, 5], "all available")
    eq(out["blocks"][0]["bad_crc_lines"], [7], "bad CRC line recorded")

    # Redundancy contradiction: valid CRC but wrong D1 among D0,D2,D3,P.
    wrong1 = bytes([s[1][0] ^ 0xFF]) + s[1][1:]
    rows = [row(cid, 0, 0, s[0]), row(cid, 0, 1, wrong1), row(cid, 0, 2, s[2]),
            row(cid, 0, 3, s[3]), row(cid, 0, 4, s[4])]
    expect_fail(manifest, write_capture(TMP, rows), "contradiction", "redundancy_contradiction")

    # Contradiction lives only in Q: all six present but Q wrong.
    rows = base[:5] + [row(cid, 0, 5, bytes([s[5][0] ^ 0x80]) + s[5][1:])]
    expect_fail(manifest, write_capture(TMP, rows), "Q-only contradiction",
                "redundancy_contradiction")

    # Contradiction that only shows when both parities are checked: P consistent
    # with D0..D3 but Q not (construct a data shard changed along with P).
    d = [s[0], s[1], s[2], s[3]]
    d2 = [bytes([d[0][0] ^ 0x01]) + d[0][1:], d[1], d[2], d[3]]
    p2 = bytes(a ^ b ^ c ^ e for a, b, c, e in zip(*d2))
    rows = [row(cid, 0, 0, d2[0]), row(cid, 0, 1, d2[1]), row(cid, 0, 2, d2[2]),
            row(cid, 0, 3, d2[3]), row(cid, 0, 4, p2), row(cid, 0, 5, s[5])]
    expect_fail(manifest, write_capture(TMP, rows), "Q catches contradiction",
                "redundancy_contradiction")

    # Manifest hash disagreement with an internally consistent codeword.
    wrong_manifest = write_raw_manifest(
        TMP, {"version": 1, "capture_id": cid,
              "blocks": [{"block_no": 0, "raw_length": len(raw), "sha256": "0" * 64}]},
    )
    expect_fail(wrong_manifest, write_capture(TMP, base), "hash mismatch", "hash_mismatch")

    # Padding tests need a block whose length is not a multiple of four.
    pad_raw = bizline(biz("pad", "s" * 5, 3, -2))  # 78 bytes: w=20, pad=2
    eq(len(pad_raw) % 4, 2, "padding fixture is ragged")
    # Non-zero padding: encode 4w bytes (w unchanged) but declare raw_length n
    # and hash the n-byte prefix.  The codeword is self-consistent, yet the
    # padding bytes are non-zero, so recovery must refuse.
    n = len(pad_raw)
    w = (n + 3) // 4
    n2 = 4 * w
    raw3 = pad_raw + b"\x11" * (n2 - n)
    m3 = write_raw_manifest(
        TMP, {"version": 1, "capture_id": "cap-pad",
              "blocks": [{"block_no": 0, "raw_length": n,
                          "sha256": hashlib.sha256(pad_raw).hexdigest()}]},
    )
    expect_fail(m3, write_capture(TMP, [row("cap-pad", 0, i, x) for i, x in enumerate(encode(raw3))]),
                "non-zero padding", "padding_nonzero")

    # Same construction with zeroed padding is accepted.
    raw2 = pad_raw + b"\x00" * (n2 - n)
    m4 = write_raw_manifest(
        TMP, {"version": 1, "capture_id": "cap-padz",
              "blocks": [{"block_no": 0, "raw_length": n,
                          "sha256": hashlib.sha256(pad_raw).hexdigest()}]},
    )
    out = expect_ok(m4, write_capture(TMP, [row("cap-padz", 0, i, x) for i, x in enumerate(encode(raw2))]),
                    "zero padding accepted")
    eq(out["blocks"][0]["recovered"], [], "zero padding audit")


def test_capture_validation() -> None:
    raw = bizline(biz("r1"))
    cid = "cap-val"
    manifest = write_manifest(TMP, cid, [raw])
    s = encode(raw)
    base = [row(cid, 0, i, x) for i, x in enumerate(s)]
    w = (len(raw) + 3) // 4

    bad_file = os.path.join(TMP, f"cap-raw-{next(_seq)}.jsonl")

    def raw_capture(lines: list[bytes]) -> str:
        with open(bad_file, "wb") as fh:
            for line in lines:
                fh.write(line)
        return bad_file

    def jline(obj, **over):
        o = dict(obj)
        o.update(over)
        return json.dumps(o).encode("utf-8") + b"\n"

    e = expect_fail(manifest, raw_capture([b"\n"] + [b""]), "empty capture line", "capture_empty_line")
    eq(e.get("capture_line_no"), 1, "empty line number")

    e = expect_fail(manifest, raw_capture([b"\xff\xfe\n"]), "bad UTF-8", "capture_encoding")
    eq(e.get("capture_line_no"), 1, "encoding line number")

    e = expect_fail(manifest, raw_capture([b"not json\n"]), "bad JSON", "capture_json")
    eq(e.get("capture_line_no"), 1, "json line number")

    e = expect_fail(manifest, raw_capture([jline(base[0], crc32=float(base[0]["crc32"]))]),
                    "float crc", "capture_crc32")
    e = expect_fail(manifest, raw_capture([jline(base[0], crc32=True)]), "bool crc", "capture_crc32")
    e = expect_fail(manifest, raw_capture([jline(base[0], crc32=-1)]), "negative crc", "capture_crc32")
    e = expect_fail(manifest, raw_capture([jline(base[0], crc32=1 << 32)]), "crc too big", "capture_crc32")
    e = expect_fail(manifest, raw_capture([jline(base[0], block_no=True)]), "bool block_no", "capture_block_no")
    e = expect_fail(manifest, raw_capture([jline(base[0], block_no=1)]), "unknown block", "capture_block_no")
    e = expect_fail(manifest, raw_capture([jline(base[0], shard_index=6)]), "shard index 6", "capture_shard_index")
    e = expect_fail(manifest, raw_capture([jline(base[0], shard_index=-1)]), "shard index -1", "capture_shard_index")
    e = expect_fail(manifest, raw_capture([jline(base[0], shard_index=True)]), "bool shard index", "capture_shard_index")
    e = expect_fail(manifest, raw_capture([jline(base[0], capture_id="other")]), "wrong source", "capture_source")
    e = expect_fail(manifest, raw_capture([jline(base[0], capture_id=1)]), "non-string source", "capture_capture_id")
    e = expect_fail(manifest, raw_capture([jline(base[0], data_hex=base[0]["data_hex"][:-2])]),
                    "short hex", "capture_data_hex")
    e = expect_fail(manifest, raw_capture([jline(base[0], data_hex=base[0]["data_hex"] + "00")]),
                    "long hex", "capture_data_hex")
    e = expect_fail(manifest, raw_capture([jline(base[0], data_hex="zz" + base[0]["data_hex"][2:])]),
                    "non-hex", "capture_data_hex")
    e = expect_fail(manifest, raw_capture([jline(base[0], data_hex=base[0]["data_hex"].upper())]),
                    "uppercase hex", "capture_data_hex")
    e = expect_fail(manifest, raw_capture([jline(base[0], data_hex=base[0]["data_hex"], crc32=0)
                                           if False else json.dumps({**base[0], "data_hex": "00"}).encode() + b"\n"]),
                    "odd hex width", "capture_data_hex")

    # Duplicate keys, missing fields, non-object rows.
    dup = b'{"capture_id":"%s","capture_id":"%s","block_no":0,"shard_index":0,"data_hex":"%s","crc32":%d}\n' % (
        cid.encode(), cid.encode(), base[0]["data_hex"].encode(), base[0]["crc32"])
    expect_fail(manifest, raw_capture([dup]), "duplicate capture key", "capture_duplicate_field")
    e = expect_fail(manifest, raw_capture([jline({k: v for k, v in base[0].items() if k != "crc32"})]),
                    "missing capture field", "capture_fields")
    e = expect_fail(manifest, raw_capture([b"[]\n"]), "capture row not object", "capture_shape")

    # A bad row anywhere before enough shards fails the whole run.
    e = expect_fail(manifest, raw_capture([jline(base[0]), b"{}\n", jline(base[1])]),
                    "bad row mid-file", "capture_fields")
    eq(e.get("capture_line_no"), 2, "mid-file line number")

    # Enough shards survive a bad line elsewhere.
    rows = base[:4]
    e = expect_fail(manifest, raw_capture([jline(r) for r in rows] + [b"{}\n"]),
                    "bad trailing row", "capture_fields")
    eq(e.get("capture_line_no"), 5, "trailing line number")

    # Unknown extra capture field is tolerated (only documented fields needed).
    out = expect_ok(manifest, raw_capture([jline(r, note="x") for r in base]), "extra capture field")
    eq(len(out["rows"]), 1, "extra field accepted")


def test_business_validation() -> None:
    expect_business_fail("value string", bizline(biz("r", value_uv="1")), "business_value_uv")
    expect_business_fail("value bool", bizline(biz("r", value_uv=True)), "business_value_uv")
    expect_business_fail("value bool false", bizline(biz("r", value_uv=False)), "business_value_uv")
    expect_business_fail("value float", bizline(biz("r", value_uv=1.5)), "business_value_uv")
    expect_business_fail("value overflow", bizline(biz("r", value_uv=1 << 63)), "business_value_uv")
    expect_business_fail("value underflow", bizline(biz("r", value_uv=-(1 << 63) - 1)), "business_value_uv")
    expect_business_fail("ts bool", bizline(biz("r", timestamp_ns=True)), "business_timestamp_ns")
    expect_business_fail("ts negative", bizline(biz("r", timestamp_ns=-1)), "business_timestamp_ns")
    expect_business_fail("ts overflow", bizline(biz("r", timestamp_ns=1 << 63)), "business_timestamp_ns")
    expect_business_fail("ts float", bizline(biz("r", timestamp_ns=1.0)), "business_timestamp_ns")
    expect_business_fail("ts string", bizline(biz("r", timestamp_ns="0")), "business_timestamp_ns")
    expect_business_fail("record id punctuation", bizline(biz("b@d")), "business_record_id")
    expect_business_fail("record id empty", bizline(biz("")), "business_record_id")
    expect_business_fail("record id long", bizline(biz("a" * 65)), "business_record_id")
    expect_business_fail("record id unicode", bizline(biz("ré")), "business_record_id")
    expect_business_fail("record id space", bizline(biz("a b")), "business_record_id")
    expect_business_fail("record id non-string", bizline(biz(7)), "business_record_id")
    expect_business_fail("sensor empty", bizline(biz("r", sensor_id="")), "business_sensor_id")
    expect_business_fail("sensor nul", bizline(biz("r", sensor_id="a\x00b")), "business_sensor_id")
    expect_business_fail("sensor long", bizline(biz("r", sensor_id="s" * 65)), "business_sensor_id")
    expect_business_fail("sensor non-string", bizline(biz("r", sensor_id=5)), "business_sensor_id")
    expect_business_fail("unknown field", bizline({**biz("r"), "extra": 1}), "business_fields")
    expect_business_fail("missing field", bizline({"record_id": "r", "sensor_id": "s", "timestamp_ns": 0}),
                         "business_fields")
    expect_business_fail("row array", b"[1,2]\n", "business_shape")
    expect_business_fail("row string", b'"x"\n', "business_shape")
    expect_business_fail("duplicate record id", bizline(biz("r")) + bizline(biz("r", timestamp_ns=2)),
                         "business_duplicate_record_id")
    expect_business_fail("empty interior line", bizline(biz("r")) + b"\n" + bizline(biz("r2")),
                         "business_empty_line")
    expect_business_fail("empty trailing line", bizline(biz("r")) + b"\n", "business_empty_line")
    expect_business_fail("invalid utf8", bizline(biz("r")) + b"\x80\n", "business_encoding")
    expect_business_fail("overlong utf8", bizline(biz("r")) + b"\xc0\x80\n", "business_encoding")
    expect_business_fail("duplicate key",
                         b'{"record_id":"r","record_id":"r2","sensor_id":"s",'
                         b'"timestamp_ns":0,"value_uv":null}\n', "business_duplicate_field")
    expect_business_fail("NaN", b'{"record_id":"r","sensor_id":"s","timestamp_ns":NaN,"value_uv":null}\n',
                         "business_json")

    # Boundary-valid rows.
    edge = (bizline(biz("a-_Z9", "s" * 64, 0, 0)) +
            bizline(biz("b" * 64, "\U0001f600", (1 << 63) - 1, -(1 << 63))))
    cid = "cap-edge"
    manifest = write_manifest(TMP, cid, [edge])
    out = expect_ok(manifest, write_capture(TMP, all_capture_rows(cid, [edge])), "boundary values")
    eq(out["rows"][0]["record_id"], "a-_Z9", "identifier charset")
    eq(out["rows"][1]["sensor_id"], "\U0001f600", "astral sensor")
    eq(out["rows"][1]["timestamp_ns"], (1 << 63) - 1, "ts boundary")
    eq(out["rows"][1]["value_uv"], -(1 << 63), "value boundary")
    # Integer-valued floats are rejected even when numerically equal.
    expect_business_fail("ts 0.0", bizline({**biz("r"), "timestamp_ns": 0.0}), "business_timestamp_ns")
    expect_business_fail("value 0.0", bizline({**biz("r"), "value_uv": 0.0}), "business_value_uv")

    # Unpaired surrogate escapes are not valid text.
    expect_business_fail("surrogate sensor",
                         b'{"record_id":"r","sensor_id":"\\ud800","timestamp_ns":0,"value_uv":null}\n',
                         "business_sensor_id")
    expect_business_fail("surrogate record id",
                         b'{"record_id":"r\\ud800","sensor_id":"s","timestamp_ns":0,"value_uv":null}\n',
                         "business_record_id")


def test_stream_layout() -> None:
    line1 = bizline(biz("alpha", "\U0001f321", (1 << 63) - 1, -(1 << 63)))
    line2 = bizline(biz("beta", "X" * 64, 0, 0))
    full = line1 + line2

    # Cut block boundaries in the middle of the emoji's 4-byte sequence and
    # in the middle of a JSON token.
    cut1 = line1.index(b"\xf0") + 2
    cut2 = len(line1) + 10
    blocks = [full[:cut1], full[cut1:cut2], full[cut2:]]
    cid = "cap-split"
    manifest = write_manifest(TMP, cid, blocks)
    out = expect_ok(manifest, write_capture(TMP, all_capture_rows(cid, blocks)),
                    "cross-block characters and lines")
    eq([r["record_id"] for r in out["rows"]], ["alpha", "beta"], "both rows")
    eq(out["rows"][0]["sensor_id"], "\U0001f321", "split emoji restored")
    eq(out["rows"][0]["byte_start"], 0, "row1 start")
    eq(out["rows"][0]["byte_end"], len(line1) - 1, "row1 end excludes LF")
    eq(out["rows"][1]["byte_start"], len(line1), "row2 start")
    eq(out["rows"][1]["byte_end"], len(full) - 1, "row2 end excludes LF")
    eq(out["rows"][0]["line_no"], 1, "row1 number")
    eq(out["rows"][1]["line_no"], 2, "row2 number")

    # Missing final LF, located in the last block.
    body = full[:-1]
    cid = "cap-nolf"
    manifest = write_manifest(TMP, cid, [body[:20], body[20:]])
    e = expect_fail(manifest, write_capture(TMP, all_capture_rows(cid, [body[:20], body[20:]])),
                    "missing final LF", "stream_missing_final_lf")
    eq(e.get("business_line_no"), 2, "no-LF line number")
    eq(e.get("byte_start"), len(line1), "no-LF byte start")

    # Bad business row in a later block: byte_start is absolute in the stream.
    cid = "cap-late"
    manifest = write_manifest(TMP, cid, [line1, b"nope\n"])
    e = expect_fail(manifest, write_capture(TMP, all_capture_rows(cid, [line1, b"nope\n"])),
                    "late bad row", "business_json")
    eq(e.get("business_line_no"), 2, "late line number")
    eq(e.get("byte_start"), len(line1), "late byte start")

    # Empty stream via a zero-block manifest.
    manifest = write_manifest(TMP, "cap-zero", [])
    out = expect_ok(manifest, write_capture(TMP, []), "zero blocks")
    eq(out, {"capture_id": "cap-zero", "rows": [], "blocks": []}, "zero-block output")

    # A single block that is one LF produces one empty business line.
    cid = "cap-lf"
    manifest = write_manifest(TMP, cid, [b"\n"])
    e = expect_fail(manifest, write_capture(TMP, all_capture_rows(cid, [b"\n"])),
                    "lone LF stream", "business_empty_line")
    eq(e.get("byte_start"), 0, "lone LF start")


def test_publication() -> None:
    raw = bizline(biz("r1"))
    cid = "cap-pub"
    manifest = write_manifest(TMP, cid, [raw])
    cap = write_capture(TMP, all_capture_rows(cid, [raw]))

    target = os.path.join(TMP, "existing.json")
    with open(target, "w") as fh:
        fh.write("DO NOT TOUCH")
    code, err, out, path = run(manifest, cap, target)
    check(code != 0, "existing target rejected", err)
    with open(target) as fh:
        eq(fh.read(), "DO NOT TOUCH", "existing target untouched")
    eq(json.loads(err.splitlines()[-1])["error"]["code"], "output_exists", "output_exists")

    # A directory at the target also counts as existing.
    d = os.path.join(TMP, "dir-target")
    os.makedirs(d)
    code, err, out, path = run(manifest, cap, d)
    check(code != 0, "directory target rejected", err)

    # Failed recovery leaves no output and no temp files.
    before = set(os.listdir(TMP))
    dup_raw = bizline(biz("r1")) + bizline(biz("r1"))
    cid2 = "cap-pub2"
    manifest2 = write_manifest(TMP, cid2, [dup_raw, raw])
    cap2 = write_capture(TMP, all_capture_rows(cid2, [dup_raw, raw]))
    expect_fail(manifest2, cap2, "failed run publishes nothing", "business_duplicate_record_id")
    leftovers = [n for n in os.listdir(TMP) if n.startswith(".ecd-tmp-")]
    eq(leftovers, [], "no temp leftovers")

    # Success then rerun with the same target is refused.
    out1 = os.path.join(TMP, "publish-once.json")
    code, err, _, _ = run(manifest, cap, out1)
    eq(code, 0, f"first publish ({err})")
    code, err, _, _ = run(manifest, cap, out1)
    check(code != 0, "second publish refused", err)

    # Manifest validation.
    cases = [
        ("version 0", {"version": 0, "capture_id": "c", "blocks": []}, "manifest_version"),
        ("version 1.0", {"version": 1.0, "capture_id": "c", "blocks": []}, "manifest_version"),
        ("version true", {"version": True, "capture_id": "c", "blocks": []}, "manifest_version"),
        ("version string", {"version": "1", "capture_id": "c", "blocks": []}, "manifest_version"),
        ("no blocks", {"version": 1, "capture_id": "c"}, "manifest_blocks"),
        ("blocks null", {"version": 1, "capture_id": "c", "blocks": None}, "manifest_blocks"),
        ("block gap", {"version": 1, "capture_id": "c",
                       "blocks": [{"block_no": 1, "raw_length": 1, "sha256": "0" * 64}]},
         "manifest_block_no"),
        ("block bool", {"version": 1, "capture_id": "c",
                        "blocks": [{"block_no": True, "raw_length": 1, "sha256": "0" * 64}]},
         "manifest_block_no"),
        ("raw len 0", {"version": 1, "capture_id": "c",
                       "blocks": [{"block_no": 0, "raw_length": 0, "sha256": "0" * 64}]},
         "manifest_raw_length"),
        ("raw len max+1", {"version": 1, "capture_id": "c",
                           "blocks": [{"block_no": 0, "raw_length": 262145, "sha256": "0" * 64}]},
         "manifest_raw_length"),
        ("bad sha", {"version": 1, "capture_id": "c",
                     "blocks": [{"block_no": 0, "raw_length": 1, "sha256": "zz" * 32}]},
         "manifest_sha256"),
        ("empty capture id", {"version": 1, "capture_id": "", "blocks": []},
         "manifest_capture_id"),
        ("non-string capture id", {"version": 1, "capture_id": 5, "blocks": []},
         "manifest_capture_id"),
        ("top-level array", [], "manifest_shape"),
    ]
    for name, obj, code_name in cases:
        expect_fail(write_raw_manifest(TMP, obj), cap, f"manifest {name}", code_name)

    # max raw_length is accepted (262144 bytes): many valid rows padded with
    # insignificant JSON whitespace to hit the exact ceiling.
    pieces = []
    total = 0
    i = 0
    while total < 262144:
        r = bizline(biz(f"r{i}", "s" * 64, i, i))
        if total + len(r) > 262144:
            break
        pieces.append(r)
        total += len(r)
        i += 1
    filler = 262144 - total
    big = b"".join(pieces)
    if filler >= 2:
        big = big[:-2] + b" " * filler + b"}\n"
    eq(len(big), 262144, "max block is exactly 262144 bytes")
    cid = "cap-max"
    manifest3 = write_manifest(TMP, cid, [big])
    out3 = expect_ok(manifest3, write_capture(TMP, all_capture_rows(cid, [big])), "max block size")
    eq(len(out3["blocks"]), 1, "max block recovered")


def test_reencoding() -> None:
    """Arbitrary byte blocks: all 15 four-shard subsets recover the codeword."""
    sys.path.insert(0, ROOT)
    import ecd as impl  # direct unit access; fixtures above are independent

    for n in (1, 2, 3, 4, 5, 7, 8, 9, 100, 1023, 4097):
        raw = bytes((i * 37 + n) & 0xFF for i in range(n))
        s = encode(raw)
        eq(impl.encode_shards(raw), s, f"encode parity n={n}")
        w = (n + 3) // 4
        for combo in itertools.combinations(range(6), 4):
            codeword, data = impl.decode_shards({i: s[i] for i in combo}, w)
            eq(codeword, s, f"codeword n={n} subset {combo}")
            eq(b"".join(data), raw + b"\x00" * (4 * w - n), f"data n={n} subset {combo}")

    # A 5-shard set that disagrees is rejected, even though a 4-subset works.
    raw = bytes(range(128))
    s = encode(raw)
    bad = dict(enumerate(s))
    bad[5] = bytes([s[5][0] ^ 1]) + s[5][1:]
    try:
        impl.decode_shards(bad, len(s[0]))
    except ValueError as exc:
        eq(str(exc), "contradiction", "5-shard contradiction detected")
    else:
        check(False, "5-shard contradiction detected")

    # Arithmetic spot checks against the independent bitwise multiplier.
    for a, b in ((0x57, 0x83), (0x00, 0xFF), (0x01, 0x1D), (0xFF, 0xFF), (0x80, 0x02)):
        eq(impl.gf_mul(a, b), gmul(a, b), f"GF product {a:02x}*{b:02x}")
    for a in (1, 2, 3, 0x11, 0x53, 0xFF):
        eq(impl.gf_mul(a, impl.gf_inv(a)), 1, f"GF inverse {a:02x}")

    # Field structure: every non-zero element is a power of 2, orders match.
    eq(sorted(impl._GF_EXP[:255]), list(range(1, 256)), "field is generated")
    eq(impl.decode_shards.__module__, "ecd", "impl under test is ecd")

    # End-to-end: independent fixture with exactly D1+D2+P+Q available.
    raw = bizline(biz("r1", "s", 10, 5)) + bizline(biz("r2", "t", 20, None))
    s = encode(raw)
    m = write_manifest(TMP, "cap-4of6", [raw])
    rows = [row("cap-4of6", 0, i, s[i]) for i in (1, 2, 4, 5)]
    out = expect_ok(m, write_capture(TMP, rows), "4-of-6 orthogonal subset")
    eq(out["blocks"][0]["available"], [1, 2, 4, 5], "available subset")
    eq(out["blocks"][0]["recovered"], [0, 3], "recovered subset")

    # A CRC-valid but wrong Q with D0..D3 present must be rejected, not ignored.
    m = write_manifest(TMP, "cap-qwrong", [raw])
    rows = [row("cap-qwrong", 0, i, s[i]) for i in range(4)]
    rows.append(row("cap-qwrong", 0, 5, bytes([s[5][0] ^ 0x10]) + s[5][1:]))
    expect_fail(m, write_capture(TMP, rows), "wrong Q rejected", "redundancy_contradiction")


def test_encode_cli_roundtrip() -> None:
    """The encode helper must feed recover without any manual fixture work."""
    b0 = bizline(biz("e1", "s", 1, None)) + bizline(biz("e2", "t", 2, 8))
    b1 = bizline(biz("e3", "u", 3, -4))
    d = os.path.join(TMP, f"enc-{next(_seq)}")
    os.makedirs(d)
    f0 = os.path.join(d, "b0")
    f1 = os.path.join(d, "b1")
    with open(f0, "wb") as fh:
        fh.write(b0)
    with open(f1, "wb") as fh:
        fh.write(b1)
    m = os.path.join(d, "m.json")
    c = os.path.join(d, "c.jsonl")
    proc = subprocess.run(
        [sys.executable, "-I", ECD, "encode", "--capture-id", "enc-cap",
         "--block-file", f0, "--block-file", f1,
         "--manifest-out", m, "--capture-out", c],
        capture_output=True, text=True,
    )
    eq(proc.returncode, 0, f"encode exits 0 ({proc.stderr})")
    out = expect_ok(m, c, "encode->recover")
    eq([r["record_id"] for r in out["rows"]], ["e1", "e2", "e3"], "encode round trip rows")


def main() -> int:
    tests = [
        test_all_double_erasures,
        test_arbitration,
        test_capture_validation,
        test_business_validation,
        test_stream_layout,
        test_publication,
        test_reencoding,
        test_encode_cli_roundtrip,
    ]
    for fn in tests:
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            FAILURES.append(f"{fn.__name__} raised {type(exc).__name__}: {exc}")
    shutil.rmtree(TMP, ignore_errors=True)
    print(f"{CHECKS} checks, {CASES} CLI runs")
    if FAILURES:
        print(f"{len(FAILURES)} FAILURES")
        for f in FAILURES:
            print("  -", f)
        return 1
    print("ALL PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
