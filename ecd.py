#!/usr/bin/env python3
"""Telemetry shard recovery with a self-contained (4+2) Reed-Solomon code.

Standard library only.  See README.md for the on-disk formats and the
arbitration/validation rules.

Usage:
    python3 ecd.py recover --manifest manifest.json --capture capture.jsonl \
        --output recovery.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
import zlib
from typing import Any, Iterable

# ---------------------------------------------------------------------------
# Finite field GF(256), reduction polynomial 0x11d (x^8+x^4+x^3+x^2+1).
# ---------------------------------------------------------------------------

_GF_POLY = 0x11D
_GF_ORDER = 255


def _build_gf_tables() -> tuple[list[int], list[int]]:
    exp = [0] * 512
    log = [0] * 256
    x = 1
    for i in range(_GF_ORDER):
        exp[i] = x
        log[x] = i
        x <<= 1
        if x & 0x100:
            x ^= _GF_POLY
    if x != 1 or len({exp[i] for i in range(_GF_ORDER)}) != _GF_ORDER:
        raise RuntimeError("GF(256) generator is not primitive")
    for i in range(_GF_ORDER, len(exp)):
        exp[i] = exp[i - _GF_ORDER]
    return exp, log


_GF_EXP, _GF_LOG = _build_gf_tables()


def gf_mul(a: int, b: int) -> int:
    """Multiply two GF(256) elements."""
    if a == 0 or b == 0:
        return 0
    return _GF_EXP[_GF_LOG[a] + _GF_LOG[b]]


def gf_inv(a: int) -> int:
    """Multiplicative inverse of a non-zero GF(256) element."""
    if a == 0:
        raise ZeroDivisionError("zero has no inverse in GF(256)")
    return _GF_EXP[(_GF_ORDER - _GF_LOG[a]) % _GF_ORDER]


# Generator matrix for shard indices 0..5.  Rows 0..3 are the systematic
# data shards; row 4 is P = D0 + D1 + D2 + D3; row 5 is
# Q = D0 + 2*D1 + 4*D2 + 8*D3.
_GENERATOR = [
    [1, 0, 0, 0],
    [0, 1, 0, 0],
    [0, 0, 1, 0],
    [0, 0, 0, 1],
    [1, 1, 1, 1],
    [1, 2, 4, 8],
]

_MUL_TABLES: dict[int, bytes] = {}


def _mul_table(c: int) -> bytes:
    table = _MUL_TABLES.get(c)
    if table is None:
        table = bytes(gf_mul(c, x) for x in range(256))
        _MUL_TABLES[c] = table
    return table


def _mul_into(out: bytearray, c: int, src: bytes) -> None:
    """out ^= c * src, byte by byte."""
    if c == 0:
        return
    table = _mul_table(c)
    for i, value in enumerate(src):
        out[i] ^= table[value]


def _add_into(out: bytearray, src: bytes) -> None:
    for i, value in enumerate(src):
        out[i] ^= value


def _gf_inv_matrix(matrix: list[list[int]]) -> list[list[int]]:
    """Invert a small square matrix over GF(256) by Gauss-Jordan elimination."""
    n = len(matrix)
    wide = [row[:] + [1 if i == j else 0 for j in range(n)] for i, row in enumerate(matrix)]

    for col in range(n):
        pivot = next((r for r in range(col, n) if wide[r][col] != 0), None)
        if pivot is None:
            raise ValueError("singular matrix")
        if pivot != col:
            wide[col], wide[pivot] = wide[pivot], wide[col]

        if wide[col][col] != 1:
            inv = gf_inv(wide[col][col])
            wide[col] = [gf_mul(v, inv) for v in wide[col]]

        for r in range(n):
            factor = wide[r][col] if r != col else 0
            if factor:
                pivot_row = wide[col]
                target = wide[r]
                for k in range(2 * n):
                    target[k] ^= gf_mul(factor, pivot_row[k])

    return [row[n:] for row in wide]


def encode_shards(raw: bytes) -> list[bytes]:
    """Return six shards D0..D3, P, Q for one original block.

    The raw block is zero-padded at the tail to a multiple of four bytes,
    then split into four equal data shards.
    """
    n = len(raw)
    if n < 1:
        raise ValueError("empty block")
    w = (n + 3) // 4
    padded = raw + b"\x00" * (4 * w - n)
    data = [padded[i * w : (i + 1) * w] for i in range(4)]

    p = bytearray(w)
    for shard in data:
        _add_into(p, shard)

    q = bytearray(w)
    for coefficient, shard in zip((1, 2, 4, 8), data):
        _mul_into(q, coefficient, shard)

    return data + [bytes(p), bytes(q)]


def _parity_shards(data: list[bytes]) -> list[bytes]:
    w = len(data[0])
    p = bytearray(w)
    for shard in data:
        _add_into(p, shard)
    q = bytearray(w)
    for coefficient, shard in zip((1, 2, 4, 8), data):
        _mul_into(q, coefficient, shard)
    return [bytes(p), bytes(q)]


def decode_shards(available: dict[int, bytes], w: int) -> tuple[list[bytes], list[bytes]]:
    """Recover all six shards using every available shard.

    ``available`` must contain at least four shards, each of length ``w``.
    Any four distinct rows of the generator matrix are independent, so one
    invertible 4x4 system is solved; afterwards every captured shard --
    including those not used as the pivot set -- is checked against the
    re-encoded codeword.  That is what makes "no cherry-picking subsets"
    enforceable.

    Raises ValueError("insufficient") or ValueError("contradiction").
    """
    indices = sorted(available)
    if len(indices) < 4:
        raise ValueError("insufficient")

    for idx in indices:
        if len(available[idx]) != w:
            raise ValueError("shard length")

    base = indices[:4]
    matrix = [_GENERATOR[idx][:] for idx in base]
    try:
        inverse = _gf_inv_matrix(matrix)
    except ValueError as exc:
        raise ValueError("singular") from exc

    data: list[bytes] = []
    for row in inverse:
        out = bytearray(w)
        for coefficient, idx in zip(row, base):
            if coefficient:
                _mul_into(out, coefficient, available[idx])
        data.append(bytes(out))

    codeword = data + _parity_shards(data)

    for idx in indices:
        if codeword[idx] != available[idx]:
            raise ValueError("contradiction")

    return codeword, data


# ---------------------------------------------------------------------------
# Errors.
# ---------------------------------------------------------------------------


class RecoveryError(Exception):
    """A located failure.  No output is published when one is raised."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        capture_line_no: int | None = None,
        block_no: int | None = None,
        business_line_no: int | None = None,
        byte_start: int | None = None,
        shard_index: int | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.capture_line_no = capture_line_no
        self.block_no = block_no
        self.business_line_no = business_line_no
        self.byte_start = byte_start
        self.shard_index = shard_index

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.capture_line_no is not None:
            result["capture_line_no"] = self.capture_line_no
        if self.block_no is not None:
            result["block_no"] = self.block_no
        if self.business_line_no is not None:
            result["business_line_no"] = self.business_line_no
        if self.byte_start is not None:
            result["byte_start"] = self.byte_start
        if self.shard_index is not None:
            result["shard_index"] = self.shard_index
        return result


class _DuplicateKey(Exception):
    def __init__(self, key: str) -> None:
        super().__init__(key)
        self.key = key


def _no_duplicate_keys(pairs: Iterable[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise _DuplicateKey(key)
        obj[key] = value
    return obj


def _reject_constant(token: str) -> Any:
    raise ValueError(f"non-standard JSON constant {token}")


def _loads_strict(text: str) -> Any:
    return json.loads(
        text,
        object_pairs_hook=_no_duplicate_keys,
        parse_constant=_reject_constant,
    )


def _is_int(value: Any) -> bool:
    return type(value) is int


# ---------------------------------------------------------------------------
# Manifest.
# ---------------------------------------------------------------------------


def _load_manifest(path: str) -> dict[str, Any]:
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        raise RecoveryError("manifest_io", f"cannot read manifest: {exc}") from exc

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RecoveryError("manifest_encoding", f"manifest is not valid UTF-8: {exc}") from exc

    try:
        obj = _loads_strict(text)
    except _DuplicateKey as exc:
        raise RecoveryError("manifest_duplicate_field", f"duplicate field {exc.key!r}") from exc
    except ValueError as exc:
        raise RecoveryError("manifest_json", f"invalid manifest JSON: {exc}") from exc

    if not isinstance(obj, dict):
        raise RecoveryError("manifest_shape", "manifest must be a JSON object")

    version = obj.get("version")
    if not _is_int(version) or version != 1:
        raise RecoveryError("manifest_version", "manifest version must be integer 1")

    capture_id = obj.get("capture_id")
    if not isinstance(capture_id, str) or not capture_id:
        raise RecoveryError("manifest_capture_id", "capture_id must be a non-empty string")
    if "\x00" in capture_id:
        raise RecoveryError("manifest_capture_id", "capture_id must not contain NUL")
    if any(0xD800 <= ord(ch) <= 0xDFFF for ch in capture_id):
        raise RecoveryError("manifest_capture_id", "capture_id must not contain surrogates")

    blocks = obj.get("blocks")
    if not isinstance(blocks, list):
        raise RecoveryError("manifest_blocks", "blocks must be an array")

    normalized: list[dict[str, Any]] = []
    for position, block in enumerate(blocks):
        if not isinstance(block, dict):
            raise RecoveryError("manifest_block_shape", f"block at position {position} is not an object")
        block_no = block.get("block_no")
        if not _is_int(block_no) or block_no != position:
            raise RecoveryError(
                "manifest_block_no",
                f"block at position {position} must have block_no {position}",
            )
        raw_length = block.get("raw_length")
        if not _is_int(raw_length) or not (1 <= raw_length <= 262144):
            raise RecoveryError(
                "manifest_raw_length",
                "raw_length must be an integer in 1..262144",
                block_no=position,
            )
        sha = block.get("sha256")
        if (
            not isinstance(sha, str)
            or len(sha) != 64
            or re.fullmatch(r"[0-9A-Fa-f]{64}", sha) is None
        ):
            raise RecoveryError(
                "manifest_sha256",
                "sha256 must be a 64-character hexadecimal string",
                block_no=position,
            )
        normalized.append(
            {"block_no": position, "raw_length": raw_length, "sha256": sha.lower()}
        )

    return {"version": 1, "capture_id": capture_id, "blocks": normalized}
# ---------------------------------------------------------------------------
# Capture parsing and arbitration.
# ---------------------------------------------------------------------------

_CAPTURE_FIELDS = {"capture_id", "block_no", "shard_index", "data_hex", "crc32"}


def _parse_capture(path: str, manifest: dict[str, Any]) -> dict[int, dict[str, Any]]:
    """Parse capture JSONL and arbitrate shard contents per block.

    Bad-CRC rows are non-fatal: they are remembered (by 1-based line number)
    but never count as usable content.  Duplicate good rows collapse to one
    candidate value, so repetition never adds weight.
    """
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        raise RecoveryError("capture_io", f"cannot read capture: {exc}") from exc

    if raw == b"":
        lines = []
    else:
        lines = raw.split(b"\n")
        if raw.endswith(b"\n"):
            lines = lines[:-1]

    blocks = manifest["blocks"]
    capture_id = manifest["capture_id"]

    # Per block and shard: the set of distinct CRC-valid contents seen.
    # A single content means "available"; two or more distinct contents mean
    # "conflict" (all of them are discarded); none means "missing".
    stats: dict[int, dict[str, Any]] = {}
    for block in blocks:
        stats[block["block_no"]] = {
            "candidates": {idx: set() for idx in range(6)},  # idx -> {content}
            "bad_crc": {idx: [] for idx in range(6)},
        }

    for line_no, line in enumerate(lines, start=1):
        try:
            text = line.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RecoveryError(
                "capture_encoding",
                f"capture line is not valid UTF-8: {exc}",
                capture_line_no=line_no,
            ) from exc
        if text.strip() == "":
            raise RecoveryError(
                "capture_empty_line",
                "empty line in capture",
                capture_line_no=line_no,
            )
        try:
            obj = _loads_strict(text)
        except _DuplicateKey as exc:
            raise RecoveryError(
                "capture_duplicate_field",
                f"duplicate field {exc.key!r}",
                capture_line_no=line_no,
            ) from exc
        except ValueError as exc:
            raise RecoveryError(
                "capture_json",
                f"invalid JSON: {exc}",
                capture_line_no=line_no,
            ) from exc

        if not isinstance(obj, dict):
            raise RecoveryError(
                "capture_shape", "capture line must be a JSON object", capture_line_no=line_no
            )
        keys = set(obj)
        missing = sorted(_CAPTURE_FIELDS - keys)
        if missing:
            # Capture rows must contain the five documented fields; other
            # fields are tolerated (unlike business rows, whose schema is
            # exactly four fields).
            raise RecoveryError(
                "capture_fields",
                f"capture line is missing required fields {missing}",
                capture_line_no=line_no,
            )

        value = obj["capture_id"]
        if not isinstance(value, str):
            raise RecoveryError(
                "capture_capture_id", "capture_id must be a string", capture_line_no=line_no
            )
        if value != capture_id:
            raise RecoveryError(
                "capture_source",
                "capture_id does not match manifest",
                capture_line_no=line_no,
            )

        block_no = obj["block_no"]
        if not _is_int(block_no) or not (0 <= block_no < len(blocks)):
            raise RecoveryError(
                "capture_block_no",
                "block_no is not a block in the manifest",
                capture_line_no=line_no,
            )
        block_spec = blocks[block_no]

        shard_index = obj["shard_index"]
        if not _is_int(shard_index) or not (0 <= shard_index < 6):
            raise RecoveryError(
                "capture_shard_index",
                "shard_index must be an integer 0..5",
                capture_line_no=line_no,
                block_no=block_no,
            )

        data_hex = obj["data_hex"]
        raw_length = block_spec["raw_length"]
        w = (raw_length + 3) // 4
        if not isinstance(data_hex, str):
            raise RecoveryError(
                "capture_data_hex",
                "data_hex must be a string",
                capture_line_no=line_no,
                block_no=block_no,
                shard_index=shard_index,
            )
        if len(data_hex) != 2 * w or re.fullmatch(r"[0-9a-f]+", data_hex) is None:
            raise RecoveryError(
                "capture_data_hex",
                f"data_hex must be exactly {2 * w} lowercase hexadecimal characters",
                capture_line_no=line_no,
                block_no=block_no,
                shard_index=shard_index,
            )
        shard = bytes.fromhex(data_hex)
        if len(shard) != w:  # defensive; the regex/length check above suffices
            raise RecoveryError(
                "capture_data_hex",
                "data_hex length mismatch",
                capture_line_no=line_no,
                block_no=block_no,
                shard_index=shard_index,
            )

        crc = obj["crc32"]
        if not _is_int(crc) or not (0 <= crc <= 0xFFFFFFFF):
            raise RecoveryError(
                "capture_crc32",
                "crc32 must be an unsigned 32-bit integer",
                capture_line_no=line_no,
                block_no=block_no,
                shard_index=shard_index,
            )

        stats_for_block = stats[block_no]

        if (zlib.crc32(shard) & 0xFFFFFFFF) != crc:
            stats_for_block["bad_crc"][shard_index].append(line_no)
            continue

        candidates = stats_for_block["candidates"][shard_index]
        candidates.add(shard)

    return stats


# ---------------------------------------------------------------------------
# Business JSONL parsing.
# ---------------------------------------------------------------------------

_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
_I64_MIN = -(1 << 63)
_I64_MAX = (1 << 63) - 1
_U64_TS_MAX = (1 << 63) - 1
_BUSINESS_FIELDS = {"record_id", "sensor_id", "timestamp_ns", "value_uv"}


def _validate_business_row(
    obj: Any,
    *,
    line_no: int,
    byte_start: int,
    seen_record_ids: set[str],
) -> dict[str, Any]:
    if not isinstance(obj, dict):
        raise RecoveryError(
            "business_shape",
            "business row must be a JSON object",
            business_line_no=line_no,
            byte_start=byte_start,
        )
    keys = set(obj)
    if keys != _BUSINESS_FIELDS:
        unknown = sorted(keys - _BUSINESS_FIELDS)
        missing = sorted(_BUSINESS_FIELDS - keys)
        raise RecoveryError(
            "business_fields",
            f"business row fields mismatch; unknown={unknown}, missing={missing}",
            business_line_no=line_no,
            byte_start=byte_start,
        )

    record_id = obj["record_id"]
    if not isinstance(record_id, str) or _IDENTIFIER_RE.fullmatch(record_id) is None:
        raise RecoveryError(
            "business_record_id",
            "record_id must be 1..64 ASCII alphanumeric/_/- characters",
            business_line_no=line_no,
            byte_start=byte_start,
        )
    if record_id in seen_record_ids:
        raise RecoveryError(
            "business_duplicate_record_id",
            f"duplicate record_id {record_id!r}",
            business_line_no=line_no,
            byte_start=byte_start,
        )

    sensor_id = obj["sensor_id"]
    if not isinstance(sensor_id, str):
        raise RecoveryError(
            "business_sensor_id",
            "sensor_id must be a string",
            business_line_no=line_no,
            byte_start=byte_start,
        )
    if not (1 <= len(sensor_id) <= 64):
        raise RecoveryError(
            "business_sensor_id",
            "sensor_id must contain 1..64 Unicode code points",
            business_line_no=line_no,
            byte_start=byte_start,
        )
    if "\x00" in sensor_id:
        raise RecoveryError(
            "business_sensor_id",
            "sensor_id must not contain NUL",
            business_line_no=line_no,
            byte_start=byte_start,
        )
    for ch in sensor_id:
        if 0xD800 <= ord(ch) <= 0xDFFF:
            raise RecoveryError(
                "business_sensor_id",
                "sensor_id contains an unpaired surrogate",
                business_line_no=line_no,
                byte_start=byte_start,
            )

    timestamp_ns = obj["timestamp_ns"]
    if not _is_int(timestamp_ns) or not (0 <= timestamp_ns <= _U64_TS_MAX):
        raise RecoveryError(
            "business_timestamp_ns",
            "timestamp_ns must be a non-negative signed 64-bit integer",
            business_line_no=line_no,
            byte_start=byte_start,
        )

    value_uv = obj["value_uv"]
    if value_uv is not None:
        if not _is_int(value_uv) or not (_I64_MIN <= value_uv <= _I64_MAX):
            raise RecoveryError(
                "business_value_uv",
                "value_uv must be null or a signed 64-bit integer",
                business_line_no=line_no,
                byte_start=byte_start,
            )

    seen_record_ids.add(record_id)
    return {
        "record_id": record_id,
        "sensor_id": sensor_id,
        "timestamp_ns": timestamp_ns,
        "value_uv": value_uv,
        "line_no": line_no,
        "byte_start": byte_start,
        "byte_end": None,  # filled by caller
    }


def parse_business_stream(data: bytes) -> list[dict[str, Any]]:
    """Parse the concatenated original byte stream as strict UTF-8 JSONL."""
    if data == b"":
        return []
    if not data.endswith(b"\n"):
        last_lf = data.rfind(b"\n")
        line_start = last_lf + 1
        line_no = data.count(b"\n") + 1
        raise RecoveryError(
            "stream_missing_final_lf",
            "non-empty business stream must end with LF",
            business_line_no=line_no,
            byte_start=line_start,
        )

    parts = data.split(b"\n")
    if parts and parts[-1] == b"":
        parts.pop()

    rows: list[dict[str, Any]] = []
    seen_record_ids: set[str] = set()
    offset = 0

    for line_no, part in enumerate(parts, start=1):
        byte_start = offset
        offset += len(part) + 1  # content plus the LF that split it

        if part == b"":
            raise RecoveryError(
                "business_empty_line",
                "empty line in business stream",
                business_line_no=line_no,
                byte_start=byte_start,
            )

        try:
            text = part.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RecoveryError(
                "business_encoding",
                f"business line is not valid UTF-8: {exc}",
                business_line_no=line_no,
                byte_start=byte_start,
            ) from exc

        try:
            obj = _loads_strict(text)
        except _DuplicateKey as exc:
            raise RecoveryError(
                "business_duplicate_field",
                f"duplicate field {exc.key!r}",
                business_line_no=line_no,
                byte_start=byte_start,
            ) from exc
        except ValueError as exc:
            raise RecoveryError(
                "business_json",
                f"invalid JSON: {exc}",
                business_line_no=line_no,
                byte_start=byte_start,
            ) from exc

        row = _validate_business_row(
            obj,
            line_no=line_no,
            byte_start=byte_start,
            seen_record_ids=seen_record_ids,
        )
        row["byte_end"] = byte_start + len(part)
        rows.append(row)

    return rows


# ---------------------------------------------------------------------------
# Recovery orchestration.
# ---------------------------------------------------------------------------


def recover(manifest_path: str, capture_path: str) -> dict[str, Any]:
    """Perform a complete recovery in memory.  Raises RecoveryError on failure."""
    manifest = _load_manifest(manifest_path)
    stats = _parse_capture(capture_path, manifest)

    raw_blocks: list[bytes] = []
    audit: list[dict[str, Any]] = []

    for block in manifest["blocks"]:
        block_no = block["block_no"]
        n = block["raw_length"]
        w = (n + 3) // 4
        block_stats = stats[block_no]

        available: dict[int, bytes] = {}
        missing: list[int] = []
        conflicts: list[int] = []

        for idx in range(6):
            candidates = block_stats["candidates"][idx]
            if len(candidates) == 0:
                missing.append(idx)
            elif len(candidates) == 1:
                available[idx] = next(iter(candidates))
            else:
                conflicts.append(idx)

        if len(available) < 4:
            raise RecoveryError(
                "insufficient_shards",
                f"block {block_no} has only {len(available)} available shards; at least 4 are required",
                block_no=block_no,
            )

        try:
            codeword, data = decode_shards(available, w)
        except ValueError as exc:
            if str(exc) == "contradiction":
                raise RecoveryError(
                    "redundancy_contradiction",
                    f"block {block_no} available shards are mutually inconsistent",
                    block_no=block_no,
                ) from exc
            raise RecoveryError(
                "decode_failed",
                f"block {block_no} could not be decoded: {exc}",
                block_no=block_no,
            ) from exc

        padded = b"".join(data)
        if any(padded[n:]):
            raise RecoveryError(
                "padding_nonzero",
                f"block {block_no} has non-zero padding beyond raw_length",
                block_no=block_no,
            )

        raw = padded[:n]
        digest = hashlib.sha256(raw).hexdigest()
        if digest != block["sha256"]:
            raise RecoveryError(
                "hash_mismatch",
                f"block {block_no} sha256 mismatch",
                block_no=block_no,
            )

        # Every shard that was not a sole captured value is restored from the
        # codeword.  Conflicting values were never used as evidence.
        recovered = sorted(
            idx for idx in range(6) if idx not in available
        )

        raw_blocks.append(raw)
        audit.append(
            {
                "block_no": block_no,
                "available": sorted(available),
                "missing": missing,
                "conflicts": conflicts,
                "recovered": recovered,
                "bad_crc_lines": sorted(
                    line for idx in range(6) for line in block_stats["bad_crc"][idx]
                ),
            }
        )

    stream = b"".join(raw_blocks)
    rows = parse_business_stream(stream)

    return {
        "capture_id": manifest["capture_id"],
        "rows": rows,
        "blocks": audit,
    }


def _serialize(obj: Any) -> bytes:
    return (
        json.dumps(obj, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    ).encode("utf-8")


def _publish_atomically(path: str, payload: bytes) -> None:
    """Publish only if the target does not exist; never leave a partial file."""
    if os.path.lexists(path):
        raise RecoveryError("output_exists", f"output target already exists: {path}")

    parent = os.path.dirname(os.path.abspath(path))
    try:
        fd, tmp = tempfile.mkstemp(prefix=".ecd-tmp-", dir=parent)
    except OSError as exc:
        raise RecoveryError("output_io", f"cannot create temporary output: {exc}") from exc

    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o644)
        try:
            # Hard-link creation is atomic and fails with EEXIST rather than
            # clobbering a target that appeared after the initial check.
            os.link(tmp, path)
        except FileExistsError as exc:
            raise RecoveryError(
                "output_exists", f"output target already exists: {path}"
            ) from exc
        except OSError as exc:
            raise RecoveryError("output_io", f"cannot publish output: {exc}") from exc
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def recover_to_file(manifest_path: str, capture_path: str, output_path: str) -> dict[str, Any]:
    result = recover(manifest_path, capture_path)
    _publish_atomically(output_path, _serialize(result))
    return result


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Recover telemetry blocks from a 4+2 erasure-coded capture."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    recover_cmd = sub.add_parser("recover", help="recover and publish the result JSON")
    recover_cmd.add_argument("--manifest", required=True)
    recover_cmd.add_argument("--capture", required=True)
    recover_cmd.add_argument("--output", required=True)

    encode_cmd = sub.add_parser(
        "encode", help="emit capture rows for plain blocks (verification aid)"
    )
    encode_cmd.add_argument("--capture-id", required=True)
    encode_cmd.add_argument("--block-file", action="append", required=True,
                            help="one plain block per file; repeatable, manifests are derived")
    encode_cmd.add_argument("--manifest-out", required=False)
    encode_cmd.add_argument("--capture-out", required=False)

    args = parser.parse_args(argv)

    if args.command == "encode":
        return _encode_cli(args)

    try:
        recover_to_file(args.manifest, args.capture, args.output)
    except RecoveryError as exc:
        sys.stderr.write(
            json.dumps({"ok": False, "error": exc.as_dict()}, ensure_ascii=False) + "\n"
        )
        return 1
    except Exception as exc:  # pragma: no cover - defensive top-level guard
        sys.stderr.write(
            json.dumps(
                {"ok": False, "error": {"code": "internal_error", "message": str(exc)}},
                ensure_ascii=False,
            )
            + "\n"
        )
        return 2
    return 0


def _encode_cli(args: argparse.Namespace) -> int:
    """Debug aid: encode plain blocks into a manifest plus capture rows."""
    blocks: list[bytes] = []
    for path in args.block_file:
        with open(path, "rb") as fh:
            blocks.append(fh.read())

    manifest = {
        "version": 1,
        "capture_id": args.capture_id,
        "blocks": [
            {
                "block_no": i,
                "raw_length": len(b),
                "sha256": hashlib.sha256(b).hexdigest(),
            }
            for i, b in enumerate(blocks)
        ],
    }
    capture_lines = []
    for block_no, block in enumerate(blocks):
        for shard_index, shard in enumerate(encode_shards(block)):
            capture_lines.append(
                json.dumps(
                    {
                        "capture_id": args.capture_id,
                        "block_no": block_no,
                        "shard_index": shard_index,
                        "data_hex": shard.hex(),
                        "crc32": zlib.crc32(shard) & 0xFFFFFFFF,
                    }
                )
            )

    if args.manifest_out:
        with open(args.manifest_out, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
    if args.capture_out:
        with open(args.capture_out, "w", encoding="utf-8") as fh:
            fh.write("\n".join(capture_lines) + "\n")
    if not args.manifest_out and not args.capture_out:
        sys.stdout.write(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
        sys.stdout.write("\n".join(capture_lines) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
