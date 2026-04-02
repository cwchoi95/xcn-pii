from __future__ import annotations

import json
import os
import logging
import ipaddress
import threading
import time
from pathlib import Path
import re
from dataclasses import dataclass, field
import hashlib
from typing import Any, Dict, List, Pattern, Tuple

import hyperscan

logger = logging.getLogger("pii.engine")

logger = logging.getLogger("pii.engine")

_IGNORED_DETECTION_CHARS = {
    "\ufeff",  # ZWNBSP / BOM
    "\u200b",  # zero width space
    "\u200c",  # zero width non-joiner
    "\u200d",  # zero width joiner
    "\u2060",  # word joiner
}


def _trace_stage_enabled() -> bool:
    return _env_bool("PII_STAGE_LOG_ENABLED", False)


def _trace_timing_enabled() -> bool:
    return _env_bool("PII_STAGE_TIMING_ENABLED", True)


def _trace_item_enabled() -> bool:
    return _env_bool("PII_STAGE_LOG_ITEMS", False)


def _trace_item_limit() -> int:
    return max(1, _env_int("PII_STAGE_LOG_ITEM_LIMIT", 20))


def _trace_text_limit() -> int:
    return max(16, _env_int("PII_STAGE_LOG_TEXT_LIMIT", 120))


def _truncate(s: str, limit: int) -> str:
    s = str(s or "")
    if len(s) <= limit:
        return s
    return s[:limit] + "..."


def _mask_match(s: str) -> str:
    raw = str(s or "")
    if len(raw) <= 4:
        return raw
    return f"{raw[:2]}...{raw[-2:]}"


def _request_id(text: str) -> str:
    raw = str(text or "")
    if not raw:
        return "empty"
    return hashlib.md5(raw.encode("utf-8", errors="ignore")).hexdigest()[:8]


def _timing_now() -> float:
    return time.perf_counter()


def _timing_ms(t0: float) -> float:
    return (time.perf_counter() - t0) * 1000.0


def _log_timing(stage: str, req_id: str | None = None, **fields: Any) -> None:
    if not _trace_timing_enabled():
        return
    ordered: List[Tuple[str, Any]] = []
    ordered.append(("req", req_id or "-"))
    ordered.append(("stage", stage))
    if "ms" in fields:
        ordered.append(("ms", fields.pop("ms")))
    ordered.extend((k, v) for k, v in fields.items())
    parts = [f"{k}={v}" for k, v in ordered]
    logger.info("[timing] %s", " ".join(parts))


def _summarize_counts(out: Dict[str, List[dict]]) -> Dict[str, int]:
    keys = [
        "SN", "SN_INVALID", "SSN", "DN", "PN", "MN", "BN", "AN", "EML", "IP",
        "SN_CTX_REJECTED", "SN_INVALID_CTX_REJECTED", "SSN_CTX_REJECTED", "DN_CTX_REJECTED",
        "PN_CTX_REJECTED", "MN_CTX_REJECTED", "BN_CTX_REJECTED", "AN_CTX_REJECTED", "EML_CTX_REJECTED", "IP_CTX_REJECTED",
    ]
    d: Dict[str, int] = {}
    for k in keys:
        d[k] = len(out.get(k) or [])
    return d


# ============================================================
# Utilities
# ============================================================


def _build_byte_to_char_map(text: str) -> List[int]:
    b = text.encode("utf-8")
    m = [0] * (len(b) + 1)

    byte_pos = 0
    for char_idx, ch in enumerate(text):
        chb = ch.encode("utf-8")
        for _ in range(len(chb)):
            if byte_pos <= len(b):
                m[byte_pos] = char_idx
            byte_pos += 1

    m[len(b)] = len(text)
    return m


def _load_bank_patterns(bn_doc: Dict[str, Any], rules_dir: Path) -> List[Dict[str, Any]]:
    path = bn_doc.get("bank_pattern_file")
    if not path:
        return []
    p = rules_dir / str(path)
    try:
        raw = p.read_text(encoding="utf-8")
        data = json.loads(raw or "{}")
    except Exception:
        return []
    out: List[Dict[str, Any]] = []
    if not isinstance(data, dict):
        return out
    for code, entry in data.items():
        if not isinstance(entry, dict):
            continue
        inst = str(entry.get("institution") or "").strip()
        patterns = entry.get("patterns") or []
        if not patterns:
            continue
        out.append({
            "code": str(code),
            "institution": inst,
            "patterns": [str(p) for p in patterns if isinstance(p, str) and p],
        })
    return out


def _dedup_sorted(items: List[dict]) -> List[dict]:
    out: List[dict] = []
    seen = set()
    for it in items:
        sig = (it.get("start"), it.get("end"), it.get("matchString"))
        if sig in seen:
            continue
        seen.add(sig)
        out.append(it)
    return out


def _select_non_overlapping(items: List[dict]) -> List[dict]:
    # Prefer longer span when multiple candidates share the same start.
    items = sorted(items, key=lambda x: (x["start"], -x["end"]))
    selected: List[dict] = []
    last_end = -1
    for it in items:
        if it["start"] >= last_end:
            selected.append(it)
            last_end = it["end"]
    return selected


def _scan_regex_cursor(text: str, regexes: List[Pattern], max_results: int, max_len: int) -> List[dict]:
    """Cursor-based scan to avoid tons of overlapping matches."""
    results: List[dict] = []
    pos = 0
    n = len(text)

    while pos < n and len(results) < max_results:
        best = None
        for rx in regexes:
            m = rx.search(text, pos)
            if not m:
                continue
            if best is None or m.start() < best.start() or (m.start() == best.start() and m.end() > best.end()):
                best = m

        if best is None:
            break

        s, e = best.start(), best.end()
        if e - s > max_len:
            e = s + max_len

        if e > s:
            results.append({"start": s, "end": e, "matchString": text[s:e]})

        pos = max(e, s + 1)

    results.sort(key=lambda x: (x["start"], x["end"]))
    return _dedup_sorted(results)


def _overlaps(a_s: int, a_e: int, b_s: int, b_e: int) -> bool:
    return not (a_e <= b_s or b_e <= a_s)


def _digits_only(s: str) -> str:
    return re.sub(r"\D", "", s or "")


_KOR_DIGIT_MAP = {
    "공": "0",
    "영": "0",
    "일": "1",
    "이": "2",
    "삼": "3",
    "사": "4",
    "오": "5",
    "육": "6",
    "륙": "6",
    "칠": "7",
    "팔": "8",
    "구": "9",
}


def _normalize_digit_text(s: str) -> str:
    raw = str(s or "")
    if not raw:
        return ""
    return "".join(_KOR_DIGIT_MAP.get(ch, ch) for ch in raw)


def _normalize_match_text(s: str) -> str:
    return str(s or "").casefold()


def _normalize_for_detection(text: str) -> Tuple[str, List[int]]:
    raw = str(text or "")
    if not raw:
        return "", []
    chars: List[str] = []
    kept_positions: List[int] = []
    for idx, ch in enumerate(raw):
        if ch in _IGNORED_DETECTION_CHARS:
            continue
        chars.append(ch)
        kept_positions.append(idx)
    return "".join(chars), kept_positions


def _remap_span(start: int, end: int, kept_positions: List[int], source_len: int) -> Tuple[int, int]:
    if not kept_positions:
        return int(start), int(end)
    s = max(0, min(int(start), len(kept_positions) - 1))
    e = max(s, int(end))
    orig_s = kept_positions[s]
    orig_e = source_len if e >= len(kept_positions) else kept_positions[e]
    if orig_e < orig_s:
        orig_e = orig_s
    return orig_s, orig_e


def _remap_output_spans(out: Dict[str, List[dict]], source_text: str, kept_positions: List[int]) -> None:
    if not source_text or not kept_positions:
        return
    for _, items in list(out.items()):
        if not isinstance(items, list):
            continue
        for it in items:
            if not isinstance(it, dict):
                continue
            s = it.get("start")
            e = it.get("end")
            if not isinstance(s, int) or not isinstance(e, int):
                continue
            if s < 0 or e < s:
                continue
            orig_s, orig_e = _remap_span(s, e, kept_positions, len(source_text))
            it["start"] = orig_s
            it["end"] = orig_e
            it["matchString"] = source_text[orig_s:orig_e]


def _span_list(items: List[dict]) -> List[Tuple[int, int]]:
    return [
        (x["start"], x["end"]) for x in (items or []) if isinstance(x.get("start"), int) and isinstance(x.get("end"), int)
    ]


def _cleanup_bn_ctx_rejected_overlap(out: Dict[str, List[dict]], bn_doc: Dict[str, Any]) -> None:
    """Drop BN_CTX_REJECTED entries that overlap with higher-priority types.

    This keeps context-rejected BN noise low when a span is already accepted as
    another type (e.g., SN).
    """
    if not isinstance(out, dict):
        return
    post = (bn_doc.get("postfilter") or {}) if isinstance(bn_doc, dict) else {}
    if not bool(post.get("enabled", True)):
        return
    reject_overlap_with = [str(x) for x in (post.get("reject_overlap_with") or [])]
    if not reject_overlap_with:
        return
    bn_rej = out.get("BN_CTX_REJECTED") or []
    if not bn_rej:
        return

    reject_spans: List[Tuple[int, int]] = []
    for key in reject_overlap_with:
        reject_spans.extend(_span_list(out.get(key) or []))
    if not reject_spans:
        return

    filtered: List[dict] = []
    for it in bn_rej:
        s = it.get("start")
        e = it.get("end")
        if not isinstance(s, int) or not isinstance(e, int) or e <= s:
            continue
        if any(_overlaps(s, e, rs, re_) for rs, re_ in reject_spans):
            continue
        filtered.append(it)

    out["BN_CTX_REJECTED"] = _finalize(filtered)


def _finalize(items: List[dict]) -> List[dict]:
    items = items or []
    items.sort(key=lambda x: (x["start"], x["end"]))
    return _dedup_sorted(_select_non_overlapping(items))


def _trim_an_suffix(match_str: str) -> str:
    """Trim common non-address suffix labels accidentally captured after AN."""
    s = str(match_str or "")
    if not s:
        return s
    # Stop at common non-address labels that often follow company address lines.
    stop_re = re.compile(
        r"(?:"
        # classic label-style tails (with ':' mostly)
        r"\s*(?:지원시간|영업시간|문의|문의전화|연락처|대표번호|대표전화|전화|팩스|담당자|이메일|\(?TEL\)?|\(?PHONE\)?|\(?FAX\)?)\s*:|"
        # metadata tails without ':' (often seen in copied forms/tables)
        r"\s+(?:구분|상세(?:\s*내용)?|내용|작성일|등록부작성일|가족관계등록부작성일)(?:\s|:|$)|"
        # bracketed metadata labels
        r"\s*\[[^\]]*(?:작성일|등록부작성일|가족관계등록부작성일|구분|상세|내용)[^\]]*\]"
        r")",
        re.IGNORECASE,
    )
    m = stop_re.search(s)
    cut = m.start() if m and m.start() > 0 else len(s)
    trimmed = s[:cut].rstrip(" ,;:/")
    return trimmed


# ============================================================
# RRN checksum validation
# ============================================================


def rrn_checksum_valid(rrn: str) -> bool:
    digits_only = re.sub(r"\D", "", _normalize_digit_text((rrn or "").strip()))
    if len(digits_only) != 13:
        return False

    digits = [int(c) for c in digits_only]
    weights = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5]

    total = 0
    for i in range(12):
        total += digits[i] * weights[i]

    expected = (11 - (total % 11)) % 10
    return expected == digits[12]


def rrn_structure_valid(rrn: str) -> bool:
    digits_only = re.sub(r"\D", "", _normalize_digit_text((rrn or "").strip()))
    if len(digits_only) != 13:
        return False

    front = digits_only[:6]
    back_first = digits_only[6]
    if back_first not in {"1", "2", "3", "4", "5", "6", "7", "8"}:
        return False

    mm = int(front[2:4])
    dd = int(front[4:6])
    if mm < 1 or mm > 12:
        return False
    if dd < 1 or dd > 31:
        return False

    century = 1900 if back_first in {"1", "2", "5", "6"} else 2000
    yy = int(front[:2])
    year = century + yy
    try:
        return bool(time.strptime(f"{year:04d}{mm:02d}{dd:02d}", "%Y%m%d"))
    except ValueError:
        return False


def email_structure_valid(value: str) -> bool:
    raw = str(value or "").strip()
    if "@" not in raw:
        return False
    try:
        local, domain = raw.rsplit("@", 1)
    except ValueError:
        return False
    if not local or not domain:
        return False
    if local.startswith(".") or local.endswith(".") or ".." in local:
        return False
    if domain.startswith(".") or domain.endswith(".") or ".." in domain:
        return False
    labels = domain.split(".")
    if len(labels) < 2:
        return False
    if any((not label) or label.startswith("-") or label.endswith("-") for label in labels):
        return False
    tld = labels[-1]
    if len(tld) < 2 or len(tld) > 24:
        return False
    return True


def ip_structure_valid(value: str) -> bool:
    raw = str(value or "").strip()
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return False
    if raw in {"0.0.0.0", "255.255.255.255"}:
        return False
    return not getattr(ip, "is_unspecified", False)


def ssn_structure_valid(value: str) -> bool:
    digits = _digits_only(str(value or "").strip())
    if len(digits) != 9:
        return False
    area = digits[:3]
    group = digits[3:5]
    serial = digits[5:]
    if area in {"000", "666"} or area.startswith("9"):
        return False
    if group == "00" or serial == "0000":
        return False
    return True


def phone_structure_valid(value: str) -> bool:
    raw = str(value or "").strip()
    if not raw:
        return False
    digits = _digits_only(_normalize_digit_text(raw))
    if raw.startswith("+"):
        return 8 <= len(digits) <= 15
    if not raw.startswith(("0", "공", "영")):
        return False
    if not (9 <= len(digits) <= 11):
        return False
    if len(set(digits)) <= 1:
        return False
    return True


# ============================================================
# Detector interfaces
# ============================================================


@dataclass
class DetectContext:
    text: str
    source_text: str = ""
    max_results: int = 500
    out: Dict[str, List[dict]] = field(default_factory=dict)
    request_id: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)

    def get(self, key: str) -> List[dict]:
        return self.out.get(key, [])

    def set(self, key: str, items: List[dict]) -> None:
        self.out[key] = items

    def get_extra(self, key: str, default: Any = None) -> Any:
        return self.extra.get(key, default)

    def set_extra(self, key: str, value: Any) -> None:
        self.extra[key] = value


class Detector:
    def run(self, ctx: DetectContext) -> None:  # pragma: no cover
        raise NotImplementedError


# ============================================================
# Hyperscan (DN only)
# ============================================================


@dataclass(frozen=True)
class HSPattern:
    expr: bytes
    flags: int


@dataclass(frozen=True)
class HSTypedPattern:
    expr: bytes
    flags: int
    out_key: str
    pattern_index: int


class HyperscanDB:
    def __init__(self, patterns: List[HSPattern]):
        self.patterns = patterns
        self.db = hyperscan.Database(mode=hyperscan.HS_MODE_BLOCK)
        self._scratch_local = threading.local()
        self._scratch_lock = threading.Lock()
        self._base_scratch = None

        if patterns:
            expressions = [p.expr for p in patterns]
            flags = [p.flags for p in patterns]
            self.db.compile(expressions=expressions, ids=list(range(len(patterns))), flags=flags)
            self._base_scratch = hyperscan.Scratch(self.db)

    def _get_scratch(self):
        scratch = getattr(self._scratch_local, "value", None)
        if scratch is not None:
            return scratch
        with self._scratch_lock:
            scratch = getattr(self._scratch_local, "value", None)
            if scratch is None:
                if self._base_scratch is not None:
                    scratch = self._base_scratch.clone()
                else:
                    scratch = hyperscan.Scratch(self.db)
                self._scratch_local.value = scratch
        return scratch

    def detect(self, text: str) -> List[dict]:
        results: List[dict] = []
        if not text or not self.patterns:
            return results

        b = text.encode("utf-8")
        byte_to_char = _build_byte_to_char_map(text)

        def on_match(id: int, from_: int, to: int, flags: int, context=None):
            if to <= 0 or to > len(b):
                return None
            try:
                from_char = byte_to_char[min(from_, len(byte_to_char) - 1)]
                to_char = byte_to_char[min(to, len(byte_to_char) - 1)]
                match_str = text[from_char:to_char]
                if match_str:
                    results.append({"start": from_char, "end": to_char, "matchString": match_str, "_hs_id": int(id)})
            except (IndexError, ValueError):
                pass
            return None

        self.db.scan(b, match_event_handler=on_match, scratch=self._get_scratch())
        return _finalize(results)


class CombinedHyperscanDB:
    def __init__(self, patterns: List[HSTypedPattern]):
        self.patterns = patterns
        self.pattern_count = len(patterns)
        self.out_keys = {p.out_key for p in patterns}
        self.db = hyperscan.Database(mode=hyperscan.HS_MODE_BLOCK)
        self._scratch_local = threading.local()
        self._scratch_lock = threading.Lock()
        self._base_scratch = None
        self._meta_by_id: Dict[int, Tuple[str, int]] = {}

        if patterns:
            expressions = [p.expr for p in patterns]
            flags = [p.flags for p in patterns]
            ids = list(range(len(patterns)))
            self.db.compile(expressions=expressions, ids=ids, flags=flags)
            self._base_scratch = hyperscan.Scratch(self.db)
            for idx, pat in enumerate(patterns):
                self._meta_by_id[idx] = (pat.out_key, pat.pattern_index)

    def _get_scratch(self):
        scratch = getattr(self._scratch_local, "value", None)
        if scratch is not None:
            return scratch
        with self._scratch_lock:
            scratch = getattr(self._scratch_local, "value", None)
            if scratch is None:
                if self._base_scratch is not None:
                    scratch = self._base_scratch.clone()
                else:
                    scratch = hyperscan.Scratch(self.db)
                self._scratch_local.value = scratch
        return scratch

    def detect_all(self, text: str) -> Dict[str, List[dict]]:
        buckets: Dict[str, List[dict]] = {}
        if not text or not self.patterns:
            return buckets

        b = text.encode("utf-8")
        byte_to_char = _build_byte_to_char_map(text)

        def on_match(id: int, from_: int, to: int, flags: int, context=None):
            if to <= 0 or to > len(b):
                return None
            meta = self._meta_by_id.get(int(id))
            if meta is None:
                return None
            out_key, pattern_index = meta
            try:
                from_char = byte_to_char[min(from_, len(byte_to_char) - 1)]
                to_char = byte_to_char[min(to, len(byte_to_char) - 1)]
                match_str = text[from_char:to_char]
                if match_str:
                    buckets.setdefault(out_key, []).append(
                        {
                            "start": from_char,
                            "end": to_char,
                            "matchString": match_str,
                            "_hs_id": int(pattern_index),
                        }
                    )
            except (IndexError, ValueError):
                pass
            return None

        self.db.scan(b, match_event_handler=on_match, scratch=self._get_scratch())
        for out_key, items in list(buckets.items()):
            buckets[out_key] = _finalize(items)
        return buckets


def _env(name: str, default: str) -> str:
    v = os.getenv(name)
    return v.strip() if v and v.strip() else default


def _env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def _env_int(name: str, default: int) -> int:
    v = os.getenv(name)
    if v is None:
        return int(default)
    try:
        return int(str(v).strip())
    except Exception:
        return int(default)


def _env_csv_upper(name: str, default_csv: str) -> List[str]:
    raw = os.getenv(name)
    if raw is None or not str(raw).strip():
        raw = default_csv
    out: List[str] = []
    for x in str(raw).split(","):
        k = str(x).strip().upper()
        if not k:
            continue
        out.append(k)
    seen = set()
    dedup: List[str] = []
    for k in out:
        if k in seen:
            continue
        seen.add(k)
        dedup.append(k)
    return dedup


__all__ = [name for name in globals() if not name.startswith("__")]


