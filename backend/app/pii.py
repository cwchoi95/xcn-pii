from __future__ import annotations

"""Public PII API (compat layer).

main.py 에서는 이 모듈의 detect_all()을 사용합니다.

추가된 기능
-----------
- 룰셋 스위칭: detect_all(..., ruleset="strict")
- 룰 메타 반환: detect_with_meta(...)

환경변수
--------
- PII_RULES_DIR: 룰 디렉터리 (기본: app/rules)
- PII_RULESET:   기본 룰셋 이름 (기본: default)

주의
----
기존 호환을 위해 detect_all의 기본 시그니처는 유지하되,
선택 파라미터(ruleset)만 추가했습니다. 기존 호출 코드는 그대로 동작합니다.
"""

import os
import time
import logging
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple

from .pii_engine import detect as _detect
from .pii_engine import detect_with_meta as _detect_with_meta
from .pii_engine import detect_with_meta_uncached as _detect_with_meta_uncached

logger = logging.getLogger("pii.detect")


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


def _split_text_ranges(text: str, chunk_chars: int, overlap_chars: int) -> List[Tuple[int, int]]:
    n = len(text or "")
    if n <= 0:
        return []
    if n <= chunk_chars:
        return [(0, n)]

    # Safety: overlap must be smaller than chunk, otherwise cursor may not advance.
    overlap_chars = max(0, min(int(overlap_chars), int(chunk_chars) - 1))

    ranges: List[Tuple[int, int]] = []
    pos = 0
    max_iters = max(8, (n // max(1, chunk_chars)) * 4 + 8)
    iters = 0
    while pos < n:
        iters += 1
        if iters > max_iters:
            # Failsafe guard for unexpected non-progressing split params/input.
            break
        end = min(n, pos + chunk_chars)
        # Prefer paragraph boundary first
        if end < n:
            para = text.rfind("\n\n", pos, end)
            line = text.rfind("\n", pos, end)
            cut = para if para > pos else line
            if cut > pos + (chunk_chars // 3):
                end = cut + (2 if cut == para else 1)
        ranges.append((pos, end))
        if end >= n:
            break
        next_pos = max(0, end - overlap_chars)
        if next_pos <= pos:
            next_pos = end
        pos = next_pos
    return ranges


def _merge_chunk_result(
    merged: Dict[str, List[dict]],
    found: Dict[str, List[dict]],
    offset: int,
    per_type_limit: int,
) -> None:
    for key, items in (found or {}).items():
        if not isinstance(items, list):
            continue
        out = merged.setdefault(key, [])
        for it in items:
            if not isinstance(it, dict):
                continue
            x = dict(it)
            if isinstance(x.get("start"), int):
                x["start"] = int(x["start"]) + offset
            if isinstance(x.get("end"), int):
                x["end"] = int(x["end"]) + offset
            out.append(x)
        out.sort(key=lambda z: (int(z.get("start", 0)), int(z.get("end", 0))))
        # dedup and cap
        dedup: List[dict] = []
        seen = set()
        for x in out:
            sig = (x.get("start"), x.get("end"), x.get("matchString"))
            if sig in seen:
                continue
            seen.add(sig)
            dedup.append(x)
            if len(dedup) >= per_type_limit:
                break
        merged[key] = dedup


def detect_all(text: str, max_results_per_type: int = 500, *, ruleset: str | None = None):
    """PII detect (backward compatible).

    Parameters
    ----------
    text: str
        검사할 텍스트
    max_results_per_type: int
        타입별 최대 매치 개수
    ruleset: Optional[str]
        선택 룰셋. None이면 환경변수 PII_RULESET 사용
    """
    return _detect(text, max_results_per_type=max_results_per_type, ruleset=ruleset)


def detect_with_meta(text: str, max_results_per_type: int = 500, *, ruleset: str | None = None):
    """Detect and return (found, meta).

    For very long text, optionally split and process chunks in parallel.
    Environment flags:
    - PII_SPLIT_ENABLED (default: true)
    - PII_SPLIT_TEXT_LEN (default: 50000)
    - PII_SPLIT_CHUNK_CHARS (default: 50000)
    - PII_SPLIT_OVERLAP_CHARS (default: 2000)
    - PII_SPLIT_MAX_WORKERS (default: 1)
    - PII_SPLIT_MAX_RESULTS_PER_TYPE (default: 200)
    - PII_SPLIT_MAX_CHUNKS (default: 64)
    """
    src = text or ""
    if not src:
        return _detect_with_meta(src, max_results_per_type=max_results_per_type, ruleset=ruleset)

    trace = _env_bool("PII_TRACE_DETECT", False)
    slow_ms = max(100, _env_int("PII_TRACE_SLOW_MS", 1500))
    req_id = hashlib.md5(src.encode("utf-8", errors="ignore")).hexdigest()[:8]
    t0_all = time.perf_counter()

    split_enabled = _env_bool("PII_SPLIT_ENABLED", True)
    split_len = max(1, _env_int("PII_SPLIT_TEXT_LEN", 50000))
    chunk_chars = max(10000, _env_int("PII_SPLIT_CHUNK_CHARS", 50000))
    overlap_chars = max(0, _env_int("PII_SPLIT_OVERLAP_CHARS", 2000))
    workers = max(1, _env_int("PII_SPLIT_MAX_WORKERS", 1))
    split_cap = max(1, _env_int("PII_SPLIT_MAX_RESULTS_PER_TYPE", 200))
    split_max_chunks = max(1, _env_int("PII_SPLIT_MAX_CHUNKS", 64))

    if (not split_enabled) or (len(src) < split_len):
        found, meta = _detect_with_meta(src, max_results_per_type=max_results_per_type, ruleset=ruleset)
        if trace:
            dt = (time.perf_counter() - t0_all) * 1000.0
            logger.info(
                "[trace] req=%s mode=single len=%d ms=%.1f ruleset=%s max_results=%d",
                req_id, len(src), dt, ruleset or "default", int(max_results_per_type or 500)
            )
        return found, meta

    ranges = _split_text_ranges(src, chunk_chars=chunk_chars, overlap_chars=overlap_chars)
    if len(ranges) > split_max_chunks:
        ranges = ranges[:split_max_chunks]
    if trace:
        logger.info(
            "[trace] req=%s mode=split len=%d chunks=%d chunk_chars=%d overlap=%d workers=%d",
            req_id, len(src), len(ranges), chunk_chars, overlap_chars, workers
        )
    if len(ranges) <= 1:
        capped = min(int(max_results_per_type or 500), split_cap)
        found, meta = _detect_with_meta(src, max_results_per_type=capped, ruleset=ruleset)
        if trace:
            dt = (time.perf_counter() - t0_all) * 1000.0
            logger.info(
                "[trace] req=%s mode=single_fallback len=%d ms=%.1f ruleset=%s max_results=%d",
                req_id, len(src), dt, ruleset or "default", capped
            )
        return found, meta

    per_chunk_limit = min(int(max_results_per_type or 500), split_cap)
    merged: Dict[str, List[dict]] = {}
    meta = None

    # When workers=1, reuse cached engine path to avoid repeated pipeline/model setup per chunk.
    if workers <= 1:
        for i, (seg_start, seg_end) in enumerate(ranges, start=1):
            seg = src[seg_start:seg_end]
            t_chunk = time.perf_counter()
            found_chunk, meta_chunk = _detect_with_meta(seg, max_results_per_type=per_chunk_limit, ruleset=ruleset)
            dt_chunk = (time.perf_counter() - t_chunk) * 1000.0
            if meta is None:
                meta = meta_chunk
            _merge_chunk_result(merged, found_chunk, seg_start, per_type_limit=int(max_results_per_type or 500))
            if trace and (dt_chunk >= slow_ms or i <= 3):
                logger.info(
                    "[trace] req=%s chunk=%d/%d offset=%d len=%d ms=%.1f",
                    req_id, i, len(ranges), seg_start, len(seg), dt_chunk
                )
        if trace:
            dt = (time.perf_counter() - t0_all) * 1000.0
            logger.info("[trace] req=%s done mode=split_serial ms=%.1f", req_id, dt)
        return merged, (meta or {})

    def _run_one(seg_start: int, seg_end: int):
        seg = src[seg_start:seg_end]
        t_chunk = time.perf_counter()
        pair = _detect_with_meta_uncached(seg, max_results_per_type=per_chunk_limit, ruleset=ruleset)
        dt_chunk = (time.perf_counter() - t_chunk) * 1000.0
        return seg_start, (seg_end - seg_start), dt_chunk, pair

    with ThreadPoolExecutor(max_workers=min(workers, len(ranges))) as ex:
        futs = [ex.submit(_run_one, s, e) for s, e in ranges]
        for fut in as_completed(futs):
            seg_start, seg_len, dt_chunk, pair = fut.result()
            found_chunk, meta_chunk = pair
            if meta is None:
                meta = meta_chunk
            _merge_chunk_result(merged, found_chunk, seg_start, per_type_limit=int(max_results_per_type or 500))
            if trace and dt_chunk >= slow_ms:
                logger.info("[trace] req=%s chunk offset=%d len=%d detect_ms=%.1f", req_id, seg_start, seg_len, dt_chunk)

    if trace:
        dt = (time.perf_counter() - t0_all) * 1000.0
        logger.info("[trace] req=%s done mode=split_parallel ms=%.1f", req_id, dt)
    return merged, (meta or {})
