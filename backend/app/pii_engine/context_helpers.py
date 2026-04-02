from __future__ import annotations

from collections import defaultdict
from typing import Any, DefaultDict, Dict, List, Pattern, Tuple

from .common import *

def _split_sentences(text: str) -> List[Tuple[int, int]]:
    """Return list of (start, end) spans for simple sentence splitting.

    Splits on sentence-ending punctuation (., ?, !, 洹몃━怨??쒓? 臾몄옣遺?? and newlines.
    This is a light-weight splitter (no external deps) suitable for extracting
    a few surrounding sentences as context.
    """
    if not text:
        return []

    spans: List[Tuple[int, int]] = []
    # Use a regex to capture sentence chunks
    pattern = re.compile(r"[^.!?\n]+(?:[.!?]+|\n+|$)", re.MULTILINE | re.DOTALL)
    pos = 0
    for m in pattern.finditer(text):
        s = m.start()
        e = m.end()
        # normalize bounds
        if s < 0:
            s = 0
        if e > len(text):
            e = len(text)
        if e > s:
            spans.append((s, e))
    if not spans:
        spans = [(0, len(text))]
    return spans


def _get_context_window_from_spans(
    text: str,
    spans: List[Tuple[int, int]],
    start: int,
    end: int,
    window_sentences: int = 2,
) -> Tuple[str, int, int]:
    if not spans:
        return ("", 0, 0)

    idx_start = None
    idx_end = None
    for i, (s, e) in enumerate(spans):
        if idx_start is None and s <= start < e:
            idx_start = i
        if idx_end is None and s <= end <= e:
            idx_end = i
        if idx_start is not None and idx_end is not None:
            break

    if idx_start is None:
        for i, (s, e) in enumerate(spans):
            if start < e:
                idx_start = i
                break
    if idx_start is None:
        idx_start = 0

    if idx_end is None:
        for i in range(len(spans) - 1, -1, -1):
            s, e = spans[i]
            if end >= s:
                idx_end = i
                break
    if idx_end is None:
        idx_end = len(spans) - 1

    s_idx = max(0, idx_start - window_sentences)
    e_idx = min(len(spans) - 1, idx_end + window_sentences)

    abs_start = spans[s_idx][0]
    abs_end = spans[e_idx][1]
    return text[abs_start:abs_end], abs_start, abs_end


def _get_context_window(text: str, start: int, end: int, window_sentences: int = 2) -> Tuple[str, int, int]:
    """Return context snippet and absolute start/end covering window_sentences
    before the sentence that contains (start) and after the sentence that contains (end).
    Returns (snippet, abs_start, abs_end).
    """
    return _get_context_window_from_spans(
        text=text,
        spans=_split_sentences(text),
        start=start,
        end=end,
        window_sentences=window_sentences,
    )


def _clip_snippet_around_span(
    snippet: str,
    snippet_abs_start: int,
    match_start: int,
    match_end: int,
    max_chars: int,
) -> str:
    raw = str(snippet or "")
    limit = max(0, int(max_chars))
    if not raw or limit <= 0 or len(raw) <= limit:
        return raw
    rel_s = max(0, int(match_start) - int(snippet_abs_start))
    rel_e = max(rel_s, int(match_end) - int(snippet_abs_start))
    match_center = (rel_s + rel_e) // 2
    half = limit // 2
    clip_s = max(0, match_center - half)
    clip_e = min(len(raw), clip_s + limit)
    if clip_e - clip_s < limit:
        clip_s = max(0, clip_e - limit)
    return raw[clip_s:clip_e]


def _looks_like_header_cell(cell: str) -> bool:
    s = str(cell or "").strip()
    if not s:
        return False
    if len(s) > 64:
        return False
    if "@" in s:
        return False
    if not re.search(r"[A-Za-z가-힣]", s):
        return False
    digits = sum(1 for ch in s if ch.isdigit())
    if digits and (float(digits) / float(len(s))) >= 0.4:
        return False
    return True


def _split_cells_with_spans(line: str) -> List[Tuple[str, int, int]]:
    """Split a table-like row into cells and keep (text,start,end) spans.

    Priority:
    1) tab-separated
    2) multi-space separated (2+)
    3) single-space token fallback
    """
    s = str(line or "")
    if not s:
        return []

    out: List[Tuple[str, int, int]] = []
    if "\t" in s:
        start = 0
        for part in s.split("\t"):
            end = start + len(part)
            out.append((part.strip(), start, end))
            start = end + 1
        return out

    # Prefer explicit column gaps first.
    multi = list(re.finditer(r"\S(?:.*?\S)?(?=\s{2,}|$)", s))
    if len(multi) >= 2:
        for m in multi:
            out.append((m.group(0).strip(), m.start(), m.end()))
        return out

    # Fallback: single-space tokenization.
    for m in re.finditer(r"\S+", s):
        out.append((m.group(0).strip(), m.start(), m.end()))
    return out


def _extract_tabular_header_hint(
    text: str,
    start: int,
    end: int,
    max_lines_up: int = 64,
    max_distance_chars: int = 8000,
) -> str:
    """Return likely column header text for a tabular row (TSV-like copy from Excel).

    Finds the current line/column for span(start,end), then scans upward lines to find
    a header-like cell in the same column.
    """
    if not text:
        return ""
    s = max(0, min(int(start), len(text)))
    e = max(s, min(int(end), len(text)))
    line_start = text.rfind("\n", 0, s) + 1
    line_end = text.find("\n", e)
    if line_end < 0:
        line_end = len(text)
    row = text[line_start:line_end]
    row_cells = _split_cells_with_spans(row)
    if len(row_cells) < 2:
        return ""
    col_pos = max(0, min(s - line_start, len(row)))

    col_idx = 0
    found_idx = False
    for i, (_, cs, ce) in enumerate(row_cells):
        if cs <= col_pos <= ce:
            col_idx = i
            found_idx = True
            break
    if not found_idx:
        # nearest cell by start position
        best_i = 0
        best_d = None
        for i, (_, cs, _ce) in enumerate(row_cells):
            d = abs(cs - col_pos)
            if best_d is None or d < best_d:
                best_d = d
                best_i = i
        col_idx = best_i

    def _best_header_cell_by_pos(cells: List[Tuple[str, int, int]], pos: int) -> str:
        best = ""
        best_d = None
        for txt, cs, _ce in cells:
            if not _looks_like_header_cell(txt):
                continue
            d = abs(int(cs) - int(pos))
            if best_d is None or d < best_d:
                best_d = d
                best = txt
        return best

    scanned = 0
    cur_end = line_start - 1
    while cur_end >= 0 and scanned < max(1, int(max_lines_up)):
        if (line_start - cur_end) > max(1, int(max_distance_chars)):
            break
        prev_start = text.rfind("\n", 0, cur_end) + 1
        prev_line = text[prev_start:cur_end]
        prev_cells = _split_cells_with_spans(prev_line)
        if prev_cells:
            cand = ""
            if col_idx < len(prev_cells):
                cand = prev_cells[col_idx][0]
            # If direct index fails or is not header-like, fallback to nearest header cell.
            if (not cand) or (not _looks_like_header_cell(cand)):
                cand = _best_header_cell_by_pos(prev_cells, col_pos)
            if _looks_like_header_cell(cand):
                return cand
            # Final fallback for single-space-formatted tables:
            # return the whole line so label regex can still match header words.
            header_like_cells = [txt for txt, _s, _e in prev_cells if _looks_like_header_cell(txt)]
            if len(header_like_cells) >= 2:
                return str(prev_line).strip()
        cur_end = prev_start - 1
        scanned += 1
    return ""


def _extract_tabular_header_line_hint(
    text: str,
    start: int,
    end: int,
    label_res: List[Pattern],
    max_lines_up: int = 64,
    max_distance_chars: int = 8000,
) -> str:
    """Fallback: find a nearby table-like header line matching label patterns."""
    if not text or not label_res:
        return ""
    s = max(0, min(int(start), len(text)))
    e = max(s, min(int(end), len(text)))
    line_start = text.rfind("\n", 0, s) + 1
    _line_end = text.find("\n", e)
    if _line_end < 0:
        _line_end = len(text)

    scanned = 0
    cur_end = line_start - 1
    while cur_end >= 0 and scanned < max(1, int(max_lines_up)):
        if (line_start - cur_end) > max(1, int(max_distance_chars)):
            break
        prev_start = text.rfind("\n", 0, cur_end) + 1
        prev_line = text[prev_start:cur_end]
        cells = _split_cells_with_spans(prev_line)
        header_like = [txt for txt, _cs, _ce in cells if _looks_like_header_cell(txt)]
        if len(header_like) >= 2 and any(rx.search(prev_line) for rx in label_res):
            return str(prev_line).strip()
        cur_end = prev_start - 1
        scanned += 1
    return ""


def _line_bounds(text: str, pos: int) -> Tuple[int, int]:
    if not text:
        return (0, 0)
    p = max(0, min(int(pos), len(text)))
    s = text.rfind("\n", 0, p) + 1
    e = text.find("\n", p)
    if e < 0:
        e = len(text)
    return (s, e)


def _row_structure_signature(line: str) -> str:
    """Return a coarse structural signature for a row-like line."""
    s = str(line or "").strip()
    if not s:
        return ""
    toks = re.findall(r"\S+", s)
    sig: List[str] = []
    for t in toks:
        if t == ">":
            sig.append(">")
        elif "@" in t:
            sig.append("<EML>")
        elif re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", t):
            sig.append("<IP>")
        elif re.fullmatch(r"\d+(?:[-/]\d+)+", t):
            sig.append("<NUMH>")
        elif re.fullmatch(r"\d+", t):
            sig.append("<NUM>")
        elif re.search(r"[A-Za-z가-힣]", t):
            sig.append("<TXT>")
        else:
            sig.append("<ETC>")
    if len(sig) > 24:
        sig = sig[:24]
    return " ".join(sig)


def _token_count(line: str) -> int:
    return len(re.findall(r"\S+", str(line or "")))


def _find_matching_phrase(text: str, phrases: List[str]) -> str:
    s = _normalize_match_text(text)
    if not s or not phrases:
        return ""
    for p in phrases:
        pp = str(p or "").strip()
        if not pp:
            continue
        if _normalize_match_text(pp) in s:
            return pp
    return ""


def _line_index_at(text: str, pos: int) -> int:
    if not text:
        return 0
    p = max(0, min(int(pos), len(text)))
    return text.count("\n", 0, p)


def _compute_repeat_bonus_plan(
    text: str,
    items: List[dict],
    enabled: bool,
    min_count: int,
    unique_min: int,
    weight: float,
    require_structure: bool,
    structure_min_ratio: float,
    structure_min_count: int,
    structure_min_tokens: int,
    require_consecutive: bool,
    consecutive_min_count: int,
) -> Tuple[List[float], List[float]]:
    n = len(items or [])
    bonuses = [0.0] * n
    ratios = [0.0] * n
    if not enabled or weight <= 0.0 or n <= 0:
        return bonuses, ratios

    repeat_unique_count = len(
        {str(it.get("matchString") or "").strip().lower() for it in items if str(it.get("matchString") or "").strip()}
    )
    if repeat_unique_count < max(1, int(unique_min)):
        return bonuses, ratios

    sig_map: Dict[str, List[Tuple[int, int]]] = {}
    for i, it in enumerate(items):
        s = int(it.get("start", 0))
        ls, le = _line_bounds(text, s)
        line = text[ls:le]
        if _token_count(line) < max(1, int(structure_min_tokens)):
            continue
        sig = _row_structure_signature(line)
        if not sig:
            continue
        line_idx = _line_index_at(text, s)
        sig_map.setdefault(sig, []).append((i, line_idx))

    eligible_total = sum(len(v) for v in sig_map.values())
    if eligible_total <= 0:
        return bonuses, ratios

    min_cnt = max(1, int(min_count))
    consec_cnt = max(1, int(consecutive_min_count))
    for sig, pairs in sig_map.items():
        cnt = len(pairs)
        ratio = float(cnt) / float(eligible_total)
        qualifies = cnt >= min_cnt
        # When consecutive-run gating is enabled, the run condition itself is the
        # primary structure constraint. In that case skip global ratio gating.
        if require_structure and (not require_consecutive):
            qualifies = qualifies and cnt >= max(1, int(structure_min_count)) and ratio >= float(structure_min_ratio)
        if not qualifies:
            continue

        apply_indices: List[int] = []
        if require_consecutive:
            pairs_sorted = sorted(pairs, key=lambda x: x[1])
            run: List[Tuple[int, int]] = [pairs_sorted[0]]
            for p in pairs_sorted[1:]:
                if p[1] == run[-1][1] + 1:
                    run.append(p)
                else:
                    if len(run) >= consec_cnt:
                        apply_indices.extend([x[0] for x in run])
                    run = [p]
            if len(run) >= consec_cnt:
                apply_indices.extend([x[0] for x in run])
        else:
            apply_indices = [x[0] for x in pairs]

        for idx in apply_indices:
            bonuses[idx] = float(weight)
            ratios[idx] = ratio

    return bonuses, ratios


def _normalize_keyword_score(score: int, max_positive: int) -> float:
    """Normalize an integer keyword score to [-1.0, 1.0].

    `score` may be negative (due to non-PII indicators). `max_positive` is the
    number of PII indicator phrases used; we divide by that to get a relative
    score and clamp to [-1,1].
    """
    if max_positive <= 0:
        return 0.0
    val = float(score) / float(max_positive)
    if val > 1.0:
        val = 1.0
    if val < -1.0:
        val = -1.0
    return val


def _normalize_embed_score(diff: float) -> float:
    """Normalize embedding-based score (max_sim - non_sim) to [-1.0, 1.0].

    Since sims are cosine in [-1,1], the diff is in [-2,2]; divide by 2.
    """
    val = float(diff) / 2.0
    if val > 1.0:
        val = 1.0
    if val < -1.0:
        val = -1.0
    return val


def _match_value_counts(items: List[dict]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for it in items or []:
        key = _normalize_match_text(str(it.get("matchString") or "").strip())
        if not key:
            continue
        counts[key] = counts.get(key, 0) + 1
    return counts


def _digit_ratio(s: str) -> float:
    if not s:
        return 0.0
    digits = sum(1 for ch in s if ch.isdigit())
    return float(digits) / float(len(s))


def _rule_context_score(
    text: str,
    start: int,
    end: int,
    match_str: str,
    label_res: List[Pattern],
    label_window: int,
    label_weight: float,
    digit_min_ratio: float,
    digit_weight: float,
    header_hint: str = "",
    header_weight: float = 0.0,
) -> float:
    score = 0.0
    if label_res:
        w = max(0, int(label_window))
        s = max(0, start - w)
        e = min(len(text), end + w)
        window = text[s:e]
        if any(rx.search(window) for rx in label_res):
            score += float(label_weight)
        if header_hint and any(rx.search(header_hint) for rx in label_res):
            score += float(header_weight if header_weight > 0 else label_weight)

    if digit_weight:
        if _digit_ratio(match_str) >= float(digit_min_ratio):
            score += float(digit_weight)

    return score


__all__ = [name for name in globals() if not name.startswith("__")]


