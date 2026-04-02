from __future__ import annotations

from .common import *

class DNDetector(Detector):
    def __init__(self, hs_db: HyperscanDB, enabled: bool = True):
        self.hs_db = hs_db
        self.enabled = enabled

    def run(self, ctx: DetectContext) -> None:
        if not self.enabled:
            ctx.set("DN", [])
            return
        t0 = _timing_now()
        results = self.hs_db.detect(ctx.text)
        detect_ms = _timing_ms(t0)
        t1 = _timing_now()
        existing = ctx.get("DN") or []
        merged = _finalize(existing + results)
        ctx.set("DN", merged[:ctx.max_results])
        _log_timing("dn.hyperscan", req_id=ctx.request_id, scan_ms=f"{detect_ms:.1f}", finalize_ms=f"{_timing_ms(t1):.1f}", matches=len(results))


class HSRegexDetector(Detector):
    """Hyperscan-first detector with optional Python verify-regex guard."""

    def __init__(
        self,
        out_key: str,
        hs_db: HyperscanDB,
        enabled: bool,
        max_match_len: int,
        verify_regexes: List[Pattern] | None = None,
        verify_window_chars: int = 2,
        supplement_regexes: List[Pattern] | None = None,
    ):
        self.out_key = out_key
        self.hs_db = hs_db
        self.enabled = enabled
        self.max_match_len = int(max_match_len)
        self.verify_regexes = verify_regexes or []
        self.verify_window_chars = max(0, int(verify_window_chars))
        self.supplement_regexes = supplement_regexes or []

    def _scan_raw(self, ctx: DetectContext) -> Tuple[List[dict], float, bool]:
        if hasattr(self.hs_db, "detect_all"):
            cache_key = f"hs_combined:{id(self.hs_db)}"
            bucketed = ctx.get_extra(cache_key)
            if bucketed is None:
                t0 = _timing_now()
                bucketed = self.hs_db.detect_all(ctx.text)
                scan_ms = _timing_ms(t0)
                ctx.set_extra(cache_key, bucketed)
                _log_timing(
                    "hs.combined",
                    req_id=ctx.request_id,
                    ms=f"{scan_ms:.1f}",
                    patterns=getattr(self.hs_db, "pattern_count", 0),
                    buckets=len(bucketed),
                )
            raw = bucketed.get(self.out_key, [])
            return raw, 0.0, True
        t0 = _timing_now()
        return self.hs_db.detect(ctx.text), _timing_ms(t0), False

    def _verify(self, text: str, it: dict) -> bool:
        if not self.verify_regexes:
            return True
        pid = it.get("_hs_id")
        if not isinstance(pid, int) or pid < 0 or pid >= len(self.verify_regexes):
            return True
        vr = self.verify_regexes[pid]
        s = int(it.get("start", 0))
        e = int(it.get("end", 0))
        ws = max(0, s - self.verify_window_chars)
        we = min(len(text), e + self.verify_window_chars)
        win = text[ws:we]
        rel_s = s - ws
        rel_e = e - ws
        for m in vr.finditer(win):
            if m.start() == rel_s and m.end() == rel_e:
                return True
        return False

    def _recover_verified_span(self, text: str, it: dict) -> Tuple[int, int] | None:
        """Recover accurate span when Hyperscan start offset is unreliable.

        Strategy:
        - Use the candidate end offset as anchor.
        - Search verify-regex in a small window around the end.
        - Prefer matches ending at the same char offset.
        """
        if not self.verify_regexes:
            return None
        pid = it.get("_hs_id")
        if not isinstance(pid, int) or pid < 0 or pid >= len(self.verify_regexes):
            return None
        vr = self.verify_regexes[pid]
        e = int(it.get("end", 0))
        if e <= 0:
            return None
        ws = max(0, e - max(self.max_match_len + 8, 32))
        we = min(len(text), e + self.verify_window_chars + 2)
        win = text[ws:we]
        best = None
        for m in vr.finditer(win):
            abs_s = ws + m.start()
            abs_e = ws + m.end()
            if abs_e == e:
                return (abs_s, abs_e)
            # nearest-by-end fallback
            dist = abs(abs_e - e)
            cand = (dist, abs_s, abs_e)
            if best is None or cand < best:
                best = cand
        if best is not None and best[0] <= 2:
            return (best[1], best[2])
        return None

    def _scan_supplement(self, ctx: DetectContext) -> List[dict]:
        if not self.supplement_regexes:
            return []
        return _scan_regex_cursor(
            ctx.text,
            self.supplement_regexes,
            max_results=ctx.max_results,
            max_len=self.max_match_len,
        )

    def run(self, ctx: DetectContext) -> None:
        if not self.enabled:
            ctx.set(self.out_key, [])
            return
        if self.out_key == "EML" and "@" not in ctx.text:
            ctx.set(self.out_key, [])
            _log_timing(
                "eml.hyperscan",
                req_id=ctx.request_id,
                scan_ms="0.0",
                verify_ms="0.0",
                finalize_ms="0.0",
                raw_matches=0,
                kept=0,
                shared_scan=0,
                skipped=1,
            )
            return
        raw, scan_ms, shared_scan = self._scan_raw(ctx)
        t0_verify = _timing_now()
        out: List[dict] = []
        for it in raw:
            s = int(it.get("start", 0))
            e = int(it.get("end", 0))
            if e <= s:
                continue
            if not self._verify(ctx.text, it):
                rec = self._recover_verified_span(ctx.text, it)
                if rec is None:
                    continue
                s, e = rec
                if e <= s:
                    continue
            if (e - s) > self.max_match_len:
                continue
            out.append({"start": s, "end": e, "matchString": ctx.text[s:e]})
            if len(out) >= ctx.max_results:
                break
        if self.supplement_regexes and len(out) < ctx.max_results:
            out.extend(self._scan_supplement(ctx))
        verify_ms = _timing_ms(t0_verify)
        t0_finalize = _timing_now()
        existing = ctx.get(self.out_key) or []
        ctx.set(self.out_key, _finalize(existing + out))
        _log_timing(
            f"{self.out_key.lower()}.hyperscan",
            req_id=ctx.request_id,
            scan_ms=f"{scan_ms:.1f}",
            verify_ms=f"{verify_ms:.1f}",
            finalize_ms=f"{_timing_ms(t0_finalize):.1f}",
            raw_matches=len(raw),
            kept=len(out),
            shared_scan=int(shared_scan),
        )


# ============================================================
# Regex detectors
# ============================================================


class RegexDetector(Detector):
    def __init__(
        self,
        out_key: str,
        regexes: List[Pattern],
        enabled: bool,
        max_match_len: int,
        split_newlines: bool = False,
    ):
        self.out_key = out_key
        self.regexes = regexes
        self.enabled = enabled
        self.max_match_len = max_match_len
        self.split_newlines = split_newlines

    def run(self, ctx: DetectContext) -> None:
        if not self.enabled:
            ctx.set(self.out_key, [])
            return
        t0_scan = _timing_now()
        items = _scan_regex_cursor(ctx.text, self.regexes, max_results=ctx.max_results, max_len=self.max_match_len)
        scan_ms = _timing_ms(t0_scan)
        t0_post = _timing_now()
        if self.split_newlines:
            split_items: List[dict] = []
            for it in items:
                s = int(it.get("start", 0))
                e = int(it.get("end", 0))
                raw = str(it.get("matchString", ""))
                if "\n" not in raw:
                    split_items.append(it)
                    continue
                rel = 0
                for part in raw.splitlines():
                    part = part.strip()
                    if not part:
                        rel += 1
                        continue
                    idx = raw.find(part, rel)
                    if idx < 0:
                        continue
                    ps = s + idx
                    pe = ps + len(part)
                    if pe <= e:
                        split_items.append({"start": ps, "end": pe, "matchString": ctx.text[ps:pe]})
                    rel = idx + len(part)
            items = split_items
        if self.out_key == "AN":
            cleaned: List[dict] = []
            for it in items:
                ms = str(it.get("matchString", ""))
                trimmed = _trim_an_suffix(ms)
                if not trimmed:
                    continue
                if len(trimmed) < 8:
                    continue
                s = int(it.get("start", 0))
                e = s + len(trimmed)
                if e <= s:
                    continue
                cleaned.append({"start": s, "end": e, "matchString": ctx.text[s:e]})
            items = cleaned
        elif self.out_key == "EML":
            items = [it for it in items if email_structure_valid(it.get("matchString", ""))]
        elif self.out_key == "SSN":
            items = [it for it in items if ssn_structure_valid(it.get("matchString", ""))]
        elif self.out_key == "IP":
            items = [it for it in items if ip_structure_valid(it.get("matchString", ""))]
        post_ms = _timing_ms(t0_post)
        t0_finalize = _timing_now()
        existing = ctx.get(self.out_key) or []
        ctx.set(self.out_key, _finalize(existing + items))
        _log_timing(
            f"{self.out_key.lower()}.regex",
            req_id=ctx.request_id,
            scan_ms=f"{scan_ms:.1f}",
            post_ms=f"{post_ms:.1f}",
            finalize_ms=f"{_timing_ms(t0_finalize):.1f}",
            matches=len(items),
        )


class SNDetector(Detector):
    def __init__(self, regexes: List[Pattern], enabled: bool, max_match_len: int, checksum_enabled: bool):
        self.regexes = regexes
        self.enabled = enabled
        self.max_match_len = max_match_len
        self.checksum_enabled = checksum_enabled

    def run(self, ctx: DetectContext) -> None:
        capture_invalid = _env_bool("PII_INCLUDE_SN_INVALID", False)
        if not self.enabled:
            ctx.set("SN", [])
            if capture_invalid:
                ctx.set("SN_INVALID", [])
            return

        t0_scan = _timing_now()
        raw = _scan_regex_cursor(ctx.text, self.regexes, max_results=ctx.max_results, max_len=self.max_match_len)
        raw = _finalize(raw)
        scan_ms = _timing_ms(t0_scan)

        if not self.checksum_enabled:
            existing_sn = ctx.get("SN") or []
            ctx.set("SN", _finalize(existing_sn + raw))
            if capture_invalid:
                existing_inv = ctx.get("SN_INVALID") or []
                ctx.set("SN_INVALID", _finalize(existing_inv))
            _log_timing("sn.regex", req_id=ctx.request_id, scan_ms=f"{scan_ms:.1f}", checksum_ms="0.0", valid=len(raw), invalid=0)
            return

        t0_checksum = _timing_now()
        sn_valid: List[dict] = []
        sn_invalid: List[dict] = []

        for it in raw:
            if rrn_checksum_valid(it["matchString"]):
                it["isValid"] = True
                sn_valid.append(it)
                continue
            if capture_invalid and rrn_structure_valid(it["matchString"]):
                it["isValid"] = False
                sn_invalid.append(it)

        existing_sn = ctx.get("SN") or []
        ctx.set("SN", _finalize(existing_sn + sn_valid))
        if capture_invalid:
            existing_inv = ctx.get("SN_INVALID") or []
            ctx.set("SN_INVALID", _finalize(existing_inv + sn_invalid))
        _log_timing(
            "sn.regex",
            req_id=ctx.request_id,
            scan_ms=f"{scan_ms:.1f}",
            checksum_ms=f"{_timing_ms(t0_checksum):.1f}",
            valid=len(sn_valid),
            invalid=len(sn_invalid),
        )


class SNHSDetector(HSRegexDetector):
    """SN detector using Hyperscan candidate scan + checksum split."""

    def __init__(
        self,
        hs_db: HyperscanDB,
        enabled: bool,
        max_match_len: int,
        checksum_enabled: bool,
        verify_regexes: List[Pattern] | None = None,
        verify_window_chars: int = 1,
        supplement_regexes: List[Pattern] | None = None,
    ):
        super().__init__(
            out_key="SN",
            hs_db=hs_db,
            enabled=enabled,
            max_match_len=max_match_len,
            verify_regexes=verify_regexes,
            verify_window_chars=verify_window_chars,
            supplement_regexes=supplement_regexes,
        )
        self.checksum_enabled = checksum_enabled

    def run(self, ctx: DetectContext) -> None:
        capture_invalid = _env_bool("PII_INCLUDE_SN_INVALID", False)
        if not self.enabled:
            ctx.set("SN", [])
            if capture_invalid:
                ctx.set("SN_INVALID", [])
            return

        raw, scan_ms, shared_scan = self._scan_raw(ctx)
        t0_verify = _timing_now()
        candidates: List[dict] = []
        for it in raw:
            s = int(it.get("start", 0))
            e = int(it.get("end", 0))
            if e <= s:
                continue
            if not self._verify(ctx.text, it):
                rec = self._recover_verified_span(ctx.text, it)
                if rec is None:
                    continue
                s, e = rec
                if e <= s:
                    continue
            if (e - s) > self.max_match_len:
                continue
            candidates.append({"start": s, "end": e, "matchString": ctx.text[s:e]})
            if len(candidates) >= ctx.max_results:
                break
        if self.supplement_regexes and len(candidates) < ctx.max_results:
            candidates.extend(self._scan_supplement(ctx))
        candidates = _finalize(candidates)
        verify_ms = _timing_ms(t0_verify)

        if not self.checksum_enabled:
            existing_sn = ctx.get("SN") or []
            ctx.set("SN", _finalize(existing_sn + candidates))
            if capture_invalid:
                existing_inv = ctx.get("SN_INVALID") or []
                ctx.set("SN_INVALID", _finalize(existing_inv))
            _log_timing("sn.hyperscan", req_id=ctx.request_id, scan_ms=f"{scan_ms:.1f}", verify_ms=f"{verify_ms:.1f}", checksum_ms="0.0", valid=len(candidates), invalid=0, shared_scan=int(shared_scan))
            return

        t0_checksum = _timing_now()
        sn_valid: List[dict] = []
        sn_invalid: List[dict] = []
        for it in candidates:
            if rrn_checksum_valid(it["matchString"]):
                it["isValid"] = True
                sn_valid.append(it)
                continue
            if capture_invalid and rrn_structure_valid(it["matchString"]):
                it["isValid"] = False
                sn_invalid.append(it)

        existing_sn = ctx.get("SN") or []
        ctx.set("SN", _finalize(existing_sn + sn_valid))
        if capture_invalid:
            existing_inv = ctx.get("SN_INVALID") or []
            ctx.set("SN_INVALID", _finalize(existing_inv + sn_invalid))
        _log_timing(
            "sn.hyperscan",
            req_id=ctx.request_id,
            scan_ms=f"{scan_ms:.1f}",
            verify_ms=f"{verify_ms:.1f}",
            checksum_ms=f"{_timing_ms(t0_checksum):.1f}",
            valid=len(sn_valid),
            invalid=len(sn_invalid),
            shared_scan=int(shared_scan),
        )


class ANHSDetector(HSRegexDetector):
    """AN detector using Hyperscan candidate scan + AN-specific cleanup."""

    def run(self, ctx: DetectContext) -> None:
        if not self.enabled:
            ctx.set("AN", [])
            return

        raw, scan_ms, shared_scan = self._scan_raw(ctx)
        t0_verify = _timing_now()
        out: List[dict] = []
        for it in raw:
            s = int(it.get("start", 0))
            e = int(it.get("end", 0))
            if e <= s:
                continue
            if not self._verify(ctx.text, it):
                rec = self._recover_verified_span(ctx.text, it)
                if rec is None:
                    continue
                s, e = rec
                if e <= s:
                    continue
            if (e - s) > self.max_match_len:
                continue
            out.append({"start": s, "end": e, "matchString": ctx.text[s:e]})
            if len(out) >= ctx.max_results:
                break
        if self.supplement_regexes and len(out) < ctx.max_results:
            out.extend(self._scan_supplement(ctx))

        verify_ms = _timing_ms(t0_verify)
        t0_clean = _timing_now()
        cleaned: List[dict] = []
        for it in _finalize(out):
            ms = str(it.get("matchString", ""))
            trimmed = _trim_an_suffix(ms)
            if not trimmed:
                continue
            if len(trimmed) < 8:
                continue
            s = int(it.get("start", 0))
            e = s + len(trimmed)
            if e <= s:
                continue
            cleaned.append({"start": s, "end": e, "matchString": ctx.text[s:e]})

        existing = ctx.get("AN") or []
        ctx.set("AN", _finalize(existing + cleaned))
        _log_timing(
            "an.hyperscan",
            req_id=ctx.request_id,
            scan_ms=f"{scan_ms:.1f}",
            verify_ms=f"{verify_ms:.1f}",
            clean_ms=f"{_timing_ms(t0_clean):.1f}",
            raw_matches=len(raw),
            kept=len(cleaned),
            shared_scan=int(shared_scan),
        )


# ============================================================
# Post filters (MN/BN)
# ============================================================


class MNPostFilter(Detector):
    def __init__(
        self,
        enabled: bool,
        boundary_digit_reject: bool,
        reject_overlap_with: List[str],
        intl_digits_len_min: int = 8,
        intl_digits_len_max: int = 15,
    ):
        self.enabled = enabled
        self.boundary_digit_reject = boundary_digit_reject
        self.reject_overlap_with = reject_overlap_with
        self.intl_digits_len_min = intl_digits_len_min
        self.intl_digits_len_max = intl_digits_len_max

    def run(self, ctx: DetectContext) -> None:
        if not self.enabled:
            return

        t0 = _timing_now()
        text = ctx.text
        mn_items = ctx.get("MN")

        reject_spans: List[Tuple[int, int]] = []
        for key in self.reject_overlap_with:
            reject_spans.extend(_span_list(ctx.get(key)))

        filtered: List[dict] = []
        for it in mn_items:
            s, e = it["start"], it["end"]

            if self.boundary_digit_reject:
                if e < len(text) and text[e].isdigit():
                    continue
                if s > 0 and text[s - 1].isdigit():
                    continue

            ms = str(it.get("matchString", "")).strip()
            if not phone_structure_valid(ms):
                continue
            if ms.startswith("+"):
                dig = _digits_only(ms)
                if not (self.intl_digits_len_min <= len(dig) <= self.intl_digits_len_max):
                    continue

            if reject_spans and any(_overlaps(s, e, rs, re_) for rs, re_ in reject_spans):
                continue

            filtered.append(it)

        ctx.set("MN", _finalize(filtered))
        _log_timing("mn.postfilter", req_id=ctx.request_id, ms=f"{_timing_ms(t0):.1f}", input=len(mn_items), kept=len(filtered))


class BNPostFilter(Detector):
    def __init__(
        self,
        enabled: bool,
        digits_len_min: int,
        digits_len_max: int,
        reject_if_phone_like: bool,
        boundary_digit_reject: bool,
        reject_overlap_with: List[str],
        phone_like_fullmatch_re: Pattern,
    ):
        self.enabled = enabled
        self.digits_len_min = digits_len_min
        self.digits_len_max = digits_len_max
        self.reject_if_phone_like = reject_if_phone_like
        self.boundary_digit_reject = boundary_digit_reject
        self.reject_overlap_with = reject_overlap_with
        self.phone_like_fullmatch_re = phone_like_fullmatch_re

    def run(self, ctx: DetectContext) -> None:
        if not self.enabled:
            return

        t0 = _timing_now()
        text = ctx.text
        bn_items = ctx.get("BN")

        reject_spans: List[Tuple[int, int]] = []
        for key in self.reject_overlap_with:
            reject_spans.extend(_span_list(ctx.get(key)))

        filtered: List[dict] = []
        for it in bn_items:
            s, e = it["start"], it["end"]

            if self.boundary_digit_reject:
                if e < len(text) and text[e].isdigit():
                    continue
                if s > 0 and text[s - 1].isdigit():
                    continue

            dig = _digits_only(it["matchString"])
            if not (self.digits_len_min <= len(dig) <= self.digits_len_max):
                continue

            if self.reject_if_phone_like:
                if self.phone_like_fullmatch_re.fullmatch(it["matchString"].strip()):
                    continue

            if reject_spans and any(_overlaps(s, e, rs, re_) for rs, re_ in reject_spans):
                continue

            filtered.append(it)

        ctx.set("BN", _finalize(_select_non_overlapping(_dedup_sorted(filtered))))
        _log_timing("bn.postfilter", req_id=ctx.request_id, ms=f"{_timing_ms(t0):.1f}", input=len(bn_items), kept=len(filtered))


# ============================================================
# Contextual post-filter (sentence-window based)
# ============================================================


