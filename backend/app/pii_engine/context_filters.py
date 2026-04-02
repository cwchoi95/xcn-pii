from __future__ import annotations

from typing import Any, DefaultDict, Dict, List, Tuple

from .common import *
from .context_helpers import *

class ContextualPostFilter(Detector):
    def __init__(
        self,
        enabled: bool = True,
        target_keys: List[str] | None = None,
        window_sentences: int = 2,
        threshold: int = 1,
        debug: bool = False,
        indicator_phrases: List[str] | None = None,
        non_pii_phrases: List[str] | None = None,
        per_type: Dict[str, Dict[str, Any]] | None = None,
        hybrid_cfg: Dict[str, Any] | None = None,
    ):
        self.enabled = enabled
        self.target_keys = target_keys or ["SN", "SSN", "DN", "PN", "MN", "BN", "AN", "EML", "IP"]
        self.window_sentences = int(window_sentences)
        self.threshold = int(threshold)
        self.debug = bool(debug)
        self.per_type = per_type or {}
        self.hybrid_cfg = hybrid_cfg or {}
        self._label_res_cache: Dict[str, List[Pattern]] = {}
        self._bank_res_cache: Dict[str, List[Tuple[str, List[Pattern]]]] = {}

        # keyword lists for context scoring (configurable via rules)
        self.pii_indicators = indicator_phrases or [
            "sn",
            "resident",
            "phone",
            "mobile",
            "email",
            "account",
            "card",
            "passport",
            "bank",
            "address",
        ]
        self.non_pii_indicators = non_pii_phrases or ["example", "sample", "test", "dummy"]

    def _score_context(self, snippet: str, indicators: List[str], non_indicators: List[str]) -> int:
        s = _normalize_match_text(snippet)
        score = 0
        for kw in indicators:
            if _normalize_match_text(kw) in s:
                score += 1
        for kw in non_indicators:
            if _normalize_match_text(kw) in s:
                score -= 1
        return score

    def _get_type_cfg(self, key: str) -> Dict[str, Any]:
        cfg = {}
        if isinstance(self.per_type.get(key), dict):
            cfg.update(self.per_type[key])
        return cfg

    def _get_label_res(self, key: str, label_patterns: List[str]) -> List[Pattern]:
        cache_key = key + "::" + "|".join(label_patterns)
        if cache_key in self._label_res_cache:
            return self._label_res_cache[cache_key]
        res = []
        for p in label_patterns:
            try:
                res.append(re.compile(p))
            except re.error:
                continue
        self._label_res_cache[cache_key] = res
        return res

    def _get_bank_res(self, bank_patterns: List[Dict[str, Any]]) -> List[Tuple[str, List[Pattern]]]:
        cache_key = json.dumps(bank_patterns, ensure_ascii=False)
        if cache_key in self._bank_res_cache:
            return self._bank_res_cache[cache_key]
        out: List[Tuple[str, List[Pattern]]] = []
        for entry in bank_patterns:
            inst = str(entry.get("institution") or "").strip()
            patterns = entry.get("patterns") or []
            res: List[Pattern] = []
            for p in patterns:
                try:
                    res.append(re.compile(str(p)))
                except re.error:
                    continue
            if inst and res:
                out.append((inst, res))
        self._bank_res_cache[cache_key] = out
        return out

    def run(self, ctx: DetectContext) -> None:
        if not self.enabled:
            return

        t0_all = _timing_now()
        stage_log = _trace_stage_enabled()
        item_log = _trace_item_enabled()
        item_limit = _trace_item_limit()
        text_limit = _trace_text_limit()
        text = ctx.text or ""
        sentence_spans = _split_sentences(text)
        window_cache: Dict[Tuple[int, int, int], Tuple[str, int, int]] = {}
        for key in self.target_keys:
            t0_key = _timing_now()
            if key == "DN":
                detected_by = "hyperscan:dn"
            elif key in ("SN", "SN_INVALID"):
                detected_by = "regex:sn"
            else:
                detected_by = f"regex:{key.lower()}"
            type_cfg = self._get_type_cfg(key)
            indicators = type_cfg.get("indicator_phrases") or self.pii_indicators
            non_indicators = type_cfg.get("non_pii_phrases") or self.non_pii_indicators
            threshold = int(type_cfg.get("threshold", self.threshold))
            window = int(type_cfg.get("window_sentences", self.window_sentences))
            force_pass_phrases = [str(x).strip() for x in (type_cfg.get("force_pass_phrases") or []) if str(x).strip()]
            force_pass_scope = str(type_cfg.get("force_pass_scope") or "snippet").strip().lower()

            hybrid = dict(self.hybrid_cfg) if isinstance(self.hybrid_cfg, dict) else {}
            if isinstance(type_cfg.get("hybrid"), dict):
                hybrid.update(type_cfg["hybrid"])
            hybrid_enabled = bool(hybrid.get("enabled", False))
            type_hybrid = type_cfg.get("hybrid") if isinstance(type_cfg.get("hybrid"), dict) else {}
            if "label_patterns" in type_hybrid:
                label_patterns = type_hybrid.get("label_patterns") or []
            else:
                # Default: use this type's indicator phrases only (avoid cross-type leakage)
                label_patterns = [re.escape(str(x)) for x in indicators if str(x).strip()]
            label_res = self._get_label_res(key, label_patterns) if label_patterns else []
            label_window = int(hybrid.get("label_window", 12))
            label_weight = float(hybrid.get("label_weight", 0.3))
            table_header_enabled = bool(hybrid.get("table_header_enabled", True))
            table_header_line_fallback = bool(hybrid.get("table_header_line_fallback", True))
            table_header_weight = float(hybrid.get("table_header_weight", label_weight))
            table_header_max_lines = int(hybrid.get("table_header_max_lines", 64))
            table_header_max_distance = int(hybrid.get("table_header_max_distance_chars", 8000))
            repeat_boost_enabled = bool(hybrid.get("repeat_boost_enabled", False))
            repeat_boost_min_count = max(1, int(hybrid.get("repeat_boost_min_count", 5)))
            repeat_boost_weight = float(hybrid.get("repeat_boost_weight", 0.0))
            repeat_boost_unique_min = max(1, int(hybrid.get("repeat_boost_unique_min", 1)))
            repeat_boost_require_structure = bool(hybrid.get("repeat_boost_require_structure", False))
            repeat_boost_structure_min_ratio = float(hybrid.get("repeat_boost_structure_min_ratio", 0.6))
            repeat_boost_structure_min_count = max(1, int(hybrid.get("repeat_boost_structure_min_count", 2)))
            repeat_boost_structure_min_tokens = max(1, int(hybrid.get("repeat_boost_structure_min_tokens", 1)))
            repeat_boost_require_consecutive = bool(hybrid.get("repeat_boost_require_consecutive", False))
            repeat_boost_consecutive_min_count = max(1, int(hybrid.get("repeat_boost_consecutive_min_count", repeat_boost_min_count)))
            digit_min_ratio = float(hybrid.get("digit_min_ratio", 0.6))
            digit_weight = float(hybrid.get("digit_weight", 0.2))
            hybrid_accept = float(hybrid.get("accept_threshold", 0.2))
            bank_patterns = type_cfg.get("bank_patterns") or []
            bank_weight = float(type_cfg.get("bank_pattern_weight", 0.25))
            bank_res = self._get_bank_res(bank_patterns) if (key == "BN" and bank_patterns) else []

            items = ctx.get(key) or []
            value_counts = _match_value_counts(items)
            repeat_count = len(items)
            repeat_unique_count = len(
                {str(it.get("matchString") or "").strip().lower() for it in items if str(it.get("matchString") or "").strip()}
            )
            repeat_bonus_by_idx, repeat_ratio_by_idx = _compute_repeat_bonus_plan(
                text=text,
                items=items,
                enabled=repeat_boost_enabled,
                min_count=repeat_boost_min_count,
                unique_min=repeat_boost_unique_min,
                weight=repeat_boost_weight,
                require_structure=repeat_boost_require_structure,
                structure_min_ratio=repeat_boost_structure_min_ratio,
                structure_min_count=repeat_boost_structure_min_count,
                structure_min_tokens=repeat_boost_structure_min_tokens,
                require_consecutive=repeat_boost_require_consecutive,
                consecutive_min_count=repeat_boost_consecutive_min_count,
            )
            kept: List[dict] = []
            rejected: List[dict] = []
            if stage_log:
                logger.info(
                    "[stage][context][keyword] key=%s start items=%d threshold=%d window=%d hybrid=%s",
                    key,
                    len(items),
                    threshold,
                    window,
                    str(hybrid_enabled).lower(),
                )
            log_count = 0
            for idx, it in enumerate(items):
                s, e = it.get("start", 0), it.get("end", 0)
                cache_key = (int(s), int(e), int(window))
                cached = window_cache.get(cache_key)
                if cached is None:
                    cached = _get_context_window_from_spans(text, sentence_spans, s, e, window_sentences=window)
                    window_cache[cache_key] = cached
                snippet, abs_s, abs_e = cached
                # Score with this type's keyword sets only.
                score = self._score_context(snippet, indicators, non_indicators)
                score_norm = _normalize_keyword_score(score, max_positive=len(indicators))
                it["context_snippet"] = snippet
                it["context_score"] = score
                it["context_score_norm"] = score_norm
                it["context_window"] = window
                it["context_method"] = "keyword"
                if not it.get("detected_by"):
                    it["detected_by"] = detected_by
                repeat_same_match_min = int(type_cfg.get("repeat_same_match_force_pass_min_count", 0) or 0)
                match_key = _normalize_match_text(str(it.get("matchString") or "").strip())
                if repeat_same_match_min > 1 and value_counts.get(match_key, 0) >= repeat_same_match_min:
                    it["context_pass"] = True
                    it["context_accept_by"] = "repeat_same_match"
                    it["context_repeat_same_match_count"] = value_counts.get(match_key, 0)
                    kept.append(it)
                    continue
                scope_text = text if force_pass_scope == "text" else snippet
                force_phrase = _find_matching_phrase(scope_text, force_pass_phrases)
                if force_phrase:
                    it["context_pass"] = True
                    it["context_accept_by"] = "force_phrase"
                    it["context_force_pass_phrase"] = force_phrase
                    kept.append(it)
                    continue
                # Accept detection based on context score or hybrid score
                accept = score >= threshold
                it["context_accept_by"] = "keyword"
                bank_bonus = 0.0
                repeat_bonus = float(repeat_bonus_by_idx[idx]) if idx < len(repeat_bonus_by_idx) else 0.0
                if bank_res:
                    snippet_l = snippet.lower()
                    for inst, res_list in bank_res:
                        if inst and inst.lower() in snippet_l:
                            if any(r.fullmatch(str(it.get("matchString") or "").strip()) for r in res_list):
                                bank_bonus = bank_weight
                                break
                if hybrid_enabled:
                    base_hybrid = float(score_norm) + float(bank_bonus) + repeat_bonus
                    if base_hybrid >= hybrid_accept:
                        hybrid_score = base_hybrid
                        it["context_hybrid_score"] = hybrid_score
                        accept = True
                        it["context_accept_by"] = "hybrid_base"
                        if repeat_bonus > 0:
                            it["context_repeat_count"] = repeat_count
                            it["context_repeat_unique_count"] = repeat_unique_count
                            it["context_repeat_bonus"] = repeat_bonus
                            if idx < len(repeat_ratio_by_idx):
                                it["context_repeat_structure_ratio"] = repeat_ratio_by_idx[idx]
                        it["context_pass"] = True
                        kept.append(it)
                        continue
                    header_hint = ""
                    if table_header_enabled:
                        header_hint = _extract_tabular_header_hint(
                            text=text,
                            start=s,
                            end=e,
                            max_lines_up=table_header_max_lines,
                            max_distance_chars=table_header_max_distance,
                        )
                        if table_header_line_fallback:
                            header_line_hint = _extract_tabular_header_line_hint(
                                text=text,
                                start=s,
                                end=e,
                                label_res=label_res,
                                max_lines_up=table_header_max_lines,
                                max_distance_chars=table_header_max_distance,
                            )
                            if header_line_hint:
                                cell_matches = bool(header_hint) and any(rx.search(header_hint) for rx in label_res)
                                if (not header_hint) or (not cell_matches):
                                    header_hint = header_line_hint
                    if header_hint:
                        it["context_header_hint"] = header_hint
                    rule_score = _rule_context_score(
                        text=text,
                        start=s,
                        end=e,
                        match_str=str(it.get("matchString") or ""),
                        label_res=label_res,
                        label_window=label_window,
                        label_weight=label_weight,
                        header_hint=header_hint,
                        header_weight=table_header_weight,
                        digit_min_ratio=digit_min_ratio,
                        digit_weight=digit_weight,
                    )
                    hybrid_score = float(score_norm) + float(rule_score) + float(bank_bonus) + repeat_bonus
                    it["context_hybrid_score"] = hybrid_score
                    if repeat_bonus > 0:
                        it["context_repeat_count"] = repeat_count
                        it["context_repeat_unique_count"] = repeat_unique_count
                        it["context_repeat_bonus"] = repeat_bonus
                        if idx < len(repeat_ratio_by_idx):
                            it["context_repeat_structure_ratio"] = repeat_ratio_by_idx[idx]
                    accept = hybrid_score >= hybrid_accept
                    it["context_accept_by"] = "hybrid"
                elif bank_bonus > 0:
                    accept = True
                    it["context_accept_by"] = "bank_pattern"
                it["context_pass"] = bool(accept)
                if accept:
                    kept.append(it)
                else:
                    rejected.append(it)

                if item_log and log_count < item_limit:
                    logger.info(
                        "[stage][context][keyword][item]\n"
                        "  key=%s span=%d:%d match=%s\n"
                        "  score: raw=%s norm=%.3f rule=%.3f bank=%.3f hybrid=%s\n"
                        "  decision: pass=%s by=%s\n"
                        "  snippet=%s",
                        key,
                        int(s),
                        int(e),
                        _mask_match(str(it.get("matchString") or "")),
                        str(score),
                        float(score_norm),
                        float(rule_score if hybrid_enabled else 0.0),
                        float(bank_bonus),
                        str(it.get("context_hybrid_score")) if "context_hybrid_score" in it else "n/a",
                        str(bool(accept)).lower(),
                        str(it.get("context_accept_by") or "unknown"),
                        _truncate(snippet.replace("\n", " "), text_limit),
                    )
                    log_count += 1

                if self.debug:
                    # record debug entry in ctx.out for programmatic access
                    dbg = {
                        "key": key,
                        "matchString": it.get("matchString"),
                        "start": s,
                        "end": e,
                        "score": score,
                        "score_norm": score_norm,
                        "accept": accept,
                        "method": "keyword",
                        "snippet": snippet[:200] + ("..." if len(snippet) > 200 else ""),
                    }
                    if "context_hybrid_score" in it:
                        dbg["hybrid_score"] = it.get("context_hybrid_score")
                    lst = ctx.out.setdefault("__context_debug", [])
                    lst.append(dbg)

            ctx.set(key, _finalize(kept))
            ctx.set(f"{key}_CTX_REJECTED", _finalize(rejected))
            _log_timing(
                "context.keyword.key",
                req_id=ctx.request_id,
                key=key,
                ms=f"{_timing_ms(t0_key):.1f}",
                input=len(items),
                kept=len(kept),
                rejected=len(rejected),
            )
            if stage_log:
                logger.info(
                    "[stage][context][keyword] key=%s done kept=%d rejected=%d",
                    key,
                    len(kept),
                    len(rejected),
                )
        _log_timing("context.keyword.total", req_id=ctx.request_id, ms=f"{_timing_ms(t0_all):.1f}", keys=len(self.target_keys))


class ContextualLLMPostFilter(Detector):
    """Contextual filter using local sentence-transformers embeddings for semantic matching.

    This class lazily loads a small, fast local model (default `sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2`) and
    computes cosine similarity between the context snippet and a list of PII indicator
    phrases. If the maximum similarity exceeds `sim_threshold`, the detection is kept.
    """

    def __init__(
        self,
        enabled: bool = True,
        target_keys: List[str] | None = None,
        window_sentences: int = 2,
        sim_threshold: float = 0.55,
        model_name: str = "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2",
        debug: bool = False,
        embedder: Any | None = None,
        indicator_phrases: List[str] | None = None,
        non_pii_phrases: List[str] | None = None,
        keyword_threshold: int = 1,
        cache_size: int = 1024,
        per_type: Dict[str, Dict[str, Any]] | None = None,
        hybrid_cfg: Dict[str, Any] | None = None,
    ):
        self.enabled = enabled
        self.target_keys = target_keys or ["SN", "SSN", "DN", "PN", "MN", "BN", "AN", "EML", "IP"]
        self.window_sentences = int(window_sentences)
        self.sim_threshold = float(sim_threshold)
        self.model_name = str(model_name)
        self.debug = bool(debug)
        self.embedder = embedder
        self.keyword_threshold = int(keyword_threshold)
        self.cache_size = int(cache_size)
        self.embed_max_chars = max(0, _env_int("PII_CONTEXT_EMBED_MAX_CHARS", 256))
        self._embed_cache: Dict[str, Any] = {}
        self.per_type = per_type or {}
        self.hybrid_cfg = hybrid_cfg or {}
        self._label_res_cache: Dict[str, List[Pattern]] = {}
        self._bank_res_cache: Dict[str, List[Tuple[str, List[Pattern]]]] = {}

        self.model = None
        self._indicator_phrases = indicator_phrases or [
            "sn",
            "resident",
            "phone",
            "mobile",
            "email",
            "account",
            "card",
            "passport",
            "bank",
            "address",
        ]
        self._non_pii_phrases = non_pii_phrases or ["example", "sample", "test", "dummy"]
        self._indicator_emb = None
        self._non_pii_emb = None
        self._type_indicator_emb: Dict[str, Any] = {}
        self._type_non_pii_emb: Dict[str, Any] = {}
        self.force_keyword_mode = False

    def _get_type_cfg(self, key: str) -> Dict[str, Any]:
        cfg = {}
        if isinstance(self.per_type.get(key), dict):
            cfg.update(self.per_type[key])
        return cfg

    def _get_label_res(self, key: str, label_patterns: List[str]) -> List[Pattern]:
        cache_key = key + "::" + "|".join(label_patterns)
        if cache_key in self._label_res_cache:
            return self._label_res_cache[cache_key]
        res = []
        for p in label_patterns:
            try:
                res.append(re.compile(p))
            except re.error:
                continue
        self._label_res_cache[cache_key] = res
        return res

    def _get_bank_res(self, bank_patterns: List[Dict[str, Any]]) -> List[Tuple[str, List[Pattern]]]:
        cache_key = json.dumps(bank_patterns, ensure_ascii=False)
        if cache_key in self._bank_res_cache:
            return self._bank_res_cache[cache_key]
        out: List[Tuple[str, List[Pattern]]] = []
        for entry in bank_patterns:
            inst = str(entry.get("institution") or "").strip()
            patterns = entry.get("patterns") or []
            res: List[Pattern] = []
            for p in patterns:
                try:
                    res.append(re.compile(str(p)))
                except re.error:
                    continue
            if inst and res:
                out.append((inst, res))
        self._bank_res_cache[cache_key] = out
        return out

    def _ensure_type_embeddings(self, key: str, indicators: List[str], non_indicators: List[str]) -> Tuple[Any, Any]:
        if key in self._type_indicator_emb and key in self._type_non_pii_emb:
            return self._type_indicator_emb[key], self._type_non_pii_emb[key]

        if self.model is None:
            return None, None

        phrases = [_normalize_match_text(x) for x in (indicators + non_indicators)]
        if hasattr(self.model, "encode"):
            embs = self.model.encode(phrases, convert_to_numpy=True, normalize_embeddings=True)
        else:
            embs = self.model.encode(phrases)

        import numpy as _np
        embs = _np.asarray(embs)
        ind = _np.asarray(embs[: len(indicators)])
        non = _np.asarray(embs[len(indicators) :])
        self._type_indicator_emb[key] = ind
        self._type_non_pii_emb[key] = non
        return ind, non

    def _ensure_model(self):
        if self.model is not None:
            return
        # If an external embedder is provided, use it.
        if self.embedder is not None:
            self.model = self.embedder
            phrases = [_normalize_match_text(x) for x in (self._indicator_phrases + self._non_pii_phrases)]
            embs = self.model.encode(phrases)
            import numpy as _np
            embs = _np.asarray(embs)
            self._indicator_emb = _np.asarray(embs[: len(self._indicator_phrases)])
            self._non_pii_emb = _np.asarray(embs[len(self._indicator_phrases) :])
            return

        try:
            from sentence_transformers import SentenceTransformer
            import numpy as np
        except Exception:
            self.model = None
            return

        self.model = SentenceTransformer(self.model_name)
        # compute normalized embeddings for indicator phrases
        phrases = [_normalize_match_text(x) for x in (self._indicator_phrases + self._non_pii_phrases)]
        embs = self.model.encode(phrases, convert_to_numpy=True, normalize_embeddings=True)
        import numpy as _np
        self._indicator_emb = _np.asarray(embs[: len(self._indicator_phrases)])
        self._non_pii_emb = _np.asarray(embs[len(self._indicator_phrases) :])

    def warmup(self) -> Dict[str, int]:
        self._ensure_model()
        if self.model is None or self._indicator_emb is None:
            return {"types": 0}
        warmed = 0
        for key in self.target_keys:
            type_cfg = self._get_type_cfg(key)
            indicators = type_cfg.get("indicator_phrases") or self._indicator_phrases
            non_indicators = type_cfg.get("non_pii_phrases") or self._non_pii_phrases
            ind_emb, _ = self._ensure_type_embeddings(key, indicators, non_indicators)
            if ind_emb is not None:
                warmed += 1
        return {"types": warmed}

    def run(self, ctx: DetectContext) -> None:
        if not self.enabled:
            return

        t0_all = _timing_now()
        stage_log = _trace_stage_enabled()
        item_log = _trace_item_enabled()
        item_limit = _trace_item_limit()
        text_limit = _trace_text_limit()
        if self.force_keyword_mode:
            kw = ContextualPostFilter(
                enabled=True,
                target_keys=self.target_keys,
                window_sentences=self.window_sentences,
                threshold=self.keyword_threshold,
                indicator_phrases=self._indicator_phrases,
                non_pii_phrases=self._non_pii_phrases,
                per_type=self.per_type,
                hybrid_cfg=self.hybrid_cfg,
            )
            kw.run(ctx)
            _log_timing("context.embed.total", req_id=ctx.request_id, ms=f"{_timing_ms(t0_all):.1f}", mode="forced_keyword")
            return

        self._ensure_model()
        if self.model is None or self._indicator_emb is None:
            # fallback to keyword filter if model unavailable
            kw = ContextualPostFilter(
                enabled=True,
                target_keys=self.target_keys,
                window_sentences=self.window_sentences,
                threshold=self.keyword_threshold,
                indicator_phrases=self._indicator_phrases,
                non_pii_phrases=self._non_pii_phrases,
                per_type=self.per_type,
                hybrid_cfg=self.hybrid_cfg,
            )
            kw.run(ctx)
            _log_timing("context.embed.total", req_id=ctx.request_id, ms=f"{_timing_ms(t0_all):.1f}", mode="fallback_keyword")
            return

        import numpy as _np

        text = ctx.text or ""
        sentence_spans = _split_sentences(text)
        window_cache: Dict[Tuple[int, int, int], Tuple[str, int, int]] = {}
        prepared_by_key: Dict[str, List[Tuple[dict, int, int, str]]] = {}
        all_missing_snippets: List[str] = []
        all_missing_seen: set[str] = set()
        for key in self.target_keys:
            type_cfg = self._get_type_cfg(key)
            window = int(type_cfg.get("window_sentences", self.window_sentences))
            embed_max_chars = int(type_cfg.get("embed_max_chars", self.embed_max_chars))
            items = ctx.get(key) or []
            meta: List[Tuple[dict, int, int, str]] = []
            for it in items:
                s, e = it.get("start", 0), it.get("end", 0)
                cache_key = (int(s), int(e), int(window))
                cached = window_cache.get(cache_key)
                if cached is None:
                    cached = _get_context_window_from_spans(text, sentence_spans, s, e, window_sentences=window)
                    window_cache[cache_key] = cached
                snippet, abs_s, abs_e = cached
                snippet = _clip_snippet_around_span(
                    snippet=snippet,
                    snippet_abs_start=abs_s,
                    match_start=s,
                    match_end=e,
                    max_chars=embed_max_chars,
                )
                if not snippet.strip():
                    continue
                meta.append((it, s, e, snippet))
                if snippet not in self._embed_cache and snippet not in all_missing_seen:
                    all_missing_seen.add(snippet)
                    all_missing_snippets.append(snippet)
            prepared_by_key[key] = meta

        total_encode_ms = 0.0
        if all_missing_snippets:
            t0_encode_all = _timing_now()
            uniq_norm = [_normalize_match_text(snip) for snip in all_missing_snippets]
            if hasattr(self.model, "encode"):
                new_vecs = self.model.encode(uniq_norm, convert_to_numpy=True, normalize_embeddings=True)
            else:
                new_vecs = self.model.encode(uniq_norm)
            total_encode_ms = _timing_ms(t0_encode_all)
            for snip, vec in zip(all_missing_snippets, new_vecs):
                self._embed_cache[snip] = vec
                if self.cache_size > 0 and len(self._embed_cache) > self.cache_size:
                    first_key = next(iter(self._embed_cache.keys()))
                    self._embed_cache.pop(first_key, None)

        for key in self.target_keys:
            t0_key = _timing_now()
            if key == "DN":
                detected_by = "hyperscan:dn"
            elif key in ("SN", "SN_INVALID"):
                detected_by = "regex:sn"
            else:
                detected_by = f"regex:{key.lower()}"
            type_cfg = self._get_type_cfg(key)
            indicators = type_cfg.get("indicator_phrases") or self._indicator_phrases
            non_indicators = type_cfg.get("non_pii_phrases") or self._non_pii_phrases
            window = int(type_cfg.get("window_sentences", self.window_sentences))
            sim_threshold = float(type_cfg.get("sim_threshold", self.sim_threshold))
            force_pass_phrases = [str(x).strip() for x in (type_cfg.get("force_pass_phrases") or []) if str(x).strip()]
            force_pass_scope = str(type_cfg.get("force_pass_scope") or "snippet").strip().lower()

            hybrid = dict(self.hybrid_cfg) if isinstance(self.hybrid_cfg, dict) else {}
            if isinstance(type_cfg.get("hybrid"), dict):
                hybrid.update(type_cfg["hybrid"])
            hybrid_enabled = bool(hybrid.get("enabled", False))
            type_hybrid = type_cfg.get("hybrid") if isinstance(type_cfg.get("hybrid"), dict) else {}
            if "label_patterns" in type_hybrid:
                label_patterns = type_hybrid.get("label_patterns") or []
            else:
                # Default: use this type's indicator phrases only (avoid cross-type leakage)
                label_patterns = [re.escape(str(x)) for x in indicators if str(x).strip()]
            label_res = self._get_label_res(key, label_patterns) if label_patterns else []
            label_window = int(hybrid.get("label_window", 12))
            label_weight = float(hybrid.get("label_weight", 0.3))
            table_header_enabled = bool(hybrid.get("table_header_enabled", True))
            table_header_line_fallback = bool(hybrid.get("table_header_line_fallback", True))
            table_header_weight = float(hybrid.get("table_header_weight", label_weight))
            table_header_max_lines = int(hybrid.get("table_header_max_lines", 64))
            table_header_max_distance = int(hybrid.get("table_header_max_distance_chars", 8000))
            repeat_boost_enabled = bool(hybrid.get("repeat_boost_enabled", False))
            repeat_boost_min_count = max(1, int(hybrid.get("repeat_boost_min_count", 5)))
            repeat_boost_weight = float(hybrid.get("repeat_boost_weight", 0.0))
            repeat_boost_unique_min = max(1, int(hybrid.get("repeat_boost_unique_min", 1)))
            repeat_boost_require_structure = bool(hybrid.get("repeat_boost_require_structure", False))
            repeat_boost_structure_min_ratio = float(hybrid.get("repeat_boost_structure_min_ratio", 0.6))
            repeat_boost_structure_min_count = max(1, int(hybrid.get("repeat_boost_structure_min_count", 2)))
            repeat_boost_structure_min_tokens = max(1, int(hybrid.get("repeat_boost_structure_min_tokens", 1)))
            repeat_boost_require_consecutive = bool(hybrid.get("repeat_boost_require_consecutive", False))
            repeat_boost_consecutive_min_count = max(1, int(hybrid.get("repeat_boost_consecutive_min_count", repeat_boost_min_count)))
            digit_min_ratio = float(hybrid.get("digit_min_ratio", 0.6))
            digit_weight = float(hybrid.get("digit_weight", 0.2))
            hybrid_accept = float(hybrid.get("accept_threshold", 0.2))
            bank_patterns = type_cfg.get("bank_patterns") or []
            bank_weight = float(type_cfg.get("bank_pattern_weight", 0.25))
            bank_res = self._get_bank_res(bank_patterns) if (key == "BN" and bank_patterns) else []

            ind_emb, non_emb = self._ensure_type_embeddings(key, indicators, non_indicators)
            if ind_emb is None:
                _log_timing("context.embed.key", req_id=ctx.request_id, key=key, ms=f"{_timing_ms(t0_key):.1f}", input=0, kept=0, rejected=0, mode="missing_embeddings")
                continue

            items = ctx.get(key) or []
            value_counts = _match_value_counts(items)
            repeat_count = len(items)
            repeat_unique_count = len(
                {str(it.get("matchString") or "").strip().lower() for it in items if str(it.get("matchString") or "").strip()}
            )
            repeat_bonus_by_idx, repeat_ratio_by_idx = _compute_repeat_bonus_plan(
                text=text,
                items=items,
                enabled=repeat_boost_enabled,
                min_count=repeat_boost_min_count,
                unique_min=repeat_boost_unique_min,
                weight=repeat_boost_weight,
                require_structure=repeat_boost_require_structure,
                structure_min_ratio=repeat_boost_structure_min_ratio,
                structure_min_count=repeat_boost_structure_min_count,
                structure_min_tokens=repeat_boost_structure_min_tokens,
                require_consecutive=repeat_boost_require_consecutive,
                consecutive_min_count=repeat_boost_consecutive_min_count,
            )
            kept: List[dict] = []
            rejected: List[dict] = []
            header_hint_cache: Dict[Tuple[int, int], str] = {}
            rule_score_cache: Dict[Tuple[int, int, str, str], float] = {}
            if stage_log:
                logger.info(
                    "[stage][context][embed] key=%s start items=%d sim_threshold=%.3f window=%d hybrid=%s",
                    key,
                    len(items),
                    sim_threshold,
                    window,
                    str(hybrid_enabled).lower(),
                )
            meta = prepared_by_key.get(key) or []
            if not meta:
                ctx.set(key, _finalize(kept))
                ctx.set(f"{key}_CTX_REJECTED", _finalize(rejected))
                continue

            snippet_score_cache: Dict[str, Tuple[float, float, float]] = {}
            for snip in {m[3] for m in meta}:
                vec = self._embed_cache.get(snip)
                if vec is None:
                    continue
                sims = _np.dot(ind_emb, vec)
                max_sim = float(sims.max()) if sims.size else 0.0
                non_sim = float(_np.dot(non_emb, vec).max()) if non_emb.size else 0.0
                score = max_sim - non_sim
                snippet_score_cache[snip] = (max_sim, non_sim, score)

            for idx, (it, s, e, snippet) in enumerate(meta):
                snippet_score = snippet_score_cache.get(snippet)
                if snippet_score is None:
                    continue
                rule_score = 0.0
                max_sim, non_sim, score = snippet_score
                score_norm = _normalize_embed_score(score)
                it["context_snippet"] = snippet
                it["context_score"] = score
                it["context_score_norm"] = score_norm
                it["context_window"] = window
                it["context_method"] = "embed"
                if not it.get("detected_by"):
                    it["detected_by"] = detected_by
                repeat_same_match_min = int(type_cfg.get("repeat_same_match_force_pass_min_count", 0) or 0)
                match_key = _normalize_match_text(str(it.get("matchString") or "").strip())
                if repeat_same_match_min > 1 and value_counts.get(match_key, 0) >= repeat_same_match_min:
                    it["context_pass"] = True
                    it["context_accept_by"] = "repeat_same_match"
                    it["context_repeat_same_match_count"] = value_counts.get(match_key, 0)
                    kept.append(it)
                    continue
                scope_text = text if force_pass_scope == "text" else snippet
                force_phrase = _find_matching_phrase(scope_text, force_pass_phrases)
                if force_phrase:
                    it["context_pass"] = True
                    it["context_accept_by"] = "force_phrase"
                    it["context_force_pass_phrase"] = force_phrase
                    kept.append(it)
                    continue
                accept = score >= sim_threshold
                it["context_accept_by"] = "embed"
                bank_bonus = 0.0
                repeat_bonus = float(repeat_bonus_by_idx[idx]) if idx < len(repeat_bonus_by_idx) else 0.0
                if bank_res:
                    snippet_l = snippet.lower()
                    for inst, res_list in bank_res:
                        if inst and inst.lower() in snippet_l:
                            if any(r.fullmatch(str(it.get("matchString") or "").strip()) for r in res_list):
                                bank_bonus = bank_weight
                                break
                if hybrid_enabled:
                    base_hybrid = float(score_norm) + float(bank_bonus) + repeat_bonus
                    if base_hybrid >= hybrid_accept:
                        hybrid_score = base_hybrid
                        it["context_hybrid_score"] = hybrid_score
                        accept = True
                        it["context_accept_by"] = "hybrid_base"
                        if repeat_bonus > 0:
                            it["context_repeat_count"] = repeat_count
                            it["context_repeat_unique_count"] = repeat_unique_count
                            it["context_repeat_bonus"] = repeat_bonus
                            if idx < len(repeat_ratio_by_idx):
                                it["context_repeat_structure_ratio"] = repeat_ratio_by_idx[idx]
                        it["context_pass"] = True
                        kept.append(it)
                        continue
                    header_key = (int(s), int(e))
                    header_hint = header_hint_cache.get(header_key, "")
                    if header_key not in header_hint_cache:
                        if table_header_enabled:
                            header_hint = _extract_tabular_header_hint(
                                text=text,
                                start=s,
                                end=e,
                                max_lines_up=table_header_max_lines,
                                max_distance_chars=table_header_max_distance,
                            )
                            if table_header_line_fallback:
                                header_line_hint = _extract_tabular_header_line_hint(
                                    text=text,
                                    start=s,
                                    end=e,
                                    label_res=label_res,
                                    max_lines_up=table_header_max_lines,
                                    max_distance_chars=table_header_max_distance,
                                )
                                if header_line_hint:
                                    cell_matches = bool(header_hint) and any(rx.search(header_hint) for rx in label_res)
                                    if (not header_hint) or (not cell_matches):
                                        header_hint = header_line_hint
                        header_hint_cache[header_key] = header_hint
                    if header_hint:
                        it["context_header_hint"] = header_hint
                    rule_key = (int(s), int(e), str(it.get("matchString") or ""), header_hint)
                    rule_score = rule_score_cache.get(rule_key, 0.0)
                    if rule_key not in rule_score_cache:
                        rule_score = _rule_context_score(
                            text=text,
                            start=s,
                            end=e,
                            match_str=str(it.get("matchString") or ""),
                            label_res=label_res,
                            label_window=label_window,
                            label_weight=label_weight,
                            header_hint=header_hint,
                            header_weight=table_header_weight,
                            digit_min_ratio=digit_min_ratio,
                            digit_weight=digit_weight,
                        )
                        rule_score_cache[rule_key] = rule_score
                    hybrid_score = float(score_norm) + float(rule_score) + float(bank_bonus) + repeat_bonus
                    it["context_hybrid_score"] = hybrid_score
                    if repeat_bonus > 0:
                        it["context_repeat_count"] = repeat_count
                        it["context_repeat_unique_count"] = repeat_unique_count
                        it["context_repeat_bonus"] = repeat_bonus
                        if idx < len(repeat_ratio_by_idx):
                            it["context_repeat_structure_ratio"] = repeat_ratio_by_idx[idx]
                    accept = hybrid_score >= hybrid_accept
                    it["context_accept_by"] = "hybrid"
                elif bank_bonus > 0:
                    accept = True
                    it["context_accept_by"] = "bank_pattern"
                it["context_pass"] = bool(accept)
                if accept:
                    kept.append(it)
                else:
                    rejected.append(it)
                if item_log and (len(kept) + len(rejected)) <= item_limit:
                    logger.info(
                        "[stage][context][embed][item]\n"
                        "  key=%s span=%d:%d match=%s\n"
                        "  sim: max=%.3f non=%.3f score=%.3f norm=%.3f\n"
                        "  bonus: rule=%.3f bank=%.3f hybrid=%s\n"
                        "  decision: pass=%s by=%s\n"
                        "  snippet=%s",
                        key,
                        int(s),
                        int(e),
                        _mask_match(str(it.get("matchString") or "")),
                        max_sim,
                        non_sim,
                        float(score),
                        float(score_norm),
                        float(rule_score),
                        float(bank_bonus),
                        str(it.get("context_hybrid_score")) if "context_hybrid_score" in it else "n/a",
                        str(bool(accept)).lower(),
                        str(it.get("context_accept_by") or "unknown"),
                        _truncate(snippet.replace("\n", " "), text_limit),
                    )
                if self.debug:
                    dbg = {
                        "key": key,
                        "matchString": it.get("matchString"),
                        "start": s,
                        "end": e,
                        "sim": float(score),
                        "score_norm": float(score_norm),
                        "accept": accept,
                        "method": "embed",
                        "snippet": snippet[:200] + ("..." if len(snippet) > 200 else ""),
                    }
                    if "context_hybrid_score" in it:
                        dbg["hybrid_score"] = it.get("context_hybrid_score")
                    lst = ctx.out.setdefault("__context_debug", [])
                    lst.append(dbg)

            ctx.set(key, _finalize(kept))
            ctx.set(f"{key}_CTX_REJECTED", _finalize(rejected))
            _log_timing(
                "context.embed.key",
                req_id=ctx.request_id,
                key=key,
                ms=f"{_timing_ms(t0_key):.1f}",
                encode_ms="0.0",
                input=len(items),
                kept=len(kept),
                rejected=len(rejected),
                uniq_snippets=len({m[3] for m in meta}),
            )
            if stage_log:
                logger.info(
                    "[stage][context][embed] key=%s done kept=%d rejected=%d",
                    key,
                    len(kept),
                    len(rejected),
                )
        _log_timing("context.embed.total", req_id=ctx.request_id, ms=f"{_timing_ms(t0_all):.1f}", encode_ms=f"{total_encode_ms:.1f}", keys=len(self.target_keys), mode="embed")


# ============================================================
# Config -> Pipeline build
# ============================================================


