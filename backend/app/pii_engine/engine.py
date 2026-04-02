from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Tuple

from .common import *
from .context import *
from .detectors import *
from .pipeline import build_pipeline
from ..rules_loader import RuleBundle, bundle_needs_reload, load_rules


def _step_name(step: Detector) -> str:
    if isinstance(step, SNHSDetector):
        return "sn.hyperscan"
    if isinstance(step, ANHSDetector):
        return "an.hyperscan"
    if isinstance(step, HSRegexDetector):
        return f"{step.out_key.lower()}.hyperscan"
    if isinstance(step, SNDetector):
        return "sn.regex"
    if isinstance(step, RegexDetector):
        return f"{step.out_key.lower()}.regex"
    if isinstance(step, DNDetector):
        return "dn.hyperscan"
    if isinstance(step, MNPostFilter):
        return "mn.postfilter"
    if isinstance(step, BNPostFilter):
        return "bn.postfilter"
    if isinstance(step, ContextualLLMPostFilter):
        return "context.embed"
    if isinstance(step, ContextualPostFilter):
        return "context.keyword"
    return step.__class__.__name__


def _prune_empty_outputs(out: Dict[str, Any]) -> Dict[str, Any]:
    pruned: Dict[str, Any] = {}
    for key, value in (out or {}).items():
        upper_key = str(key).upper()
        if upper_key == "SN_INVALID" or upper_key.endswith("_CTX_REJECTED"):
            continue
        if key == "__context_debug":
            if value:
                pruned[key] = value
            continue
        if isinstance(value, list):
            if value:
                pruned[key] = value
            continue
        if value not in (None, "", 0, False):
            pruned[key] = value
    return pruned


class PiiEngine:
    def __init__(self, bundle: RuleBundle, pipeline: Iterable[Detector]):
        self.bundle = bundle
        self.pipeline = list(pipeline)

    def detect(self, text: str, max_results_per_type: int = 500, include_context_debug: bool | None = None) -> Dict[str, List[dict]]:
        source_text = text or ""
        norm_text, kept_positions = _normalize_for_detection(source_text)
        max_results = int(max_results_per_type or (self.bundle.ruleset.get("defaults") or {}).get("max_results_per_type", 500))
        trace = _env_bool("PII_TRACE_DETECT", False)
        stage_log = _trace_stage_enabled()
        slow_ms = max(100, _env_int("PII_TRACE_SLOW_MS", 1500))

        # Auto fast-path for very long inputs.
        # Controlled by env:
        # - PII_FASTPATH_ENABLED (default=true)
        # - PII_FASTPATH_TEXT_LEN (default=50000)
        # - PII_FASTPATH_MAX_RESULTS_PER_TYPE (default=200)
        # - PII_FASTPATH_TARGET_KEYS (default=SN,SN_INVALID,SSN,DN,PN,MN,EML,IP)
        text_len = len(source_text)
        fast_enabled = _env_bool("PII_FASTPATH_ENABLED", True)
        fast_len = max(1, _env_int("PII_FASTPATH_TEXT_LEN", 50000))
        fast_max = max(1, _env_int("PII_FASTPATH_MAX_RESULTS_PER_TYPE", 100))
        fast_keys = _env_csv_upper(
            "PII_FASTPATH_TARGET_KEYS",
            "SN,SN_INVALID,SSN,DN,PN,MN,EML,IP",
        )
        fast_mode = bool(fast_enabled and text_len >= fast_len)
        allowed_keys = set(fast_keys)
        if fast_mode:
            max_results = min(max_results, fast_max)

        # decide whether to include context debug info (param overrides env)
        include_debug = include_context_debug if include_context_debug is not None else _env_bool("PII_INCLUDE_CONTEXT_DEBUG", False)

        ctx = DetectContext(
            text=norm_text,
            source_text=source_text,
            max_results=max_results,
            out={},
            request_id=_request_id(source_text),
        )

        # set debug flags on pipeline detectors that support it
        restore: List[Tuple[Any, str, Any]] = []
        for step in self.pipeline:
            if hasattr(step, "debug"):
                try:
                    restore.append((step, "debug", getattr(step, "debug")))
                    setattr(step, "debug", bool(include_debug))
                except Exception:
                    pass

            if not fast_mode:
                continue

            # Reduce detector scope for long text.
            try:
                if isinstance(step, RegexDetector):
                    if step.out_key.upper() not in allowed_keys:
                        restore.append((step, "enabled", step.enabled))
                        step.enabled = False
                elif isinstance(step, SNDetector):
                    if not (("SN" in allowed_keys) or ("SN_INVALID" in allowed_keys)):
                        restore.append((step, "enabled", step.enabled))
                        step.enabled = False
                elif isinstance(step, DNDetector):
                    if "DN" not in allowed_keys:
                        restore.append((step, "enabled", step.enabled))
                        step.enabled = False
                elif isinstance(step, MNPostFilter):
                    if "MN" not in allowed_keys:
                        restore.append((step, "enabled", step.enabled))
                        step.enabled = False
                elif isinstance(step, BNPostFilter):
                    if "BN" not in allowed_keys:
                        restore.append((step, "enabled", step.enabled))
                        step.enabled = False
                elif isinstance(step, ContextualPostFilter):
                    restore.append((step, "target_keys", list(step.target_keys)))
                    step.target_keys = [x for x in step.target_keys if str(x).upper() in allowed_keys]
                elif isinstance(step, ContextualLLMPostFilter):
                    restore.append((step, "target_keys", list(step.target_keys)))
                    step.target_keys = [x for x in step.target_keys if str(x).upper() in allowed_keys]
                    restore.append((step, "force_keyword_mode", bool(step.force_keyword_mode)))
                    step.force_keyword_mode = True
            except Exception:
                continue

        t0_all = time.perf_counter()
        try:
            for idx, step in enumerate(self.pipeline, start=1):
                before = _summarize_counts(ctx.out) if stage_log else {}
                if stage_log:
                    logger.info(
                        "[stage][pipeline] step_start idx=%d name=%s text_len=%d max_results=%d",
                        idx,
                        _step_name(step),
                        len(source_text),
                        max_results,
                    )
                t0_step = time.perf_counter()
                step.run(ctx)
                dt_step = (time.perf_counter() - t0_step) * 1000.0
                if stage_log:
                    after = _summarize_counts(ctx.out)
                    deltas = []
                    for k in after.keys():
                        diff = int(after.get(k, 0)) - int(before.get(k, 0))
                        if diff != 0:
                            deltas.append(f"{k}:{diff:+d}")
                    logger.info(
                        "[stage][pipeline] step_done idx=%d name=%s ms=%.1f delta=%s",
                        idx,
                        _step_name(step),
                        dt_step,
                        ",".join(deltas) if deltas else "none",
                    )
                _log_timing(
                    "pipeline",
                    req_id=ctx.request_id,
                    idx=idx,
                    name=_step_name(step),
                    ms=f"{dt_step:.1f}",
                    text_len=len(source_text),
                    max_results=max_results,
                )
                if trace and dt_step >= slow_ms:
                    logger.info(
                        "[trace] step slow idx=%d name=%s ms=%.1f text_len=%d",
                        idx,
                        _step_name(step),
                        dt_step,
                        len(source_text),
                    )
        finally:
            # Restore mutable detector attributes to keep engine cache safe.
            for obj, attr, val in reversed(restore):
                try:
                    setattr(obj, attr, val)
                except Exception:
                    pass
        if trace:
            dt_all = (time.perf_counter() - t0_all) * 1000.0
            logger.info(
                "[trace] detect done ms=%.1f text_len=%d ruleset=%s max_results=%d fast_mode=%s",
                dt_all,
                len(source_text),
                self.bundle.ruleset_name,
                max_results,
                str(fast_mode).lower(),
            )
        _log_timing(
            "detect.total",
            req_id=ctx.request_id,
            ms=f"{((time.perf_counter() - t0_all) * 1000.0):.1f}",
            text_len=len(source_text),
            ruleset=self.bundle.ruleset_name,
            max_results=max_results,
            fast_mode=str(fast_mode).lower(),
        )

        for key, value in list(ctx.out.items()):
            if isinstance(value, list):
                ctx.out[key] = _finalize(value)

        # BN context-rejected noise cleanup against overlap priority types.
        _cleanup_bn_ctx_rejected_overlap(ctx.out, self.bundle.rule_docs.get("bn") or {})
        _remap_output_spans(ctx.out, source_text, kept_positions)

        # If debug not requested, strip debug entries
        if not include_debug and "__context_debug" in ctx.out:
            ctx.out.pop("__context_debug", None)

        return _prune_empty_outputs(ctx.out)

        # Optionally hide SN_INVALID by default. Controlled via ruleset defaults
        # or environment variable `PII_INCLUDE_SN_INVALID` (true/1 to include).
        include_sn_invalid = _env_bool("PII_INCLUDE_SN_INVALID", False)
        try:
            rs_defaults = (self.bundle.ruleset or {}).get("defaults") or {}
            include_sn_invalid = bool(rs_defaults.get("include_sn_invalid", include_sn_invalid))
        except Exception:
            pass

        if not include_sn_invalid:
            ctx.out.pop("SN_INVALID", None)

        # If debug not requested, strip debug entries
        if not include_debug and "__context_debug" in ctx.out:
            ctx.out.pop("__context_debug", None)

        # Optionally include aggregated context scores in the top-level result.
        include_scores = _env_bool("PII_INCLUDE_CONTEXT_SCORES", False) or bool(include_debug)
        try:
            rs_defaults = (self.bundle.ruleset or {}).get("defaults") or {}
            include_scores = bool(rs_defaults.get("include_context_scores", include_scores))
        except Exception:
            pass

        if include_scores:
            scores: Dict[str, List[dict]] = {}
            for k in ["SN", "SN_INVALID", "SSN", "DN", "PN", "MN", "BN", "AN", "EML", "IP"]:
                items = ctx.out.get(k, []) or []
                lst: List[dict] = []
                for it in items:
                    entry = {"start": it.get("start"), "end": it.get("end"), "matchString": it.get("matchString")}
                    if "context_score_norm" in it:
                        entry["context_score_norm"] = it.get("context_score_norm")
                    elif "context_score" in it:
                        entry["context_score"] = it.get("context_score")
                    lst.append(entry)
                scores[k] = lst

            ctx.out["__context_scores"] = scores

        return ctx.out


# ============================================================
# Engine registry (ruleset switching + hot reload)
# ============================================================

_ENGINE_REGISTRY: dict[tuple[str, str], PiiEngine] = {}


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
    # stable dedup
    seen = set()
    dedup: List[str] = []
    for k in out:
        if k in seen:
            continue
        seen.add(k)
        dedup.append(k)
    return dedup


def _env_csv(name: str, default_csv: str) -> List[str]:
    raw = os.getenv(name)
    if raw is None or not str(raw).strip():
        raw = default_csv
    out: List[str] = []
    for x in str(raw).split(","):
        k = str(x).strip()
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


def get_engine(*, ruleset: str | None = None, rules_dir: str | None = None) -> PiiEngine:
    """Get (or build) an engine for a given ruleset."""
    rs = (ruleset or _env('PII_RULESET', 'default')).strip()
    rd = (rules_dir or _env('PII_RULES_DIR', 'app/rules')).strip()
    key = (rd, rs)

    eng = _ENGINE_REGISTRY.get(key)
    if eng is None:
        bundle = load_rules(rules_dir=rd, ruleset_name=rs)
        pipeline = build_pipeline(bundle)
        eng = PiiEngine(bundle=bundle, pipeline=pipeline)
        _ENGINE_REGISTRY[key] = eng
        return eng

    if bundle_needs_reload(eng.bundle):
        bundle = load_rules(rules_dir=rd, ruleset_name=rs)
        pipeline = build_pipeline(bundle)
        eng = PiiEngine(bundle=bundle, pipeline=pipeline)
        _ENGINE_REGISTRY[key] = eng

    return eng


def preload_models(*, rulesets: List[str] | None = None, rules_dir: str | None = None) -> Dict[str, int]:
    rd = (rules_dir or _env("PII_RULES_DIR", "app/rules")).strip()
    target_rulesets = rulesets or _env_csv("PII_PRELOAD_RULESETS", _env("PII_RULESET", "default"))
    warmed = 0
    engines = 0
    type_embeddings = 0
    for rs in target_rulesets:
        eng = get_engine(ruleset=rs, rules_dir=rd)
        engines += 1
        for step in eng.pipeline:
            if isinstance(step, ContextualLLMPostFilter):
                stats = step.warmup()
                warmed += 1
                type_embeddings += int((stats or {}).get("types", 0))
    return {"rulesets": engines, "models": warmed, "type_embeddings": type_embeddings}


def detect(
    text: str,
    max_results_per_type: int = 500,
    include_context_debug: bool | None = None,
    *,
    ruleset: str | None = None,
    rules_dir: str | None = None,
) -> Dict[str, List[dict]]:
    """Detect PII with optional ruleset switching.

    `include_context_debug` overrides the environment variable `PII_INCLUDE_CONTEXT_DEBUG` if provided.
    """
    return get_engine(ruleset=ruleset, rules_dir=rules_dir).detect(text=text, max_results_per_type=max_results_per_type, include_context_debug=include_context_debug)


def detect_with_meta(
    text: str,
    max_results_per_type: int = 500,
    *,
    ruleset: str | None = None,
    rules_dir: str | None = None,
) -> tuple[Dict[str, List[dict]], Dict[str, str]]:
    """Detect PII and return (result, meta)."""
    eng = get_engine(ruleset=ruleset, rules_dir=rules_dir)
    found = eng.detect(text=text, max_results_per_type=max_results_per_type)
    meta = {
        'ruleset_name': eng.bundle.ruleset_name,
        'ruleset_version': eng.bundle.version,
        'ruleset_updated_at': eng.bundle.updated_at,
    }
    return found, meta


def detect_with_meta_uncached(
    text: str,
    max_results_per_type: int = 500,
    *,
    ruleset: str | None = None,
    rules_dir: str | None = None,
) -> tuple[Dict[str, List[dict]], Dict[str, str]]:
    """Detect PII and return (result, meta) using a fresh non-cached engine.

    Useful for parallel chunk processing to avoid shared detector state.
    """
    rs = (ruleset or _env('PII_RULESET', 'default')).strip()
    rd = (rules_dir or _env('PII_RULES_DIR', 'app/rules')).strip()
    bundle = load_rules(rules_dir=rd, ruleset_name=rs)
    pipeline = build_pipeline(bundle)
    eng = PiiEngine(bundle=bundle, pipeline=pipeline)
    found = eng.detect(text=text, max_results_per_type=max_results_per_type)
    meta = {
        'ruleset_name': eng.bundle.ruleset_name,
        'ruleset_version': eng.bundle.version,
        'ruleset_updated_at': eng.bundle.updated_at,
    }
    return found, meta
