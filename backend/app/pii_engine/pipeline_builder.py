from __future__ import annotations

from typing import List

from .common import *
from .context import *
from .context_config import _build_context_doc
from .detectors import *
from .regex_builders import *
from ..rules_loader import RuleBundle

def build_pipeline(bundle: RuleBundle) -> List[Detector]:
    """Build detector pipeline."""

    ruleset = bundle.ruleset
    docs = bundle.rule_docs

    steps = ruleset.get("steps") or []
    if not isinstance(steps, list):
        raise ValueError("steps must be a list")

    defaults = ruleset.get("defaults") or {}
    max_len_default = int(defaults.get("max_match_len_default") or 240)

    # Macros (for AN)
    macros: Dict[str, str] = {}
    an_doc = docs.get("an") or {}
    if isinstance(an_doc.get("sido_pattern"), str):
        macros["SIDO"] = str(an_doc["sido_pattern"])

    # Build DN detector source (Hyperscan primary, regex fallback)
    dn_doc = docs.get("dn") or {}
    dn_db: HyperscanDB | None = None
    dn_fallback_regexes: List[Pattern] = []
    dn_verify_regexes: List[Pattern] = []
    if _env_bool("PII_HS_DN_ENABLED", True):
        try:
            dn_db = _build_hs_db_dn(dn_doc)
            dn_verify_regexes = _build_verify_regexes(dn_doc)
        except Exception as e:
            print(f"[warn] DN Hyperscan disabled due to compile error: {e}")
            dn_fallback_regexes = _build_dn_fallback_regexes(dn_doc)
    else:
        dn_fallback_regexes = _build_dn_fallback_regexes(dn_doc)

    # Build regex patterns for all other PII types
    sn_doc = docs.get("sn") or {}
    sn_regexes = _build_regexes(sn_doc, macros={})
    sn_hs_supported = _get_hs_supported_pattern_indexes(sn_doc, macros={})
    sn_supplement_regexes = _build_regexes_by_indexes(sn_doc, set(range(len(sn_doc.get("patterns") or []))) - sn_hs_supported, macros={})

    ssn_doc = docs.get("SSN") or {}
    ssn_regexes = _build_regexes(ssn_doc, macros={})
    ssn_hs_supported = _get_hs_supported_pattern_indexes(ssn_doc, macros={})
    ssn_supplement_regexes = _build_regexes_by_indexes(ssn_doc, set(range(len(ssn_doc.get("patterns") or []))) - ssn_hs_supported, macros={})

    pn_doc = docs.get("pn") or {}
    pn_regexes = _build_regexes(pn_doc, macros={})
    pn_hs_supported = _get_hs_supported_pattern_indexes(pn_doc, macros={})
    pn_supplement_regexes = _build_regexes_by_indexes(pn_doc, set(range(len(pn_doc.get("patterns") or []))) - pn_hs_supported, macros={})

    mn_doc = docs.get("mn") or {}
    mn_regexes = _build_regexes(mn_doc, macros={})
    mn_hs_supported = _get_hs_supported_pattern_indexes(mn_doc, macros={})
    mn_supplement_regexes = _build_regexes_by_indexes(mn_doc, set(range(len(mn_doc.get("patterns") or []))) - mn_hs_supported, macros={})

    bn_doc = docs.get("bn") or {}
    bn_regexes = _build_regexes(bn_doc, macros={})
    bn_bank_enabled = bool(bn_doc.get("bank_pattern_enabled", True))
    bn_bank_enabled = _env_bool("PII_BN_BANK_PATTERN_ENABLED", bn_bank_enabled)
    bn_bank_patterns = _load_bank_patterns(bn_doc, bundle.rules_dir) if bn_bank_enabled else []
    bn_bank_weight = float(bn_doc.get("bank_pattern_weight", 0.25)) if bn_bank_enabled else 0.0

    an_regexes = _build_regexes(an_doc, macros=macros)
    an_hs_supported = _get_hs_supported_pattern_indexes(an_doc, macros=macros)
    an_supplement_regexes = _build_regexes_by_indexes(an_doc, set(range(len(an_doc.get("patterns") or []))) - an_hs_supported, macros=macros)

    em_doc = docs.get("EML") or {}
    em_regexes = _build_regexes(em_doc, macros={})
    em_hs_supported = _get_hs_supported_pattern_indexes(em_doc, macros={})
    em_supplement_regexes = _build_regexes_by_indexes(em_doc, set(range(len(em_doc.get("patterns") or []))) - em_hs_supported, macros={})
    ip_doc = docs.get("ip") or {}
    ip_regexes = _build_regexes(ip_doc, macros={})
    ip_hs_supported = _get_hs_supported_pattern_indexes(ip_doc, macros={})
    ip_supplement_regexes = _build_regexes_by_indexes(ip_doc, set(range(len(ip_doc.get("patterns") or []))) - ip_hs_supported, macros={})

    # Hyperscan-first for easy-compatible regex types (fallback to Python regex on failure)
    hs_ssn_db: HyperscanDB | None = None
    hs_sn_db: HyperscanDB | None = None
    hs_pn_db: HyperscanDB | None = None
    hs_mn_db: HyperscanDB | None = None
    hs_an_db: HyperscanDB | None = None
    hs_em_db: HyperscanDB | None = None
    hs_ip_db: HyperscanDB | None = None
    sn_verify_regexes: List[Pattern] = []
    ssn_verify_regexes: List[Pattern] = []
    pn_verify_regexes: List[Pattern] = []
    mn_verify_regexes: List[Pattern] = []
    an_verify_regexes: List[Pattern] = []
    em_verify_regexes: List[Pattern] = []
    ip_verify_regexes: List[Pattern] = []
    combined_hs_db: CombinedHyperscanDB | None = None

    if _env_bool("PII_HS_SN_ENABLED", True):
        try:
            hs_sn_db = _build_hs_db_regex_rule(sn_doc)
            sn_verify_regexes = _build_verify_regexes(sn_doc)
        except HyperscanUnsupportedRule:
            pass
        except Exception as e:
            print(f"[warn] SN Hyperscan disabled due to compile error: {e}")

    if _env_bool("PII_HS_SSN_ENABLED", True):
        try:
            hs_ssn_db = _build_hs_db_regex_rule(ssn_doc)
            ssn_verify_regexes = _build_verify_regexes(ssn_doc)
        except HyperscanUnsupportedRule:
            pass
        except Exception as e:
            print(f"[warn] SSN Hyperscan disabled due to compile error: {e}")

    if _env_bool("PII_HS_PN_ENABLED", True):
        try:
            hs_pn_db = _build_hs_db_regex_rule(pn_doc)
            pn_verify_regexes = _build_verify_regexes(pn_doc)
        except HyperscanUnsupportedRule:
            pass
        except Exception as e:
            print(f"[warn] PN Hyperscan disabled due to compile error: {e}")

    if _env_bool("PII_HS_MN_ENABLED", True):
        try:
            hs_mn_db = _build_hs_db_regex_rule(mn_doc)
            mn_verify_regexes = _build_verify_regexes(mn_doc)
        except HyperscanUnsupportedRule:
            pass
        except Exception as e:
            print(f"[warn] MN Hyperscan disabled due to compile error: {e}")

    if _env_bool("PII_HS_AN_ENABLED", True):
        try:
            hs_an_db = _build_hs_db_regex_rule(an_doc, macros=macros)
            an_verify_regexes = _build_verify_regexes(an_doc, macros=macros)
        except HyperscanUnsupportedRule:
            pass
        except Exception as e:
            print(f"[warn] AN Hyperscan disabled due to compile error: {e}")

    if _env_bool("PII_HS_EML_ENABLED", True):
        try:
            hs_em_db = _build_hs_db_regex_rule(em_doc)
            em_verify_regexes = _build_verify_regexes(em_doc)
        except HyperscanUnsupportedRule:
            pass
        except Exception as e:
            print(f"[warn] EML Hyperscan disabled due to compile error: {e}")

    if _env_bool("PII_HS_IP_ENABLED", True):
        try:
            hs_ip_db = _build_hs_db_regex_rule(ip_doc)
            ip_verify_regexes = _build_verify_regexes(ip_doc)
        except HyperscanUnsupportedRule:
            pass
        except Exception as e:
            print(f"[warn] IP Hyperscan disabled due to compile error: {e}")

    if _env_bool("PII_HS_COMBINED_ENABLED", False):
        try:
            combined_specs: List[tuple[str, Dict[str, Any], Dict[str, str] | None]] = []
            if hs_sn_db is not None:
                combined_specs.append(("SN", sn_doc, {}))
            if hs_ssn_db is not None:
                combined_specs.append(("SSN", ssn_doc, {}))
            if hs_pn_db is not None:
                combined_specs.append(("PN", pn_doc, {}))
            if hs_mn_db is not None:
                combined_specs.append(("MN", mn_doc, {}))
            if hs_an_db is not None:
                combined_specs.append(("AN", an_doc, macros))
            if hs_em_db is not None:
                combined_specs.append(("EML", em_doc, {}))
            if hs_ip_db is not None:
                combined_specs.append(("IP", ip_doc, {}))
            if combined_specs:
                combined_hs_db = _build_combined_hs_db(combined_specs)
        except HyperscanUnsupportedRule:
            combined_hs_db = None
        except Exception as e:
            combined_hs_db = None
            print(f"[warn] Combined Hyperscan disabled due to compile error: {e}")

    def _select_hs_db(out_key: str, fallback: HyperscanDB | None) -> HyperscanDB | CombinedHyperscanDB | None:
        if combined_hs_db is not None and out_key in getattr(combined_hs_db, "out_keys", set()):
            return combined_hs_db
        return fallback

    # For BN postfilter phone-like check
    phone_like_fullmatch = mn_regexes[0] if mn_regexes else re.compile(r"(?<!\d)0\d{1,2}[-.\s]?\d{3,4}[-.\s]?\d{4}(?!\d)")

    # Build detectors based on step list
    pipeline: List[Detector] = []
    for step in steps:
        step = str(step)

        if step == "dn":
            max_len = int(dn_doc.get("max_match_len") or max_len_default)
            if dn_db is not None:
                pipeline.append(
                    HSRegexDetector(
                        "DN",
                        hs_db=dn_db,
                        enabled=bool(dn_doc.get("enabled", True)),
                        max_match_len=max_len,
                        verify_regexes=dn_verify_regexes,
                        verify_window_chars=2,
                    )
                )
            else:
                pipeline.append(
                    RegexDetector(
                        "DN",
                        dn_fallback_regexes,
                        enabled=bool(dn_doc.get("enabled", True)),
                        max_match_len=max_len,
                    )
                )
            continue

        if step == "SSN":
            max_len = int(ssn_doc.get("max_match_len") or max_len_default)
            hs_db = _select_hs_db("SSN", hs_ssn_db)
            if hs_db is not None:
                pipeline.append(
                    HSRegexDetector(
                        "SSN",
                        hs_db=hs_db,
                        enabled=bool(ssn_doc.get("enabled", True)),
                        max_match_len=max_len,
                        verify_regexes=ssn_verify_regexes,
                        verify_window_chars=2,
                        supplement_regexes=ssn_supplement_regexes,
                    )
                )
            else:
                pipeline.append(RegexDetector("SSN", ssn_regexes, enabled=bool(ssn_doc.get("enabled", True)), max_match_len=max_len))
            continue

        if step == "sn":
            max_len = int(sn_doc.get("max_match_len") or max_len_default)
            checksum_enabled = bool((sn_doc.get("checksum") or {}).get("enabled", True))
            hs_db = _select_hs_db("SN", hs_sn_db)
            if hs_db is not None:
                pipeline.append(
                    SNHSDetector(
                        hs_db=hs_db,
                        enabled=bool(sn_doc.get("enabled", True)),
                        max_match_len=max_len,
                        checksum_enabled=checksum_enabled,
                        verify_regexes=sn_verify_regexes,
                        verify_window_chars=1,
                        supplement_regexes=sn_supplement_regexes,
                    )
                )
            else:
                pipeline.append(SNDetector(regexes=sn_regexes, enabled=bool(sn_doc.get("enabled", True)), max_match_len=max_len, checksum_enabled=checksum_enabled))
            continue

        if step == "pn":
            max_len = int(pn_doc.get("max_match_len") or max_len_default)
            hs_db = _select_hs_db("PN", hs_pn_db)
            if hs_db is not None:
                pipeline.append(
                    HSRegexDetector(
                        "PN",
                        hs_db=hs_db,
                        enabled=bool(pn_doc.get("enabled", True)),
                        max_match_len=max_len,
                        verify_regexes=pn_verify_regexes,
                        verify_window_chars=1,
                        supplement_regexes=pn_supplement_regexes,
                    )
                )
            else:
                pipeline.append(RegexDetector("PN", pn_regexes, enabled=bool(pn_doc.get("enabled", True)), max_match_len=max_len))
            continue

        if step == "mn":
            max_len = int(mn_doc.get("max_match_len") or max_len_default)
            hs_db = _select_hs_db("MN", hs_mn_db)
            if hs_db is not None:
                pipeline.append(
                    HSRegexDetector(
                        "MN",
                        hs_db=hs_db,
                        enabled=bool(mn_doc.get("enabled", True)),
                        max_match_len=max_len,
                        verify_regexes=mn_verify_regexes,
                        verify_window_chars=1,
                        supplement_regexes=mn_supplement_regexes,
                    )
                )
            else:
                pipeline.append(RegexDetector("MN", mn_regexes, enabled=bool(mn_doc.get("enabled", True)), max_match_len=max_len))
            continue

        if step == "bn":
            max_len = int(bn_doc.get("max_match_len") or max_len_default)
            pipeline.append(RegexDetector("BN", bn_regexes, enabled=bool(bn_doc.get("enabled", True)), max_match_len=max_len))
            continue

        if step == "an":
            max_len = int(an_doc.get("max_match_len") or max_len_default)
            hs_db = _select_hs_db("AN", hs_an_db)
            if hs_db is not None:
                pipeline.append(
                    ANHSDetector(
                        "AN",
                        hs_db=hs_db,
                        enabled=bool(an_doc.get("enabled", True)),
                        max_match_len=max_len,
                        verify_regexes=an_verify_regexes,
                        verify_window_chars=2,
                        supplement_regexes=an_supplement_regexes,
                    )
                )
            else:
                pipeline.append(
                    RegexDetector(
                        "AN",
                        an_regexes,
                        enabled=bool(an_doc.get("enabled", True)),
                        max_match_len=max_len,
                        split_newlines=True,
                    )
                )
            continue

        if step == "EML":
            max_len = int(em_doc.get("max_match_len") or max_len_default)
            hs_db = _select_hs_db("EML", hs_em_db)
            if hs_db is not None:
                pipeline.append(
                    HSRegexDetector(
                        "EML",
                        hs_db=hs_db,
                        enabled=bool(em_doc.get("enabled", True)),
                        max_match_len=max_len,
                        verify_regexes=em_verify_regexes,
                        verify_window_chars=1,
                        supplement_regexes=em_supplement_regexes,
                    )
                )
            else:
                pipeline.append(RegexDetector("EML", em_regexes, enabled=bool(em_doc.get("enabled", True)), max_match_len=max_len))
            continue

        if step == "ip":
            max_len = int(ip_doc.get("max_match_len") or max_len_default)
            hs_db = _select_hs_db("IP", hs_ip_db)
            if hs_db is not None:
                pipeline.append(
                    HSRegexDetector(
                        "IP",
                        hs_db=hs_db,
                        enabled=bool(ip_doc.get("enabled", True)),
                        max_match_len=max_len,
                        verify_regexes=ip_verify_regexes,
                        verify_window_chars=2,
                        supplement_regexes=ip_supplement_regexes,
                    )
                )
            else:
                pipeline.append(RegexDetector("IP", ip_regexes, enabled=bool(ip_doc.get("enabled", True)), max_match_len=max_len))
            continue

        if step == "post_mn":
            post = (mn_doc.get("postfilter") or {}) if isinstance(mn_doc.get("postfilter"), dict) else {}
            intl_digits_len = post.get("intl_digits_length") or {}
            pipeline.append(
                MNPostFilter(
                    enabled=bool(post.get("enabled", True)),
                    boundary_digit_reject=bool(post.get("boundary_digit_reject", True)),
                    reject_overlap_with=[str(x) for x in (post.get("reject_overlap_with") or [])],
                    intl_digits_len_min=int(intl_digits_len.get("min", 8)),
                    intl_digits_len_max=int(intl_digits_len.get("max", 15)),
                )
            )
            continue

        if step == "post_bn":
            post = (bn_doc.get("postfilter") or {}) if isinstance(bn_doc.get("postfilter"), dict) else {}
            digits_len = post.get("digits_length") or {}
            pipeline.append(
                BNPostFilter(
                    enabled=bool(post.get("enabled", True)),
                    digits_len_min=int(digits_len.get("min", 10)),
                    digits_len_max=int(digits_len.get("max", 14)),
                    reject_if_phone_like=bool(post.get("reject_if_phone_like", True)),
                    boundary_digit_reject=bool(post.get("boundary_digit_reject", True)),
                    reject_overlap_with=[str(x) for x in (post.get("reject_overlap_with") or [])],
                    phone_like_fullmatch_re=phone_like_fullmatch,
                )
            )
            continue

        if step == "post_context":
            ctx_doc = _build_context_doc(docs)
            enabled = bool(ctx_doc.get("enabled", True))
            window = int(ctx_doc.get("window_sentences", 2))
            method = str(ctx_doc.get("method") or "keyword")
            target_keys = [str(x) for x in (ctx_doc.get("target_keys") or ["SN", "SSN", "DN", "PN", "MN", "BN", "AN", "EML", "IP"])]
            indicator_phrases = ctx_doc.get("indicator_phrases") if isinstance(ctx_doc.get("indicator_phrases"), list) else None
            non_pii_phrases = ctx_doc.get("non_pii_phrases") if isinstance(ctx_doc.get("non_pii_phrases"), list) else None
            if method in ("embed", "semantic"):
                sim_threshold = float(ctx_doc.get("sim_threshold", 0.55))
                model_name = str(ctx_doc.get("model_name", "jhgan/ko-sbert-multitask"))
                debug = bool(ctx_doc.get("debug", False))
                keyword_threshold = int(ctx_doc.get("threshold", 1))
                cache_size = int(ctx_doc.get("cache_size", 1024))
                per_type = ctx_doc.get("per_type") if isinstance(ctx_doc.get("per_type"), dict) else {}
                if bn_bank_patterns:
                    bn_cfg = dict(per_type.get("BN") or {})
                    bn_cfg.setdefault("bank_patterns", bn_bank_patterns)
                    bn_cfg.setdefault("bank_pattern_weight", bn_bank_weight)
                    per_type["BN"] = bn_cfg
                hybrid_cfg = ctx_doc.get("hybrid") if isinstance(ctx_doc.get("hybrid"), dict) else {}
                pipeline.append(
                    ContextualLLMPostFilter(
                        enabled=enabled,
                        target_keys=target_keys,
                        window_sentences=window,
                        sim_threshold=sim_threshold,
                        model_name=model_name,
                        debug=debug,
                        indicator_phrases=indicator_phrases,
                        non_pii_phrases=non_pii_phrases,
                        keyword_threshold=keyword_threshold,
                        cache_size=cache_size,
                        per_type=per_type,
                        hybrid_cfg=hybrid_cfg,
                    )
                )
            else:
                threshold = int(ctx_doc.get("threshold", 1))
                debug = bool(ctx_doc.get("debug", False))
                per_type = ctx_doc.get("per_type") if isinstance(ctx_doc.get("per_type"), dict) else {}
                if bn_bank_patterns:
                    bn_cfg = dict(per_type.get("BN") or {})
                    bn_cfg.setdefault("bank_patterns", bn_bank_patterns)
                    bn_cfg.setdefault("bank_pattern_weight", bn_bank_weight)
                    per_type["BN"] = bn_cfg
                hybrid_cfg = ctx_doc.get("hybrid") if isinstance(ctx_doc.get("hybrid"), dict) else {}
                pipeline.append(
                    ContextualPostFilter(
                        enabled=enabled,
                        target_keys=target_keys,
                        window_sentences=window,
                        threshold=threshold,
                        debug=debug,
                        indicator_phrases=indicator_phrases,
                        non_pii_phrases=non_pii_phrases,
                        per_type=per_type,
                        hybrid_cfg=hybrid_cfg,
                    )
                )
            continue

    return pipeline


# ============================================================
# Engine with hot reload
# ============================================================


