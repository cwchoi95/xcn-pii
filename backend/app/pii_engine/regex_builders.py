from __future__ import annotations

from typing import Any, Dict, List, Pattern, Tuple

from .common import *
from ..rules_loader import expand_macros


class HyperscanUnsupportedRule(Exception):
    pass


def _compile_re(pattern: str, flags_cfg: Dict[str, Any] | None) -> Pattern:
    flags = 0
    if flags_cfg:
        if flags_cfg.get("ignorecase"):
            flags |= re.IGNORECASE
        if flags_cfg.get("unicode"):
            flags |= re.UNICODE
    return re.compile(pattern, flags)


def _build_regexes(rule_doc: Dict[str, Any], macros: Dict[str, str]) -> List[Pattern]:
    patterns = rule_doc.get("patterns") or []
    if not isinstance(patterns, list):
        raise ValueError("patterns must be a list")

    regexes: List[Pattern] = []
    for p in patterns:
        if not isinstance(p, dict):
            continue
        raw = str(p.get("regex") or "")
        if not raw:
            continue
        expanded = expand_macros(raw, macros)
        rx = _compile_re(expanded, p.get("flags") if isinstance(p.get("flags"), dict) else None)
        regexes.append(rx)

    return regexes


def _hs_flags_from_cfg(flags_cfg: Dict[str, Any] | None) -> int:
    f = 0
    flags_cfg = flags_cfg or {}
    if flags_cfg.get("ignorecase"):
        f |= hyperscan.HS_FLAG_CASELESS
    if flags_cfg.get("utf8", True):
        f |= hyperscan.HS_FLAG_UTF8
    if flags_cfg.get("ucp", True):
        f |= hyperscan.HS_FLAG_UCP
    if flags_cfg.get("som", True):
        f |= hyperscan.HS_FLAG_SOM_LEFTMOST
    return f


def _validate_hs_expr(expr: str, hs_flags: int) -> bool:
    try:
        db = hyperscan.Database(mode=hyperscan.HS_MODE_BLOCK)
        db.compile(expressions=[expr.encode("utf-8")], ids=[0], flags=[hs_flags])
        return True
    except Exception:
        return False


def _get_hs_supported_pattern_indexes(rule_doc: Dict[str, Any], macros: Dict[str, str] | None = None) -> set[int]:
    if not rule_doc.get("enabled", True):
        return set()
    pats = rule_doc.get("patterns") or []
    if not isinstance(pats, list):
        raise ValueError("patterns must be a list")
    macros = macros or {}
    out: set[int] = set()
    for pattern_index, p in enumerate(pats):
        if not isinstance(p, dict):
            continue
        expr = str(p.get("expr") or p.get("regex") or "").strip()
        if not expr:
            continue
        expr = expand_macros(expr, macros)
        flags_cfg = p.get("flags") if isinstance(p.get("flags"), dict) else {}
        if "som" not in flags_cfg:
            flags_cfg = dict(flags_cfg)
            flags_cfg["som"] = True
        hs_flags = _hs_flags_from_cfg(flags_cfg)
        if _validate_hs_expr(expr, hs_flags):
            out.add(int(pattern_index))
    return out


def _build_regexes_by_indexes(rule_doc: Dict[str, Any], indexes: set[int], macros: Dict[str, str]) -> List[Pattern]:
    patterns = rule_doc.get("patterns") or []
    if not isinstance(patterns, list):
        raise ValueError("patterns must be a list")
    regexes: List[Pattern] = []
    for idx, p in enumerate(patterns):
        if idx not in indexes or not isinstance(p, dict):
            continue
        raw = str(p.get("regex") or "")
        if not raw:
            continue
        expanded = expand_macros(raw, macros)
        rx = _compile_re(expanded, p.get("flags") if isinstance(p.get("flags"), dict) else None)
        regexes.append(rx)
    return regexes


def _build_hs_db_dn(dn_doc: Dict[str, Any]) -> HyperscanDB:
    """Build Hyperscan DB for DN only."""
    if not dn_doc.get("enabled", True):
        return HyperscanDB([])

    pats = dn_doc.get("patterns") or []
    if not isinstance(pats, list):
        raise ValueError("dn.patterns must be a list")

    compiled: List[HSPattern] = []
    for p in pats:
        if not isinstance(p, dict):
            continue
        expr = str(p.get("expr") or "")
        if not expr:
            continue

        hs_flags = _hs_flags_from_cfg(p.get("flags") if isinstance(p.get("flags"), dict) else None)
        compiled.append(HSPattern(expr=expr.encode("utf-8"), flags=hs_flags))

    return HyperscanDB(compiled)


def _build_dn_fallback_regexes(dn_doc: Dict[str, Any]) -> List[Pattern]:
    """Build Python regex fallback patterns for DN when Hyperscan compile fails."""
    out: List[Pattern] = []
    pats = dn_doc.get("patterns") or []
    if not isinstance(pats, list):
        return out
    for p in pats:
        if not isinstance(p, dict):
            continue
        vr = str(p.get("verify_regex") or "").strip()
        if not vr:
            vr = str(p.get("expr") or "").strip()
        if not vr:
            continue
        try:
            out.append(re.compile(vr))
        except Exception:
            continue
    return out


def _build_hs_db_regex_rule(rule_doc: Dict[str, Any], macros: Dict[str, str] | None = None) -> HyperscanDB:
    """Build Hyperscan DB from generic regex rule docs (patterns[].expr|regex)."""
    if not rule_doc.get("enabled", True):
        return HyperscanDB([])
    pats = rule_doc.get("patterns") or []
    if not isinstance(pats, list):
        raise ValueError("patterns must be a list")
    macros = macros or {}
    compiled: List[HSPattern] = []
    for p in pats:
        if not isinstance(p, dict):
            continue
        expr = str(p.get("expr") or p.get("regex") or "").strip()
        if not expr:
            continue
        expr = expand_macros(expr, macros)
        flags_cfg = p.get("flags") if isinstance(p.get("flags"), dict) else {}
        if "som" not in flags_cfg:
            flags_cfg = dict(flags_cfg)
            flags_cfg["som"] = True
        hs_flags = _hs_flags_from_cfg(flags_cfg)
        if not _validate_hs_expr(expr, hs_flags):
            continue
        compiled.append(HSPattern(expr=expr.encode("utf-8"), flags=hs_flags))
    if not compiled:
        raise HyperscanUnsupportedRule("no supported hyperscan patterns")
    return HyperscanDB(compiled)


def _build_hs_typed_patterns(out_key: str, rule_doc: Dict[str, Any], macros: Dict[str, str] | None = None) -> List[HSTypedPattern]:
    if not rule_doc.get("enabled", True):
        return []
    pats = rule_doc.get("patterns") or []
    if not isinstance(pats, list):
        raise ValueError("patterns must be a list")
    macros = macros or {}
    compiled: List[HSTypedPattern] = []
    for pattern_index, p in enumerate(pats):
        if not isinstance(p, dict):
            continue
        expr = str(p.get("expr") or p.get("regex") or "").strip()
        if not expr:
            continue
        expr = expand_macros(expr, macros)
        flags_cfg = p.get("flags") if isinstance(p.get("flags"), dict) else {}
        if "som" not in flags_cfg:
            flags_cfg = dict(flags_cfg)
            flags_cfg["som"] = True
        hs_flags = _hs_flags_from_cfg(flags_cfg)
        if not _validate_hs_expr(expr, hs_flags):
            continue
        compiled.append(
            HSTypedPattern(
                expr=expr.encode("utf-8"),
                flags=hs_flags,
                out_key=str(out_key),
                pattern_index=int(pattern_index),
            )
        )
    return compiled


def _build_combined_hs_db(rule_specs: List[Tuple[str, Dict[str, Any], Dict[str, str] | None]]) -> CombinedHyperscanDB:
    compiled: List[HSTypedPattern] = []
    for out_key, rule_doc, macros in rule_specs:
        compiled.extend(_build_hs_typed_patterns(out_key, rule_doc, macros=macros))
    if not compiled:
        raise HyperscanUnsupportedRule("no supported combined hyperscan patterns")
    return CombinedHyperscanDB(compiled)


def _build_verify_regexes(rule_doc: Dict[str, Any], macros: Dict[str, str] | None = None) -> List[Pattern]:
    """Build Python verify regexes aligned with patterns order."""
    pats = rule_doc.get("patterns") or []
    if not isinstance(pats, list):
        return []
    macros = macros or {}
    out: List[Pattern] = []
    for p in pats:
        if not isinstance(p, dict):
            continue
        raw = str(p.get("verify_regex") or p.get("regex") or p.get("expr") or "").strip()
        if not raw:
            continue
        raw = expand_macros(raw, macros)
        flags = 0
        flags_cfg = p.get("flags") if isinstance(p.get("flags"), dict) else {}
        if flags_cfg.get("ignorecase"):
            flags |= re.IGNORECASE
        out.append(re.compile(raw, flags))
    return out


__all__ = [name for name in globals() if not name.startswith("__")]
