from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

import yaml


# -----------------------------------------------------------------------------
# File loading
# -----------------------------------------------------------------------------


def load_doc(path: Path) -> Dict[str, Any]:
    """Load a YAML/JSON file into a dict."""
    if not path.exists():
        raise FileNotFoundError(str(path))

    suffix = path.suffix.lower()
    raw = path.read_text(encoding="utf-8")

    if suffix in (".yaml", ".yml"):
        data = yaml.safe_load(raw) or {}
    elif suffix == ".json":
        data = json.loads(raw or "{}")
    else:
        raise ValueError(f"Unsupported rules file extension: {path}")

    if not isinstance(data, dict):
        raise ValueError(f"Rules file root must be an object/mapping: {path}")
    return data


# -----------------------------------------------------------------------------
# Bundles & meta
# -----------------------------------------------------------------------------


@dataclass
class RuleBundle:
    """Loaded ruleset + per-type rule documents.

    - ruleset: 마스터 룰셋 문서(_ruleset*.yaml)
    - rule_docs: sn/dn/bn/... 등 타입별 룰 문서
    - mtimes: 핫리로드를 위해 읽었던 모든 파일의 mtime을 저장
    - version: 파일 내용 기반 fingerprint(sha256)
    - updated_at: 가장 최근 수정 시각(UTC iso)
    """

    rules_dir: Path
    ruleset_name: str
    ruleset_path: Path
    ruleset: Dict[str, Any]
    rule_docs: Dict[str, Dict[str, Any]]
    mtimes: Dict[str, float]
    version: str
    updated_at: str


def _env(name: str, default: str) -> str:
    v = os.getenv(name)
    return v.strip() if v and v.strip() else default


# -----------------------------------------------------------------------------
# Ruleset discovery
# -----------------------------------------------------------------------------


def discover_ruleset_file(rules_dir: Path, ruleset_name: str) -> Path:
    """Pick a master ruleset file.

    Search order:
    1) _ruleset_<name>.yaml / .yml / .json
    2) _ruleset.yaml / .yml / .json

    Example
    -------
    - ruleset_name="strict"  -> _ruleset_strict.yaml (if exists)
    - else fallback -> _ruleset.yaml
    """

    candidates: List[Path] = []
    for ext in (".yaml", ".yml", ".json"):
        candidates.append(rules_dir / f"_ruleset_{ruleset_name}{ext}")
    for ext in (".yaml", ".yml", ".json"):
        candidates.append(rules_dir / f"_ruleset{ext}")

    for p in candidates:
        if p.exists():
            return p

    # default fallback name (existing projects)
    p = rules_dir / "_ruleset.yaml"
    return p


def list_rulesets(rules_dir: str | Path) -> List[str]:
    """List available ruleset names in rules_dir.

    - _ruleset.yaml 은 항상 "default"로 노출(호환)
    - _ruleset_<name>.yaml 은 <name>으로 노출
    """
    d = Path(rules_dir)
    out: List[str] = []

    # explicit named rulesets
    for p in d.glob("_ruleset_*.*"):
        stem = p.stem  # e.g. _ruleset_strict
        if not stem.startswith("_ruleset_"):
            continue
        name = stem.replace("_ruleset_", "", 1)
        if name and name not in out:
            out.append(name)

    # fallback
    for ext in (".yaml", ".yml", ".json"):
        if (d / f"_ruleset{ext}").exists():
            if "default" not in out:
                out.append("default")
            break

    out.sort()
    return out


# -----------------------------------------------------------------------------
# Macros
# -----------------------------------------------------------------------------


def _apply_macros(value: Any, macros: Dict[str, str]) -> Any:
    """Recursively replace {KEY} in strings.

    - value가 dict/list/str이면 내부를 순회하면서 치환합니다.
    - 치환 대상은 "문자열"만.
    """
    if value is None:
        return value

    if isinstance(value, str):
        s = value
        for k, v in macros.items():
            s = s.replace("{" + k + "}", str(v))
        return s

    if isinstance(value, list):
        return [_apply_macros(x, macros) for x in value]

    if isinstance(value, dict):
        return {k: _apply_macros(v, macros) for k, v in value.items()}

    return value


# -----------------------------------------------------------------------------
# Fingerprinting (version)
# -----------------------------------------------------------------------------


def _fingerprint(paths: Iterable[Path]) -> str:
    """Compute sha256 over all rule file contents (stable ordering)."""
    h = hashlib.sha256()
    for p in sorted({str(x) for x in paths}):
        pp = Path(p)
        h.update(pp.name.encode("utf-8"))
        h.update(b"\n")
        h.update(pp.read_bytes())
        h.update(b"\n\n")
    return h.hexdigest()[:16]


def _updated_at_utc(mtimes: Dict[str, float]) -> str:
    if not mtimes:
        return ""
    mx = max(mtimes.values())
    # ISO 8601 UTC
    from datetime import datetime, timezone

    return datetime.fromtimestamp(mx, tz=timezone.utc).isoformat()


# -----------------------------------------------------------------------------
# Load rules
# -----------------------------------------------------------------------------


def load_rules(
    rules_dir: str | Path | None = None,
    ruleset_name: str | None = None,
) -> RuleBundle:
    """Load a ruleset + its per-type rule files."""

    rules_dir_p = Path(rules_dir) if rules_dir else Path(_env("PII_RULES_DIR", "app/rules"))
    ruleset_name_v = ruleset_name or _env("PII_RULESET", "default")

    ruleset_path = discover_ruleset_file(rules_dir_p, ruleset_name_v)
    ruleset_doc = load_doc(ruleset_path)

    # macros: allow shared constants like {SIDO} in address regex
    macros: Dict[str, str] = {}
    if isinstance(ruleset_doc.get("macros"), dict):
        macros.update({k: str(v) for k, v in ruleset_doc["macros"].items()})

    # load per-type docs
    rule_files = ruleset_doc.get("rule_files") or {}
    if not isinstance(rule_files, dict):
        raise ValueError("ruleset.rule_files must be a mapping")

    docs: Dict[str, Dict[str, Any]] = {}
    mtimes: Dict[str, float] = {}

    def _track(p: Path) -> None:
        try:
            mtimes[str(p)] = p.stat().st_mtime
        except FileNotFoundError:
            mtimes[str(p)] = 0.0

    _track(ruleset_path)

    for key, filename in rule_files.items():
        p = rules_dir_p / str(filename)
        doc = load_doc(p)

        # per-doc macros override/add
        local_macros = dict(macros)
        if isinstance(doc.get("macros"), dict):
            local_macros.update({k: str(v) for k, v in doc["macros"].items()})

        doc = _apply_macros(doc, local_macros)
        docs[str(key)] = doc
        _track(p)

    version = _fingerprint([Path(x) for x in mtimes.keys()])
    updated_at = _updated_at_utc(mtimes)

    return RuleBundle(
        rules_dir=rules_dir_p,
        ruleset_name=ruleset_name_v,
        ruleset_path=ruleset_path,
        ruleset=ruleset_doc,
        rule_docs=docs,
        mtimes=mtimes,
        version=version,
        updated_at=updated_at,
    )

# -----------------------------------------------------------------------------
# Compatibility helpers (imported by pii_engine.py)
# -----------------------------------------------------------------------------

def expand_macros(doc: Any, macros: Dict[str, str]) -> Any:
    """
    Backward-compatible helper.
    pii_engine.py에서 import하는 expand_macros()를 제공하기 위한 wrapper 입니다.

    Parameters
    ----------
    doc:
        YAML/JSON에서 읽은 rule 문서(dict/list/str 혼합 가능)
    macros:
        {"SIDO": "..."} 같이 {KEY} 치환에 사용할 매크로 딕셔너리

    Returns
    -------
    치환이 적용된 doc
    """
    return _apply_macros(doc, macros)


def bundle_needs_reload(bundle: "RuleBundle") -> bool:
    """
    Hot-reload 판단 함수.

    bundle.load_rules()가 읽었던 모든 파일들의 mtime을 저장해두고,
    현재 파일 mtime과 비교하여 하나라도 변경되었으면 True를 반환합니다.

    Notes
    -----
    - 파일이 삭제된 경우(FileNotFoundError)도 reload 필요로 간주합니다.
    - Windows/overlayfs 환경에서 mtime 해상도가 낮을 수 있어,
      운영에서는 변경 시점이 같은 파일을 연속 저장할 때 반영이 늦어 보일 수 있습니다.
    """
    for path_str, old_mtime in (bundle.mtimes or {}).items():
        p = Path(path_str)
        try:
            new_mtime = p.stat().st_mtime
        except FileNotFoundError:
            return True

        # mtime이 다르면 룰 변경으로 간주
        if new_mtime != old_mtime:
            return True

    return False
