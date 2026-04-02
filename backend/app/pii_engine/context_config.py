from __future__ import annotations

from typing import Any, Dict

def _build_context_doc(docs: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Build context config from context.yaml + per-type context_*.yaml files."""
    base = docs.get("context") or {}
    if isinstance(base.get("context"), dict):
        base = base["context"]
    ctx_doc: Dict[str, Any] = dict(base) if isinstance(base, dict) else {}

    per_type = dict(ctx_doc.get("per_type") or {})
    for key, doc in docs.items():
        if not key.startswith("context_"):
            continue
        type_key = key[len("context_"):]
        if not type_key:
            continue
        if not isinstance(doc, dict):
            continue
        cfg = doc.get("config") if isinstance(doc.get("config"), dict) else doc
        if not isinstance(cfg, dict):
            continue
        merged = dict(per_type.get(type_key) or {})
        merged.update(cfg)
        per_type[type_key] = merged

    ctx_doc["per_type"] = per_type
    return ctx_doc


