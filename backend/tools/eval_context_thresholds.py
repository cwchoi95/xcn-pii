from __future__ import annotations

import argparse
import json
import math
import csv
from typing import Dict, List, Tuple
import urllib.request
import yaml


def _call_api(url: str, text: str, max_results: int = 200) -> Dict:
    req = urllib.request.Request(
        url,
        data=json.dumps({"text": text, "max_results_per_type": max_results}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _call_debug(url: str, text: str) -> Dict:
    req = urllib.request.Request(
        url,
        data=json.dumps({"text": text, "method": "embed", "window_sentences": 2}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _find_match(items: List[Dict], match: str) -> Dict | None:
    for it in items or []:
        if str(it.get("matchString", "")) == match:
            return it
    return None


def _find_debug_item(debug_items: List[Dict], ptype: str, match: str) -> Dict | None:
    for it in debug_items or []:
        if it.get("key") == ptype and str(it.get("matchString", "")) == match:
            return it
    return None


def _metrics(tp: int, fp: int, fn: int) -> Dict[str, float]:
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) else 0.0
    return {"precision": prec, "recall": rec, "f1": f1}


def _eval_thresholds(rows: List[Dict], key: str, thresholds: List[float]) -> Tuple[float, Dict[str, float]]:
    best_t = None
    best = None
    for t in thresholds:
        tp = fp = fn = 0
        for r in rows:
            score = r.get(key)
            if score is None or isinstance(score, float) is False:
                # skip items without score
                continue
            pred = 1 if score >= t else 0
            if pred == 1 and r["label"] == 1:
                tp += 1
            elif pred == 1 and r["label"] == 0:
                fp += 1
            elif pred == 0 and r["label"] == 1:
                fn += 1
        m = _metrics(tp, fp, fn)
        if best is None or m["f1"] > best["f1"]:
            best_t = t
            best = m
    return best_t, best or {"precision": 0.0, "recall": 0.0, "f1": 0.0}


def _eval_thresholds_per_type(rows: List[Dict], key: str, thresholds: List[float]) -> Dict[str, Dict]:
    out: Dict[str, Dict] = {}
    types = sorted({r.get("type") for r in rows if r.get("type")})
    for tname in types:
        subset = [r for r in rows if r.get("type") == tname]
        best_t, best = _eval_thresholds(subset, key, thresholds)
        out[tname] = {"threshold": best_t, **best}
    return out


def _write_rows_csv(path: str, rows: List[Dict]) -> None:
    cols = [
        "id",
        "type",
        "label",
        "match",
        "context_score_norm",
        "context_hybrid_score",
    ]
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k) for k in cols})


def _write_summary_csv(path: str, overall: Dict, per_type: Dict[str, Dict]) -> None:
    cols = ["scope", "metric", "threshold", "precision", "recall", "f1"]
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for metric, info in overall.items():
            w.writerow(
                {
                    "scope": "overall",
                    "metric": metric,
                    "threshold": info["threshold"],
                    "precision": info["precision"],
                    "recall": info["recall"],
                    "f1": info["f1"],
                }
            )
        for metric, by_type in per_type.items():
            for tname, info in by_type.items():
                w.writerow(
                    {
                        "scope": tname,
                        "metric": metric,
                        "threshold": info["threshold"],
                        "precision": info["precision"],
                        "recall": info["recall"],
                        "f1": info["f1"],
                    }
                )


def _update_context_yaml(path: str, per_type_norm: Dict[str, Dict], per_type_hybrid: Dict[str, Dict], overall_hybrid: Dict) -> None:
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    ctx = data.get("context")
    if not isinstance(ctx, dict):
        ctx = {}
        data["context"] = ctx

    if isinstance(ctx.get("hybrid"), dict):
        ctx["hybrid"]["accept_threshold"] = overall_hybrid.get("threshold")

    if not isinstance(ctx.get("per_type"), dict):
        ctx["per_type"] = {}

    for tname, info in per_type_norm.items():
        entry = ctx["per_type"].get(tname, {})
        entry["sim_threshold"] = info.get("threshold")
        ctx["per_type"][tname] = entry

    for tname, info in per_type_hybrid.items():
        entry = ctx["per_type"].get(tname, {})
        if not isinstance(entry.get("hybrid"), dict):
            entry["hybrid"] = {}
        entry["hybrid"]["accept_threshold"] = info.get("threshold")
        ctx["per_type"][tname] = entry

    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, allow_unicode=True, sort_keys=False)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="backend/tools/context_eval.json")
    ap.add_argument("--url", default="http://localhost:8005/pii/detect")
    ap.add_argument("--min", type=float, default=-0.2)
    ap.add_argument("--max", type=float, default=0.8)
    ap.add_argument("--step", type=float, default=0.05)
    ap.add_argument("--out-rows", default="backend/tools/context_eval_rows.csv")
    ap.add_argument("--out-summary", default="backend/tools/context_eval_summary.csv")
    ap.add_argument("--update-context", default="backend/app/rules/context.yaml")
    args = ap.parse_args()

    with open(args.data, "r", encoding="utf-8") as f:
        data = json.load(f)

    items = data.get("items", [])
    rows: List[Dict] = []

    for it in items:
        resp = _call_api(args.url, it["text"])
        pdata = resp.get("data", {})
        arr = pdata.get(it["type"], [])
        found = _find_match(arr, it["match"])
        row = {
            "id": it.get("id"),
            "label": int(it.get("label", 0)),
            "type": it.get("type"),
            "match": it.get("match"),
            "context_score_norm": None,
            "context_hybrid_score": None,
        }
        if found:
            row["context_score_norm"] = found.get("context_score_norm")
            row["context_hybrid_score"] = found.get("context_hybrid_score")
        else:
            # fallback to debug endpoint to recover scores for filtered items
            dbg = _call_debug(args.url.replace("/pii/detect", "/debug/context"), it["text"])
            ditems = dbg.get("debug", [])
            ditem = _find_debug_item(ditems, it["type"], it["match"])
            if ditem:
                row["context_score_norm"] = ditem.get("score_norm")
                row["context_hybrid_score"] = ditem.get("hybrid_score")
        rows.append(row)

    thresholds = []
    t = args.min
    while t <= args.max + 1e-9:
        thresholds.append(round(t, 4))
        t += args.step

    best_norm_t, best_norm = _eval_thresholds(rows, "context_score_norm", thresholds)
    best_hybrid_t, best_hybrid = _eval_thresholds(rows, "context_hybrid_score", thresholds)
    per_type_norm = _eval_thresholds_per_type(rows, "context_score_norm", thresholds)
    per_type_hybrid = _eval_thresholds_per_type(rows, "context_hybrid_score", thresholds)

    print("== Best threshold (context_score_norm) ==")
    print(f"threshold={best_norm_t} precision={best_norm['precision']:.3f} recall={best_norm['recall']:.3f} f1={best_norm['f1']:.3f}")
    print("== Best threshold (context_hybrid_score) ==")
    print(f"threshold={best_hybrid_t} precision={best_hybrid['precision']:.3f} recall={best_hybrid['recall']:.3f} f1={best_hybrid['f1']:.3f}")
    print("== Per-type thresholds (context_score_norm) ==")
    for tname, info in per_type_norm.items():
        print(f"{tname}: threshold={info['threshold']} precision={info['precision']:.3f} recall={info['recall']:.3f} f1={info['f1']:.3f}")
    print("== Per-type thresholds (context_hybrid_score) ==")
    for tname, info in per_type_hybrid.items():
        print(f"{tname}: threshold={info['threshold']} precision={info['precision']:.3f} recall={info['recall']:.3f} f1={info['f1']:.3f}")
    print("== Rows ==")
    for r in rows:
        print(json.dumps(r, ensure_ascii=False))

    _write_rows_csv(args.out_rows, rows)
    overall = {
        "context_score_norm": {"threshold": best_norm_t, **best_norm},
        "context_hybrid_score": {"threshold": best_hybrid_t, **best_hybrid},
    }
    per_type = {
        "context_score_norm": per_type_norm,
        "context_hybrid_score": per_type_hybrid,
    }
    _write_summary_csv(args.out_summary, overall, per_type)
    if args.update_context:
        _update_context_yaml(
            args.update_context,
            per_type_norm,
            per_type_hybrid,
            overall.get("context_hybrid_score", {}),
        )


if __name__ == "__main__":
    main()
