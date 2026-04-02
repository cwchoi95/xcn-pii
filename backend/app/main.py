from __future__ import annotations

import logging
import os
import time
import hashlib

from fastapi import FastAPI, Header
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.schemas import DetectPiiRequest, DetectPiiResponse, PiiData, MatchItem, PiiMeta
from app.pii import detect_all, detect_with_meta
from app.pii_engine import preload_models
from app.rules_loader import list_rulesets, load_rules
from app.context_debug_api import router as debug_router
from app.logging_utils import setup_file_logging


setup_file_logging()

app = FastAPI(title="PII Detector (Hyperscan + re)", version="1.0.0")
app.include_router(debug_router)
logger = logging.getLogger("pii.api")

app.mount("/static", StaticFiles(directory="app/static"), name="static")


def _env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return str(v).strip().lower() in ("1", "true", "yes", "on")


@app.on_event("startup")
def preload_pii_models() -> None:
    if not _env_bool("PII_MODEL_PRELOAD_ENABLED", True):
        logger.info("PII model preload disabled")
        return
    try:
        warmed = preload_models()
        logger.info(
            "PII model preload complete. rulesets=%d models=%d type_embeddings=%d",
            int(warmed.get("rulesets", 0)),
            int(warmed.get("models", 0)),
            int(warmed.get("type_embeddings", 0)),
        )
    except Exception:
        logger.exception("PII model preload failed")


@app.get("/")
def root():
    return FileResponse("app/static/index.html")


@app.post("/pii/detect", response_model=DetectPiiResponse, response_model_exclude_none=True)
def pii_detect(
    req: DetectPiiRequest,
    x_pii_ruleset: str | None = Header(default=None, alias="X-PII-RULESET"),
):
    """PII 탐지.

    룰셋 스위칭
    -----------
    - 요청 헤더로 룰셋을 지정할 수 있습니다.
        X-PII-RULESET: strict
    - 헤더가 없으면 환경변수 PII_RULESET (기본: default)를 사용합니다.

    응답 meta
    ---------
    - ruleset_name / ruleset_version / ruleset_updated_at 을 포함해
      "어떤 룰"로 탐지했는지 추적 가능하게 합니다.
    """

    text = req.text or ""
    t0 = time.perf_counter()
    req_id = hashlib.md5(text.encode("utf-8", errors="ignore")).hexdigest()[:8] if text else "empty"
    logger.info(
        "[request] /pii/detect\n"
        "  req=%s chars=%d bytes=%d max_results_per_type=%d ruleset=%s",
        req_id,
        len(text),
        len(text.encode("utf-8", errors="ignore")),
        int(req.max_results_per_type or 0),
        x_pii_ruleset or os.getenv("PII_RULESET", "default"),
    )

    t_detect = time.perf_counter()
    found, meta = detect_with_meta(text, max_results_per_type=req.max_results_per_type, ruleset=x_pii_ruleset)
    detect_ms = (time.perf_counter() - t_detect) * 1000.0

    data_kwargs = {}
    for key in ("SN", "SSN", "DN", "AN", "PN", "MN", "BN", "EML", "IP"):
        values = found.get(key, []) or []
        if not values:
            continue
        data_kwargs[f"{key}_CNT"] = len(values)
        data_kwargs[key] = [MatchItem(**x) for x in values]
    data = PiiData(**data_kwargs)

    total_ms = (time.perf_counter() - t0) * 1000.0
    logger.info(
        "[timing] /pii/detect\n"
        "  req=%s detect_ms=%.1f total_ms=%.1f\n"
        "  kept: SN=%d SSN=%d DN=%d PN=%d MN=%d BN=%d AN=%d EML=%d IP=%d",
        req_id,
        detect_ms,
        total_ms,
        len(found.get("SN", [])),
        len(found.get("SSN", [])),
        len(found.get("DN", [])),
        len(found.get("PN", [])),
        len(found.get("MN", [])),
        len(found.get("BN", [])),
        len(found.get("AN", [])),
        len(found.get("EML", [])),
        len(found.get("IP", [])),
    )
    logger.info(
        "[decision] /pii/detect\n"
        "  req=%s kept_total=%d rejected_total=%d\n"
        "  rejected: SN=%d SN_INVALID=%d SSN=%d DN=%d PN=%d MN=%d BN=%d AN=%d EML=%d IP=%d",
        req_id,
        sum(
            len(found.get(k, []))
            for k in ("SN", "SN_INVALID", "SSN", "DN", "PN", "MN", "BN", "AN", "EML", "IP")
        ),
        sum(
            len(found.get(k, []))
            for k in (
                "SN_CTX_REJECTED",
                "SN_INVALID_CTX_REJECTED",
                "SSN_CTX_REJECTED",
                "DN_CTX_REJECTED",
                "PN_CTX_REJECTED",
                "MN_CTX_REJECTED",
                "BN_CTX_REJECTED",
                "AN_CTX_REJECTED",
                "EML_CTX_REJECTED",
                "IP_CTX_REJECTED",
            )
        ),
        len(found.get("SN_CTX_REJECTED", [])),
        len(found.get("SN_INVALID_CTX_REJECTED", [])),
        len(found.get("SSN_CTX_REJECTED", [])),
        len(found.get("DN_CTX_REJECTED", [])),
        len(found.get("PN_CTX_REJECTED", [])),
        len(found.get("MN_CTX_REJECTED", [])),
        len(found.get("BN_CTX_REJECTED", [])),
        len(found.get("AN_CTX_REJECTED", [])),
        len(found.get("EML_CTX_REJECTED", [])),
        len(found.get("IP_CTX_REJECTED", [])),
    )

    return DetectPiiResponse(success=True, status=200, data=data, meta=PiiMeta(**meta))

@app.get("/pii/rulesets")
def pii_rulesets():
    """서버가 인식하는 룰셋 목록을 반환합니다.

    - rules_dir: PII_RULES_DIR(기본: app/rules)
    - _ruleset.yaml          -> default
    - _ruleset_<name>.yaml   -> <name>

    각 룰셋의 version/updated_at 도 함께 제공합니다.
    """
    rules_dir = os.getenv("PII_RULES_DIR", "app/rules")
    names = list_rulesets(rules_dir)

    out = []
    for name in names:
        try:
            b = load_rules(rules_dir=rules_dir, ruleset_name=name)
            out.append({
                "ruleset_name": b.ruleset_name,
                "ruleset_version": b.version,
                "ruleset_updated_at": b.updated_at,
                "ruleset_path": str(b.ruleset_path),
            })
        except Exception as e:
            out.append({"ruleset_name": name, "error": str(e)})

    return {"rules_dir": rules_dir, "rulesets": out}


@app.get("/pii/selftest")
def pii_selftest():
    sample = (
        "SN=900101-1234567 "
        "DN=11-22-333333-44 "
        "PN=M12345678 "
        "MN=010-1234-5678 "
        "SSN=123-45-6789 "
        "EML=test.user+aa@company.co.kr "
        "IP=192.168.0.10 "
        "AN=서울특별시 강남구 테헤란로 123-4"
    )
    found = detect_all(sample, max_results_per_type=50)
    return {
        "sample": sample,
        "counts": {k: len(v) for k, v in found.items()},
        "found": found,
    }
