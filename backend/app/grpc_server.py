from __future__ import annotations

import hashlib
import logging
import os
import time
from concurrent import futures
from typing import Any

import grpc

from .logging_utils import setup_file_logging
from .pii import detect_with_meta
from .pii_engine import preload_models
from .proto import pii_pb2, pii_pb2_grpc

logger = logging.getLogger("pii.grpc")


def _env(name: str, default: str) -> str:
    v = os.getenv(name)
    return v.strip() if v and v.strip() else default


def _env_int(name: str, default: int) -> int:
    v = os.getenv(name)
    if v is None:
        return int(default)
    try:
        return int(str(v).strip())
    except Exception:
        return int(default)


def _env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def _build_match_item(pb2: Any, it: dict) -> Any:
    return pb2.MatchItem(
        start=int(it.get("start", 0)),
        end=int(it.get("end", 0)),
        match_string=str(it.get("matchString", "")),
        is_valid=bool(it.get("isValid", False)),
        context_score=float(it.get("context_score", 0.0) or 0.0),
        context_score_norm=float(it.get("context_score_norm", 0.0) or 0.0),
        context_hybrid_score=float(it.get("context_hybrid_score", 0.0) or 0.0),
        context_method=str(it.get("context_method", "")),
        context_accept_by=str(it.get("context_accept_by", "")),
        context_pass=bool(it.get("context_pass", False)),
        detected_by=str(it.get("detected_by", "")),
    )


def _build_data(pb2: Any, found: dict) -> Any:
    def items(key: str) -> list[Any]:
        return [_build_match_item(pb2, x) for x in (found.get(key, []) or [])]

    field_map = {
        "SN": ("sn_cnt", "sn"),
        "SSN": ("ssn_cnt", "ssn"),
        "DN": ("dn_cnt", "dn"),
        "AN": ("an_cnt", "an"),
        "PN": ("pn_cnt", "pn"),
        "MN": ("mn_cnt", "mn"),
        "BN": ("bn_cnt", "bn"),
        "EML": ("eml_cnt", "eml"),
        "IP": ("ip_cnt", "ip"),
    }
    kwargs: dict[str, Any] = {}
    for key, (cnt_field, items_field) in field_map.items():
        values = found.get(key, []) or []
        if not values:
            continue
        kwargs[cnt_field] = len(values)
        kwargs[items_field] = [_build_match_item(pb2, x) for x in values]
    return pb2.PiiData(**kwargs)


def _log_detect_summary(req_id: str, text: str, max_results_per_type: int, ruleset: str | None, found: dict, detect_ms: float, total_ms: float) -> None:
    logger.info(
        "[request] grpc Detect\n"
        "  req=%s chars=%d bytes=%d max_results_per_type=%d ruleset=%s",
        req_id,
        len(text),
        len(text.encode("utf-8", errors="ignore")),
        max_results_per_type,
        ruleset or os.getenv("PII_RULESET", "default"),
    )
    logger.info(
        "[timing] grpc Detect\n"
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
        "[decision] grpc Detect\n"
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


def serve() -> None:
    if _env_bool("PII_MODEL_PRELOAD_ENABLED", True):
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

    class PiiDetectorServicer(pii_pb2_grpc.PiiDetectorServicer):
        def Detect(self, request, context):  # noqa: N802
            try:
                text = request.text or ""
                max_results_per_type = int(request.max_results_per_type or 500)
                ruleset = request.ruleset.strip() if request.ruleset else None
                req_id = hashlib.md5(text.encode("utf-8", errors="ignore")).hexdigest()[:8] if text else "empty"
                t0 = time.perf_counter()
                t_detect = time.perf_counter()
                found, meta = detect_with_meta(
                    text,
                    max_results_per_type=max_results_per_type,
                    ruleset=ruleset,
                )
                detect_ms = (time.perf_counter() - t_detect) * 1000.0
                total_ms = (time.perf_counter() - t0) * 1000.0
                _log_detect_summary(req_id, text, max_results_per_type, ruleset, found, detect_ms, total_ms)
                return pii_pb2.DetectResponse(
                    success=True,
                    status=200,
                    message="OK",
                    data=_build_data(pii_pb2, found),
                    meta=pii_pb2.PiiMeta(
                        ruleset_name=str((meta or {}).get("ruleset_name", "")),
                        ruleset_version=str((meta or {}).get("ruleset_version", "")),
                        ruleset_updated_at=str((meta or {}).get("ruleset_updated_at", "")),
                    ),
                )
            except Exception as e:  # pragma: no cover
                logger.exception("gRPC Detect failed")
                context.set_code(grpc.StatusCode.INTERNAL)
                context.set_details(str(e))
                return pii_pb2.DetectResponse(
                    success=False,
                    status=500,
                    message=str(e),
                )

        def Health(self, request, context):  # noqa: N802
            return pii_pb2.HealthResponse(
                ok=True,
                service="xcn-pii-new-grpc",
                version="1.0.0",
            )

    max_workers = max(1, _env_int("PII_GRPC_MAX_WORKERS", 4))
    max_concurrent_streams = max(1, _env_int("PII_GRPC_MAX_CONCURRENT_STREAMS", 1024))
    keepalive_time_ms = max(1000, _env_int("PII_GRPC_KEEPALIVE_TIME_MS", 30000))
    keepalive_timeout_ms = max(1000, _env_int("PII_GRPC_KEEPALIVE_TIMEOUT_MS", 10000))
    max_concurrent_rpcs = _env_int("PII_GRPC_MAX_CONCURRENT_RPCS", 0)
    host = _env("PII_GRPC_HOST", "0.0.0.0")
    port = _env_int("PII_GRPC_PORT", 50051)
    bind = f"{host}:{port}"
    options = [
        ("grpc.so_reuseport", int(_env_bool("PII_GRPC_SO_REUSEPORT", True))),
        ("grpc.max_concurrent_streams", max_concurrent_streams),
        ("grpc.keepalive_time_ms", keepalive_time_ms),
        ("grpc.keepalive_timeout_ms", keepalive_timeout_ms),
        ("grpc.keepalive_permit_without_calls", 1),
        ("grpc.http2.max_pings_without_data", 0),
    ]

    kwargs = {}
    if max_concurrent_rpcs > 0:
        kwargs["maximum_concurrent_rpcs"] = max_concurrent_rpcs
    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=max_workers),
        options=options,
        **kwargs,
    )
    pii_pb2_grpc.add_PiiDetectorServicer_to_server(PiiDetectorServicer(), server)
    server.add_insecure_port(bind)
    server.start()
    logger.info(
        "gRPC server started on %s workers=%d max_streams=%d max_rpcs=%s reuseport=%s",
        bind,
        max_workers,
        max_concurrent_streams,
        str(max_concurrent_rpcs) if max_concurrent_rpcs > 0 else "unlimited",
        str(_env_bool("PII_GRPC_SO_REUSEPORT", True)).lower(),
    )
    server.wait_for_termination()


if __name__ == "__main__":
    setup_file_logging()
    logging.basicConfig(level=os.getenv("PII_LOG_LEVEL", "INFO"))
    serve()
