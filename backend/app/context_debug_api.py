from fastapi import FastAPI, HTTPException, APIRouter
from pydantic import BaseModel, ConfigDict
from typing import Optional

from .pii_engine import (
    detect,
    DetectContext,
    ContextualPostFilter,
    ContextualLLMPostFilter,
)
from .pii_engine.common import _request_id

app = FastAPI(title="PII Context Debug API")
router = APIRouter()


class DebugRequest(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    text: str
    method: Optional[str] = "embed"  # embed or keyword
    window_sentences: Optional[int] = 2
    sim_threshold: Optional[float] = 0.55
    model_name: Optional[str] = "jhgan/ko-sbert-multitask"
    target_keys: Optional[list[str]] = None


@router.post("/debug/context")
async def debug_context(req: DebugRequest):
    text = req.text or ""
    if not text.strip():
        raise HTTPException(status_code=400, detail="text is required")

    # Run base detection with current engine
    found = detect(text=text)

    # Create a DetectContext wrapper so we can run post-filter and capture debug
    ctx = DetectContext(text=text, source_text=text, max_results=500, out=found, request_id=_request_id(text))

    target_keys = req.target_keys or ["SN", "SSN", "DN", "PN", "MN", "BN", "AN", "EML"]

    if (req.method or "embed").lower() in ("embed", "semantic"):
        filt = ContextualLLMPostFilter(enabled=True, target_keys=target_keys, window_sentences=req.window_sentences, sim_threshold=req.sim_threshold, model_name=req.model_name, debug=True)
    else:
        filt = ContextualPostFilter(enabled=True, target_keys=target_keys, window_sentences=req.window_sentences, threshold=1, debug=True)

    # Run filter which will populate ctx.out and ctx.out['__context_debug'] when debug
    filt.run(ctx)

    # Return results and any debug entries
    result = {
        "found": ctx.out,
        "debug": ctx.out.get("__context_debug", []),
    }
    return result


app.include_router(router)
