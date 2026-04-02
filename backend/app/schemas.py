from __future__ import annotations

from pydantic import BaseModel, Field
from typing import List, Optional


class DetectPiiRequest(BaseModel):
    # Large payloads are handled by split/fast-path logic in app.pii.
    text: str = Field(min_length=1, max_length=10000000)
    max_results_per_type: int = Field(default=500, ge=1, le=5000)


class MatchItem(BaseModel):
    start: int
    end: int
    matchString: str
    isValid: Optional[bool] = None  
    context_score: Optional[float] = None
    context_score_norm: Optional[float] = None
    context_hybrid_score: Optional[float] = None
    context_method: Optional[str] = None
    context_accept_by: Optional[str] = None
    context_pass: Optional[bool] = None
    detected_by: Optional[str] = None


class PiiData(BaseModel):
    SN_CNT: Optional[int] = None
    SN: Optional[List[MatchItem]] = None
    SSN_CNT: Optional[int] = None
    SSN: Optional[List[MatchItem]] = None
    DN_CNT: Optional[int] = None
    DN: Optional[List[MatchItem]] = None
    AN_CNT: Optional[int] = None
    AN: Optional[List[MatchItem]] = None
    PN_CNT: Optional[int] = None
    PN: Optional[List[MatchItem]] = None
    MN_CNT: Optional[int] = None
    MN: Optional[List[MatchItem]] = None
    BN_CNT: Optional[int] = None
    BN: Optional[List[MatchItem]] = None
    EML_CNT: Optional[int] = None
    EML: Optional[List[MatchItem]] = None
    IP_CNT: Optional[int] = None
    IP: Optional[List[MatchItem]] = None

class PiiMeta(BaseModel):
    ruleset_name: str
    ruleset_version: str
    ruleset_updated_at: str


class DetectPiiResponse(BaseModel):
    success: bool
    status: int
    data: PiiData
    meta: PiiMeta | None = None
