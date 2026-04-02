from __future__ import annotations
from typing import List, Dict

# 실제로는 OpenSearch hit를 여기에 맞춰 매핑하면 됨
DOCS: List[Dict] = [
    {
        "doc_id": "doc-001",
        "title": "사내 계정 생성 가이드",
        "content": "계정 생성 문의: admin@company.com / 담당자 010-1234-5678. "
                   "테스트 주민번호: 900101-1234567 (예시).",
        "score": 0.92,
    },
    {
        "doc_id": "doc-002",
        "title": "VPN 접속 매뉴얼",
        "content": "VPN 서버 IP는 10.1.2.3 입니다. 접속 문제 시 02-123-4567로 연락 바랍니다.",
        "score": 0.88,
    },
    {
        "doc_id": "doc-003",
        "title": "결제 관련 안내",
        "content": "카드번호 예시: 4111 1111 1111 1111 (테스트). 문의: billing@company.com",
        "score": 0.83,
    },
]


def search_docs(query: str, top_k: int = 5) -> List[Dict]:
    """아주 단순한 contains 검색(데모). 실제론 OpenSearch 결과를 그대로 반환하면 됨."""
    q = query.strip().lower()
    if not q:
        return DOCS[:top_k]

    scored = []
    for d in DOCS:
        text = (d["title"] + " " + d["content"]).lower()
        base = d.get("score", 0.5)
        bonus = 0.2 if q in text else 0.0
        scored.append((base + bonus, d))

    scored.sort(key=lambda x: x[0], reverse=True)
    return [d for _, d in scored[:top_k]]
