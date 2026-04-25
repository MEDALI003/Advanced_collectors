from fastapi import APIRouter, HTTPException
from app.rag_threat_engine import score_payload, fetch_recent_payloads

router = APIRouter(prefix="/ai", tags=["AI RAG"])


@router.post("/rag-score-event")
def rag_score_event(payload: dict):
    try:
        return score_payload(payload)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/rag-score-latest")
def rag_score_latest(limit: int = 5):
    try:
        payloads = fetch_recent_payloads(limit=limit)
        results = [score_payload(payload) for payload in payloads]
        return {"results": results}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))