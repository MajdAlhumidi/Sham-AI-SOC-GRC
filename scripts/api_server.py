import os
import json
import hmac
from datetime import datetime
from typing import List, Dict, Any, Optional, Literal
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Header, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

# Support both "python scripts/api_server.py" and "uvicorn scripts.api_server:app".
if __package__:
    from .alert_context import incident_target_host
    from .dashboard import render_dashboard
    from .review_audit import append_human_review
    from .grc.integration import sync_human_review
    from .grc.router import router as grc_router
    from .casework.router import router as casework_router
else:
    from alert_context import incident_target_host
    from dashboard import render_dashboard
    from review_audit import append_human_review
    from grc.integration import sync_human_review
    from grc.router import router as grc_router
    from casework.router import router as casework_router

app = FastAPI(title="Cyber SOC Command Center")
app.include_router(grc_router, prefix="/api")
app.include_router(casework_router, prefix="/api")

CHROMA_DB_PATH = "/home/ubuntu/soc-ai-agent/incident_vector_db"

def get_real_incidents_from_chroma() -> List[Dict[str, Any]]:
    """قراءة جميع السجلات الحقيقية الدائمة من ChromaDB"""
    try:
        if not os.path.exists(CHROMA_DB_PATH):
            return []
        
        import chromadb
        client = chromadb.PersistentClient(path=CHROMA_DB_PATH)
        collection = client.get_collection("security_incidents")
        data = collection.get()

        if not data or not data.get("ids"):
            return []

        real_incidents = []
        total = len(data["ids"])

        for i in reversed(range(total)):
            case_id = data["ids"][i]
            meta = data["metadatas"][i] if data.get("metadatas") else {}
            cls = str(meta.get("classification", "unknown")).strip().lower()
            verdict_by_class = {
                "true_positive": "Critical TP",
                "false_positive": "Benign/FP",
                "benign": "Benign",
                "suspicious": "Suspicious / Review",
                "unknown": "Suspicious / Review"
            }
            verdict = verdict_by_class.get(cls, "Suspicious / Review")

            host = incident_target_host(meta)
            src_ip = meta.get("source_ip", "N/A")
            user = meta.get("user_account", "N/A")
            rule = meta.get("rule_name", "Security Alert")
            notes = meta.get("analyst_notes", "No investigation notes recorded.")

            raw_timestamp = str(meta.get("timestamp", datetime.now().strftime("%H:%M:%S")))
            display_time = raw_timestamp[11:19] if len(raw_timestamp) >= 19 and "T" in raw_timestamp else raw_timestamp
            action_status = str(meta.get("containment_status", "NOT_EXECUTED")).upper()
            if action_status == "EXECUTED_AND_VERIFIED":
                containment_label = "Executed & Verified"
            elif action_status == "FAILED":
                containment_label = "Failed"
            else:
                containment_label = "Not executed"

            real_incidents.append({
                "case_id": case_id,
                "time": display_time,
                "host_agent": host if host != "N/A" else "local-agent",
                "level": int(meta.get("rule_level", 0) or 0),
                "rule_name": rule,
                "verdict": verdict,
                "containment": containment_label,
                "details": notes,
                "source_ip": src_ip,
                "user": user,
                "llm_provider": meta.get("llm_provider", "unknown"),
                "llm_model": meta.get("llm_model", "unknown"),
                "fallback_used": meta.get("fallback_used")
            })

        return real_incidents
    except Exception as e:
        print(f"[!] Error fetching from ChromaDB: {e}")
        return []

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                pass

manager = ConnectionManager()

class ExternalAlertInput(BaseModel):
    case_id: str = ""
    rule_level: int = 7
    rule_desc: str = ""
    target_host: str = ""
    source_ip: str = ""
    user: str = "N/A"
    payload: str = ""
    report_text: str = ""
    classification: str = ""
    containment_status: str = "NOT_EXECUTED"
    llm_provider: str = "unknown"
    llm_model: str = "unknown"
    fallback_used: Optional[bool] = None


class HumanReviewInput(BaseModel):
    incident_id: str = Field(..., min_length=1, max_length=128)
    agent_classification: Literal["true_positive", "false_positive", "suspicious", "benign", "unknown"]
    decision: Literal["accepted", "corrected", "escalated"]
    final_classification: Optional[Literal["true_positive", "false_positive", "suspicious", "benign", "unknown"]] = None
    reviewer: str = Field(..., min_length=1, max_length=128)
    notes: str = Field(default="", max_length=2000)
    agent_recommendations: List[str] = Field(default_factory=list, max_items=10)


@app.get("/api/incidents")
def list_incidents():
    """Keep the existing dashboard Sync DB endpoint available after upgrades."""
    return {"incidents": get_real_incidents_from_chroma()}


@app.post("/api/broadcast")
async def ingest_real_agent_alert(alert: ExternalAlertInput):
    """بث التقرير المحفوظ في ChromaDB إلى المتصفح لحظياً"""
    classification = alert.classification.strip().lower()
    verdict_by_class = {
        "true_positive": "Critical TP",
        "false_positive": "Benign/FP",
        "benign": "Benign",
        "suspicious": "Suspicious / Review",
        "unknown": "Suspicious / Review"
    }
    verdict = verdict_by_class.get(classification, "Suspicious / Review")
    now_time = datetime.now().strftime("%H:%M:%S")
    action_status = alert.containment_status.strip().upper()
    if action_status == "EXECUTED_AND_VERIFIED":
        containment_label = "Executed & Verified"
    elif action_status == "FAILED":
        containment_label = "Failed"
    else:
        containment_label = "Not executed"

    new_record = {
        "case_id": alert.case_id if alert.case_id else f"INC-{datetime.now().strftime('%Y%m%d')}-LIVE",
        "time": now_time,
        "host_agent": alert.target_host,
        "level": alert.rule_level,
        "rule_name": alert.rule_desc,
        "verdict": verdict,
        "containment": containment_label,
        "details": alert.report_text,
        "source_ip": alert.source_ip,
        "user": alert.user,
        "llm_provider": alert.llm_provider,
        "llm_model": alert.llm_model,
        "fallback_used": alert.fallback_used
    }

    await manager.broadcast({"type": "NEW_ALERT", "incident": new_record})
    return {"status": "broadcasted", "case_id": new_record["case_id"]}


@app.post("/api/reviews")
async def record_human_review(
    review: HumanReviewInput,
    x_review_token: Optional[str] = Header(default=None, alias="X-Review-Token"),
):
    """Record an analyst decision separately from the agent suggestion.

    Configure SOC_REVIEW_API_TOKEN to enable the route. It is disabled by default.
    """
    expected_token = os.getenv("SOC_REVIEW_API_TOKEN", "").strip()
    if not expected_token:
        raise HTTPException(
            status_code=503,
            detail="Human review recording is disabled; configure SOC_REVIEW_API_TOKEN.",
        )
    if not x_review_token or not hmac.compare_digest(x_review_token, expected_token):
        raise HTTPException(status_code=401, detail="Invalid review token.")

    try:
        record = append_human_review(review.dict())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except OSError:
        raise HTTPException(status_code=500, detail="Could not persist the human review record.")

    return {
        "status": "recorded",
        "review_id": record["review_id"],
        "incident_id": record["incident_id"],
        "human_decision": record["human_decision"],
        "final_classification": record["final_classification"],
        "grc_sync": sync_human_review(record),
    }


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        initial_data = get_real_incidents_from_chroma()
        await websocket.send_json({"type": "INIT_DATA", "incidents": initial_data})
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.get("/", response_class=HTMLResponse)
async def serve_ui():
    return render_dashboard(get_real_incidents_from_chroma())

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
