import os
import json
import asyncio
from datetime import datetime
from typing import List, Dict, Any, Optional, Literal
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

# Support both "python scripts/api_server.py" and "uvicorn scripts.api_server:app".
if __package__:
    from .alert_context import incident_target_host
    from .dashboard import render_dashboard
    from .security import SESSION_COOKIE, SESSION_TTL, Security, authorize_route
    from .review_audit import append_human_review, sync_review_memory
    from .grc.integration import sync_human_review
    from .grc.router import router as grc_router
    from .casework.router import router as casework_router
else:
    from alert_context import incident_target_host
    from dashboard import render_dashboard
    from security import SESSION_COOKIE, SESSION_TTL, Security, authorize_route
    from review_audit import append_human_review, sync_review_memory
    from grc.integration import sync_human_review
    from grc.router import router as grc_router
    from casework.router import router as casework_router

router = APIRouter()

CHROMA_DB_PATH = os.getenv("SOC_VECTOR_DB_PATH", "/home/ubuntu/soc-ai-agent/incident_vector_db")

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
    def __init__(self, security):
        self.security = security
        self.active_connections = {}

    async def send(self, websocket, session_id, message):
        if session_id and self.security.principal_for_session(session_id) is None:
            return False
        try:
            await websocket.send_json(message)
        except (WebSocketDisconnect, RuntimeError, OSError):
            return False
        return True

    async def broadcast(self, message):
        for connection, session_id in tuple(self.active_connections.items()):
            if not await self.send(connection, session_id, message):
                self.active_connections.pop(connection, None)

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


@router.get("/api/incidents")
def list_incidents():
    """Keep the existing dashboard Sync DB endpoint available after upgrades."""
    return {"incidents": get_real_incidents_from_chroma()}


@router.post("/api/broadcast")
async def ingest_real_agent_alert(alert: ExternalAlertInput, request: Request):
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

    new_record = {
        "case_id": alert.case_id if alert.case_id else f"INC-{datetime.now().strftime('%Y%m%d')}-LIVE",
        "time": now_time,
        "host_agent": alert.target_host,
        "level": alert.rule_level,
        "rule_name": alert.rule_desc,
        "verdict": verdict,
        "containment": "Not executed",
        "details": alert.report_text,
        "source_ip": alert.source_ip,
        "user": alert.user,
        "llm_provider": alert.llm_provider,
        "llm_model": alert.llm_model,
        "fallback_used": alert.fallback_used
    }

    await request.app.state.connections.broadcast({"type": "NEW_ALERT", "incident": new_record})
    return {"status": "broadcasted", "case_id": new_record["case_id"]}


@router.post("/api/reviews")
async def record_human_review(review: HumanReviewInput, request: Request):
    """Record an analyst decision separately from the agent suggestion.

    Configure SOC_REVIEW_API_TOKEN to enable the route. It is disabled by default.
    """
    try:
        record = append_human_review(review.model_dump(), principal=request.state.principal)
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
        "historical_memory": sync_review_memory(record, CHROMA_DB_PATH),
    }


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    security = websocket.app.state.security
    manager = websocket.app.state.connections
    origin = websocket.headers.get("origin")
    if (security.mode == "token" or origin) and origin not in security.websocket_origins:
        await websocket.close(code=1008)
        return
    try:
        _, session_id = security.authorize(websocket, ("SOC_READER",))
    except HTTPException:
        await websocket.close(code=1008)
        return
    await websocket.accept()
    manager.active_connections[websocket] = session_id
    try:
        initial_data = get_real_incidents_from_chroma()
        if not await manager.send(websocket, session_id, {"type": "INIT_DATA", "incidents": initial_data}):
            await websocket.close(code=1008)
            return
        while True:
            if not session_id:
                await websocket.receive_text()
                continue
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=15)
            except TimeoutError:
                pass
            if security.principal_for_session(session_id) is None:
                await websocket.close(code=1008)
                break
    except WebSocketDisconnect:
        pass
    finally:
        manager.active_connections.pop(websocket, None)


LOGIN_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in to SHAM</title>
<style>
body{margin:0;min-height:100vh;display:grid;place-items:center;font:1rem system-ui;color:#ecf2fa;background:#0a101b}
main{width:min(22rem,calc(100% - 4rem));padding:2rem;border:1px solid #34445a;border-radius:12px;background:#121c2b}
h1{font-size:1.5rem;margin:0 0 1rem} form{display:grid;gap:.75rem}
input,button{box-sizing:border-box;width:100%;padding:.75rem;border:1px solid #60758f;border-radius:6px;font:inherit}
input{color:inherit;background:#0a101b} button{background:#99d9ff;color:#091526;cursor:pointer}
</style></head><body><main><h1>Sign in to SHAM</h1>
<form id="login" method="post" action="/api/auth/session">
<label for="token">Access token</label>
<input id="token" type="password" required maxlength="2048" autocomplete="current-password">
<button type="submit">Sign in</button>
<p id="status" role="status"></p>
</form></main><script>
const form = document.getElementById('login');
form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const input = document.getElementById('token');
  const status = document.getElementById('status');
  const submit = form.querySelector('button');
  const body = JSON.stringify({token: input.value});
  input.value = '';
  submit.disabled = true;
  try {
    const response = await fetch('/api/auth/session', {
      method: 'POST', headers: {'Content-Type': 'application/json'}, body
    });
    if (response.ok) { window.location.reload(); return; }
    status.textContent = response.status === 429 ? 'Too many attempts. Try again shortly.' : 'Sign-in failed.';
  } catch (_) {
    status.textContent = 'Could not connect to SHAM.';
  } finally { submit.disabled = false; }
});
</script></body></html>"""

PRIVATE_HEADERS = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}


@router.post("/api/auth/session")
async def login(request: Request):
    security = request.app.state.security
    if security.mode != "token":
        raise HTTPException(404, "Browser sessions are only available in token mode.")
    security.validate_origin(request)
    security.limiter.require(("login", request.client.host if request.client else ""), 20)
    local_http = not security.secure_cookie and security.local(request)
    if not local_http and request.url.scheme != "https":
        raise HTTPException(403, "Browser authentication requires HTTPS.")
    payload = bytearray()
    async for chunk in request.stream():
        if len(payload) + len(chunk) > 8192:
            raise HTTPException(413, "Sign-in request is too large.")
        payload.extend(chunk)
    try:
        data = json.loads(payload)
        token = data.get("token") if isinstance(data, dict) else None
    except (ValueError, UnicodeError):
        token = None
    principal = security.token_principal(token)
    if not principal or principal.token_kind in {"service", "admin", "review"} or "SOC_READER" not in principal.roles:
        raise HTTPException(401, "Invalid browser credential.")
    security.revoke(request.cookies.get(SESSION_COOKIE))
    response = Response(status_code=204, headers=PRIVATE_HEADERS)
    response.set_cookie(
        SESSION_COOKIE, security.issue_session(principal), max_age=SESSION_TTL,
        httponly=True, secure=not local_http, samesite="lax",
    )
    return response


@router.post("/api/auth/logout")
async def logout(request: Request):
    security = request.app.state.security
    if security.mode != "token":
        raise HTTPException(404, "Browser sessions are only available in token mode.")
    security.validate_origin(request)
    security.revoke(request.cookies.get(SESSION_COOKIE))
    response = Response(status_code=204, headers=PRIVATE_HEADERS)
    response.delete_cookie(SESSION_COOKIE, httponly=True, secure=request.url.scheme == "https", samesite="lax")
    return response


@router.get("/", response_class=HTMLResponse)
async def serve_ui(request: Request):
    security = request.app.state.security
    token_mode = security.mode == "token"
    if token_mode and not security.principal_for_session(request.cookies.get(SESSION_COOKIE)):
        return HTMLResponse(LOGIN_PAGE, headers=PRIVATE_HEADERS)
    response = render_dashboard(get_real_incidents_from_chroma(), signed_in=token_mode)
    response.headers.update(PRIVATE_HEADERS)
    return response


def create_app():
    security = Security()
    app = FastAPI(
        title="Cyber SOC Command Center", dependencies=[Depends(authorize_route)],
        docs_url=None, redoc_url=None, openapi_url=None,
    )
    app.state.security = security
    app.state.connections = ConnectionManager(security)
    app.add_middleware(
        CORSMiddleware, allow_origins=security.allowed_origins, allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH"],
        allow_headers=["Authorization", "Content-Type", "X-Review-Token"],
    )
    app.include_router(router)
    app.include_router(grc_router, prefix="/api")
    app.include_router(casework_router, prefix="/api")
    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn
    security = app.state.security
    uvicorn.run(app, host=security.host, port=security.port, forwarded_allow_ips=security.trusted_proxies)
