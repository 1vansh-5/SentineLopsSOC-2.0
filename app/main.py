import json
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware

from .database import connect, init_db
from .schemas import AlertIn, SimulateIn
from .detection import classify_alert
from .ai_reasoner import analyze_alert

API_KEY = os.getenv("SENTINELOPS_API_KEY")
ALLOWED_ORIGINS = [x.strip() for x in os.getenv(
    "ALLOWED_ORIGINS", "http://localhost:5500,http://127.0.0.1:5500"
).split(",") if x.strip()]

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(title="SentinelOps Starter API", version="0.2.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-API-Key"],
)

def require_key(x_api_key: str | None):
    if not API_KEY:
        raise HTTPException(status_code=503, detail="Server API key is not configured")
    if not x_api_key or x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Missing or invalid X-API-Key")

def save_alert(payload: AlertIn):
    result = classify_alert(payload.event_type, payload.details, payload.severity)
    with connect() as conn:
        cur = conn.execute(
            "INSERT INTO alerts (source_ip,event_type,target,details,severity,status) VALUES (?,?,?,?,?,?)",
            (payload.source_ip, payload.event_type, payload.target, payload.details, payload.severity,
             "needs_review" if result["needs_review"] else "new")
        )
        alert_id = cur.lastrowid
    return {"id": alert_id, "detection": result}

@app.get("/health")
def health():
    return {"status": "ok", "service": "sentinelops-api", "mode": "simulation-first"}

@app.get("/alerts")
def list_alerts():
    with connect() as conn:
        rows = conn.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 100").fetchall()
    return [dict(r) for r in rows]

@app.get("/incidents")
def list_incidents():
    with connect() as conn:
        rows = conn.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT 100").fetchall()
    output = []
    for r in rows:
        item = dict(r)
        item["evidence"] = json.loads(item["evidence"])
        output.append(item)
    return output

@app.post("/webhook/alert")
def receive_sensor_alert(payload: AlertIn, x_api_key: str | None = Header(default=None)):
    """Webhook endpoint for an authorized sensor or a local test client."""
    require_key(x_api_key)
    return save_alert(payload)

@app.post("/simulate/attack")
def simulate_attack(payload: SimulateIn, x_api_key: str | None = Header(default=None)):
    """Generate safe synthetic events; no traffic is sent and no real system is changed."""
    require_key(x_api_key)
    if payload.scenario == "brute_force":
        alert = AlertIn(source_ip=payload.source_ip, event_type="failed_login",
                        target=payload.target, details="Synthetic demo: repeated failed logins",
                        severity="high")
    elif payload.scenario == "sql_injection":
        alert = AlertIn(source_ip=payload.source_ip, event_type="sql_injection",
                        target=payload.target, details="Synthetic demo: possible SQL injection pattern",
                        severity="high")
    else:
        alert = AlertIn(source_ip=payload.source_ip, event_type="successful_login",
                        target=payload.target, details="Synthetic demo: normal login; no preceding failures",
                        severity="low")
    return save_alert(alert)

@app.post("/incidents/{alert_id}/investigate")
def investigate(alert_id: int, x_api_key: str | None = Header(default=None)):
    require_key(x_api_key)
    with connect() as conn:
        row = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Alert not found")
        alert = dict(row)
        result = analyze_alert(alert)
        # Safe by default: response is simulation-only, never calls a real firewall.
        action = "NO_AUTOMATIC_ACTION"
        response_status = "SIMULATED_ONLY"
        if result["assessment"] in ("POSSIBLE_COMPROMISE", "SUSPICIOUS_ACTIVITY", "ATTACK_CONFIRMED"):
            action = "RECOMMEND_ANALYST_REVIEW"
        cur = conn.execute(
            "INSERT INTO incidents (alert_id,assessment,confidence,evidence,response_action,response_status) VALUES (?,?,?,?,?,?)",
            (alert_id, result["assessment"], result["confidence"], json.dumps(result["evidence"]),
             action, response_status)
        )
        incident_id = cur.lastrowid
        conn.execute("UPDATE alerts SET status='investigated' WHERE id=?", (alert_id,))
    return {"incident_id": incident_id, "alert_id": alert_id, **result,
            "response_action": action, "response_status": response_status}

