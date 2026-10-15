import json
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware

from .database import connect, init_db
from .schemas import AlertIn, SimulateIn
from .detection import classify_alert
from .ai_reasoner import analyze_alert
from .agent_loop import run_investigation
from pydantic import BaseModel
from typing import Literal
from .outcome_reasoner import assess_outcome


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
def investigate(
    alert_id: int,
    x_api_key: str | None = Header(default=None),
):
    require_key(x_api_key)

    # Step 1: Retrieve the alert.
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM alerts WHERE id=?",
            (alert_id,),
        ).fetchone()

    if row is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert = dict(row)

    # Step 2: Gemini-guided evidence collection.
    investigation = run_investigation(alert, max_steps=4)

    # Step 3: Existing Gemini alert assessment.
    result = analyze_alert(alert)

    # Step 4: Do not treat placeholders as verified evidence.
    if result["assessment"] == "ATTACK_CONFIRMED":
        result["assessment"] = "INCONCLUSIVE"
        result["confidence"] = "low"
        result["summary"] = (
            "Attack success is not independently verified. "
            "Additional evidence is required."
        )

    # Step 5: Safe response recommendation.
    action = "NO_AUTOMATIC_ACTION"
    response_status = "SIMULATED_ONLY"

    if result["assessment"] in (
        "POSSIBLE_COMPROMISE",
        "SUSPICIOUS_ACTIVITY",
    ):
        action = "RECOMMEND_ANALYST_REVIEW"

    # Step 6: Store the incident and investigation trace.
    stored_evidence = {
        "alert_evidence": result["evidence"],
        "investigation": investigation,
    }

    with connect() as conn:
        cur = conn.execute(
            """
            INSERT INTO incidents
            (alert_id, assessment, confidence, evidence,
             response_action, response_status)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                alert_id,
                result["assessment"],
                result["confidence"],
                json.dumps(stored_evidence),
                action,
                response_status,
            ),
        )

        incident_id = cur.lastrowid

        conn.execute(
            "UPDATE alerts SET status='investigated' WHERE id=?",
            (alert_id,),
        )

    return {
        "incident_id": incident_id,
        "alert_id": alert_id,
        **result,
        "investigation": investigation,
        "response_action": action,
        "response_status": response_status,
    }

class EvidenceTestRequest(BaseModel):
    scenario: Literal[
        "attack_succeeded",
        "attack_failed",
        "inconclusive",
    ]


@app.post("/testing/evidence-investigation")
def test_evidence_investigation(
    payload: EvidenceTestRequest,
    x_api_key: str | None = Header(default=None),
):
    require_key(x_api_key)

    # This endpoint is for controlled synthetic testing only.
    if os.getenv("SENTINELOPS_ENABLE_TEST_ENDPOINTS") != "true":
        raise HTTPException(
            status_code=404,
            detail="Test endpoint disabled",
        )

    alert = {
        "source_ip": "198.51.100.23",
        "event_type": "failed_login",
        "target": "demo-login",
        "details": "Synthetic authentication investigation",
        "severity": "high",
    }

    investigation = run_investigation(
        alert,
        max_steps=4,
        scenario=payload.scenario,
    )

    outcome = assess_outcome(investigation)

    return {
        "mode": "synthetic_test",
        "scenario": payload.scenario,
        "investigation": investigation,
        "outcome": outcome,
        "response_action": "NO_AUTOMATIC_ACTION",
        "response_status": "SIMULATED_ONLY",
    }
