# SentineLopsSOC-2.0
this is an upgraded version of the last repository
# SentinelOps SOC Starter — Gemini-assisted (safe simulation)

A beginner-friendly FastAPI backend for SentinelOps. It includes SQLite storage, synthetic alerts, rule-based classification, optional Gemini-assisted triage, and simulated-only response recommendations. It does **not** capture live traffic or modify a real firewall.

## 1. Secure setup (Windows PowerShell)

From the project folder:

```powershell
py -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Set secrets only in this terminal session. Replace the placeholder with your own key locally; do not paste it into chat, source code, screenshots, or GitHub:

```powershell
$env:GEMINI_API_KEY="YOUR_GEMINI_KEY_HERE"
$env:SENTINELOPS_API_KEY="replace-this-with-a-long-random-secret"
$env:ALLOWED_ORIGINS="http://localhost:5500,http://127.0.0.1:5500"
```

For a strong local `SENTINELOPS_API_KEY`, generate one with:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Copy the generated value into the environment variable. These variables disappear when you close the terminal; set them again in a new terminal. For deployment, use the hosting provider's secret/environment-variable settings, not a committed `.env` file.

If PowerShell activation is blocked, skip activation and use the venv Python directly:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
$env:GEMINI_API_KEY="YOUR_GEMINI_KEY_HERE"
$env:SENTINELOPS_API_KEY="replace-this-with-a-long-random-secret"
$env:ALLOWED_ORIGINS="http://localhost:5500,http://127.0.0.1:5500"
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

## 2. Start and test

```powershell
python -m uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000/docs`. The backend will use Gemini if the key is configured. If the Gemini request fails or no key is set, it uses the deterministic rule-based fallback and reports `ai_status: fallback_rules`.

1. In `POST /simulate/attack`, create a synthetic alert. Example:

```json
{"scenario":"brute_force","source_ip":"198.51.100.23","target":"demo-login"}
```

2. For protected endpoints, add request header `X-API-Key` with the `SENTINELOPS_API_KEY` value.
3. Copy the returned alert `id`.
4. Call `POST /incidents/{alert_id}/investigate` using that ID.
5. Inspect `assessment`, `confidence`, `evidence`, `recommended_next_steps`, `ai_status`, and `response_status`.

## Security notes

- Never put `GEMINI_API_KEY` in browser JavaScript or the GitHub Pages frontend. Keep model calls on the backend.
- Never commit a real API key. `.env` is ignored by Git; `.env.example` contains placeholders only.
- Treat model output as untrusted advisory data. The application validates its structure and still uses only simulated response actions.
- A single alert usually cannot prove a successful compromise. Correlate with server/authentication logs, asset inventory, vulnerability data, and verification evidence.
- Before deploying publicly, add rate limiting, request-size limits, authentication/authorization, secret rotation, audit logging, and provider-side key restrictions. Restrict CORS to the exact frontend origin you control.
- The demo stores incident evidence in SQLite. Do not send real customer secrets, credentials, or sensitive production logs to a model without an approved data-handling policy.
