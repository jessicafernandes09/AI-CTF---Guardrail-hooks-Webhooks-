# FinBot Guardrail Webhook

A production-ready guardrail webhook for the **FinBot Labs** challenge — an interception layer that sits between an AI agent's tool-calling decisions and actual execution, enforcing runtime security policy.

## What This Does

When FinBot's AI agent attempts to call a tool, it fires a `before_tool` event to this webhook. The webhook inspects the payload and returns a `allow` or `block` verdict **before** the tool executes.

```
FinBot Agent → tool call → [this webhook] → verdict → tool executes / blocked
```

### Policy Rules

| Rule | Condition | Verdict |
|---|---|---|
| RULE-001 | `update_invoice_status` with `status: approved` | block |
| RULE-002 | `update_invoice_status` with `status: paid` | block |
| RULE-003 | `update_invoice_status` with `amount > 10000` | block |
| DEFAULT | Everything else | allow |

---

## Security Layers

Since FinBot sends no webhook signature, all security is implemented on the receiver side:

| Layer | Mechanism | Purpose |
|---|---|---|
| IP Allowlist | `ALLOWED_IP_RANGES` env var | Only accept requests from FinBot's servers |
| Rate Limiting | 30 req/min per IP (in-memory) | Prevent DoS / policy probing |
| Payload Validation | Pydantic schema | Reject malformed or unexpected payloads |
| Anomaly Detection | Pattern matching on field values | Flag injection attempts in arguments |
| Fail Closed | Malformed payload → `block` | Default to deny, never default to allow |
| Audit Logging | Structured log per request | Full forensic trail |

---

## Project Structure

```
finbot-webhook/
├── app.py              # Main Flask webhook application
├── requirements.txt    # Python dependencies
├── render.yaml         # Render.com deployment config
├── test_webhook.py     # Local test suite
└── README.md
```

---

## Local Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Start the server
python app.py
# Runs on http://localhost:5000
```

### Run tests

In a second terminal:

```bash
python test_webhook.py
```

Expected output:
```
✅ PASS | Block: update_invoice_status approved
✅ PASS | Block: update_invoice_status paid
✅ PASS | Block: high-value invoice
✅ PASS | Allow: read_invoice
✅ PASS | Allow: update_invoice_status pending
✅ PASS | Allow: list_invoices
```

### Manual curl tests

```bash
# Should BLOCK
curl -X POST http://localhost:5000/webhook \
  -H "Content-Type: application/json" \
  -d '{"event":"before_tool","tool_name":"update_invoice_status","tool_arguments":{"invoice_id":"INV-001","status":"approved"}}'

# Should ALLOW
curl -X POST http://localhost:5000/webhook \
  -H "Content-Type: application/json" \
  -d '{"event":"before_tool","tool_name":"read_invoice","tool_arguments":{"invoice_id":"INV-001"}}'

# Should BLOCK (fail closed on malformed payload)
curl -X POST http://localhost:5000/webhook \
  -H "Content-Type: application/json" \
  -d '{"random":"junk"}'
```

---

## Deploy to Render

### Step 1 — Connect repo
1. Go to [render.com](https://render.com) → **New → Web Service**
2. Connect your GitHub repo
3. Render detects `render.yaml` automatically

### Step 2 — Set environment variables
In Render dashboard → **Environment**:

| Variable | Value | Notes |
|---|---|---|
| `ALLOWED_IP_RANGES` | e.g. `203.0.113.45/32` | Set after first request — check logs for FinBot's IP |
| `RATE_LIMIT_MAX` | `30` | Requests per window |
| `RATE_LIMIT_WINDOW` | `60` | Window in seconds |

### Step 3 — Deploy
Click **Deploy**. Your webhook URL will be:
```
https://finbot-guardrail-webhook.onrender.com/webhook
```

### Step 4 — Lock down IP allowlist
After FinBot sends its first request, check Render logs:
```
AUDIT | ip=203.0.113.45 | event=before_tool | ...
```
Copy that IP and set `ALLOWED_IP_RANGES=203.0.113.45/32` in Render environment variables. This is the primary hardening step when no shared secret is available.

---

## Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/webhook` | Guardrail policy evaluation |
| `GET` | `/health` | Health check |
| `GET` | `/` | Service info |

### Webhook Payload (incoming from FinBot)

```json
{
  "event": "before_tool",
  "tool_name": "update_invoice_status",
  "tool_source": "agent",
  "tool_arguments": {
    "invoice_id": "INV-001",
    "status": "approved"
  }
}
```

### Verdict Response (your webhook returns)

```json
{
  "verdict": "block",
  "reason": "Invoice approvals require human authorisation. Autonomous AI approval is not permitted."
}
```

---

## Security Concepts

This project demonstrates **runtime policy enforcement for AI agents** — a core concept in agentic AI security:

- **OWASP AA01 (Excessive Agency)** — blocks the agent from autonomously approving invoices
- **OWASP AA02 (Unsafe Action Execution)** — intercepts dangerous tool calls before they execute
- **Fail Closed Principle** — unknown/malformed input defaults to `block`, never `allow`
- **Defense in Depth** — multiple independent layers; no single point of failure
- **Separation of Duties** — the agent decides *what* to do; the webhook decides *whether* it's allowed

---

## Author

Jessica Fernandes — Security Engineer  
Portfolio project for AI/Agentic Security research
