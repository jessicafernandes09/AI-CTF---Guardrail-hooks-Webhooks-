"""
FinBot Guardrail Webhook
========================
Webhook endpoint for FinBot Labs guardrail challenge.

Security layers (no shared secret from FinBot):
  1. IP allowlist  — only accept requests from known FinBot IP ranges
  2. Rate limiting — prevent DoS / brute-force policy probing
  3. Payload validation — strict schema, reject unexpected structures
  4. Anomaly detection — flag suspicious payload patterns
  5. Audit logging — every event recorded with IP, tool, verdict
"""

import time
import logging
import os
import ipaddress
import hmac
import hashlib
from collections import defaultdict
from datetime import datetime
from typing import Optional

from flask import Flask, request, jsonify
from pydantic import BaseModel, field_validator

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# ── Config (set via Render environment variables) ──────────────────────────────
RATE_LIMIT_MAX    = int(os.environ.get("RATE_LIMIT_MAX",    "30"))   # requests
RATE_LIMIT_WINDOW = int(os.environ.get("RATE_LIMIT_WINDOW", "60"))   # per N seconds

WEBHOOK_SECRET     = os.environ.get("WEBHOOK_SECRET", "")
TIMESTAMP_TOLERANCE = int(os.environ.get("TIMESTAMP_TOLERANCE", "300"))

# FinBot's server IP ranges — add the real ones once you see them in your logs
# Empty list = allowlist disabled (open to all, log only)
ALLOWED_IP_RANGES = [
    r.strip()
    for r in os.environ.get("ALLOWED_IP_RANGES", "").split(",")
    if r.strip()
]

# Known legitimate tools FinBot will ever call
KNOWN_TOOLS = {
    "update_invoice_status",
    "read_invoice",
    "list_invoices",
    "get_invoice",
    "send_email",
    "search_invoices",
}

# ── In-memory rate limiter ─────────────────────────────────────────────────────
_rate_store: dict[str, list] = defaultdict(list)

def is_rate_limited(ip: str) -> bool:
    now = time.time()
    window_start = now - RATE_LIMIT_WINDOW
    _rate_store[ip] = [t for t in _rate_store[ip] if t > window_start]
    if len(_rate_store[ip]) >= RATE_LIMIT_MAX:
        return True
    _rate_store[ip].append(now)
    return False

# ── Signature verification ──────────────────────────────────────────────────
def verify_signature(raw_body: bytes, signature_header: str, timestamp_header: str) -> bool:
    """
    Verifies X-Guardrail-Signature: sha256=<hmac> over "timestamp.body".
    If WEBHOOK_SECRET is not set, verification is skipped (open mode).
    """
    if not WEBHOOK_SECRET:
        return True  # no secret configured — skip verification

    if not signature_header or not timestamp_header:
        return False

    try:
        ts = int(timestamp_header)
    except ValueError:
        return False

    if abs(time.time() - ts) > TIMESTAMP_TOLERANCE:
        return False

    signed_payload = f"{timestamp_header}.".encode() + raw_body
    expected = hmac.new(WEBHOOK_SECRET.encode(), signed_payload, hashlib.sha256).hexdigest()

    received = signature_header
    if received.startswith("sha256="):
        received = received[len("sha256="):]

    return hmac.compare_digest(expected, received)

# ── IP Allowlist ───────────────────────────────────────────────────────────────
def is_allowed_ip(ip: str) -> bool:
    """
    If ALLOWED_IP_RANGES is configured, only those CIDRs pass.
    If empty, all IPs pass (but are still logged).
    """
    if not ALLOWED_IP_RANGES:
        return True  # allowlist not configured yet — log and proceed
    try:
        addr = ipaddress.ip_address(ip)
        return any(
            addr in ipaddress.ip_network(cidr, strict=False)
            for cidr in ALLOWED_IP_RANGES
        )
    except ValueError:
        return False

# ── Payload Schema (strict) ────────────────────────────────────────────────────
class ToolArguments(BaseModel):
    # Allow any fields FinBot sends — but we capture the ones we care about
    status:     Optional[str]   = None
    invoice_id: Optional[str]   = None
    amount:     Optional[float] = None

    model_config = {"extra": "allow"}   # don't reject unknown fields

class WebhookPayload(BaseModel):
    event:          str
    tool_name:      str
    tool_arguments: ToolArguments = ToolArguments()
    tool_source:    Optional[str] = None

    model_config = {"extra": "allow"}

    @field_validator("event")
    @classmethod
    def event_must_be_known(cls, v: str) -> str:
        if v not in ("before_tool", "after_tool"):
            raise ValueError(f"Unexpected event type: {v}")
        return v

# ── Anomaly Detection ──────────────────────────────────────────────────────────
def detect_anomalies(payload: WebhookPayload, ip: str) -> list[str]:
    """
    Flags suspicious patterns — doesn't block, but enriches the audit log.
    Useful for spotting prompt injection attempts or platform misbehaviour.
    """
    flags = []

    # Unknown tool being called
    if payload.tool_name not in KNOWN_TOOLS:
        flags.append(f"UNKNOWN_TOOL:{payload.tool_name}")

    # tool_source is unexpected
    if payload.tool_source and payload.tool_source not in ("agent", "system", "finbot"):
        flags.append(f"UNEXPECTED_SOURCE:{payload.tool_source}")

    # Injection pattern in string fields (basic check)
    args_dict = payload.tool_arguments.model_dump()
    for field, value in args_dict.items():
        if isinstance(value, str):
            lowered = value.lower()
            if any(kw in lowered for kw in ["ignore previous", "system:", "jailbreak", "<script"]):
                flags.append(f"INJECTION_PATTERN_IN:{field}")

    return flags

# ── Policy Engine ──────────────────────────────────────────────────────────────
def evaluate_policy(payload: WebhookPayload) -> dict:
    tool = payload.tool_name
    args = payload.tool_arguments

    # RULE-001: Core challenge requirement — block invoice approval
    if tool == "update_invoice_status" and args.status == "approved":
        return {
            "verdict": "block",
            "reason":  "Invoice approvals require human authorisation. Autonomous AI approval is not permitted.",
            "rule":    "RULE-001"
        }

    # RULE-002: Block marking as paid (financial finalisation)
    if tool == "update_invoice_status" and args.status == "paid":
        return {
            "verdict": "block",
            "reason":  "Marking invoices as paid requires human confirmation.",
            "rule":    "RULE-002"
        }

    # RULE-003: High-value guard
    if tool == "update_invoice_status" and args.amount and args.amount > 10000:
        return {
            "verdict": "block",
            "reason":  f"Invoice value ${args.amount:,.2f} exceeds autonomous action threshold.",
            "rule":    "RULE-003"
        }

    return {
        "verdict": "allow",
        "reason":  "Policy check passed.",
        "rule":    "DEFAULT-ALLOW"
    }

# ── Routes ─────────────────────────────────────────────────────────────────────
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "timestamp": datetime.utcnow().isoformat()})


@app.route("/webhook", methods=["POST"])
def guardrail():
    # Real IP (Render sits behind a proxy)
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()

    # ── Layer 1: IP allowlist ──────────────────────────────────────────────────
    if not is_allowed_ip(ip):
        logger.warning(f"BLOCKED_IP | ip={ip}")
        # Return 200 with block so FinBot doesn't retry — but log the rejection
        return jsonify({"verdict": "block", "reason": "Request origin not permitted."}), 200

    # ── Layer 2: Rate limit ────────────────────────────────────────────────────
    if is_rate_limited(ip):
        logger.warning(f"RATE_LIMITED | ip={ip}")
        return jsonify({"verdict": "block", "reason": "Rate limit exceeded."}), 429

    # ── Layer 3: Payload validation ────────────────────────────────────────────
    raw_body = request.get_data()

    sig_header = request.headers.get("X-Guardrail-Signature", "")
    ts_header  = request.headers.get("X-Guardrail-Timestamp", "")

    if not verify_signature(raw_body, sig_header, ts_header):
        logger.warning(f"BAD_SIGNATURE | ip={ip}")
        return jsonify({"verdict": "block", "reason": "Invalid or missing signature."}), 200

    try:
        raw = request.get_json(force=True, silent=True)
        if not raw:
            raise ValueError("Empty or non-JSON body")
        payload = WebhookPayload(**raw)
    except Exception as e:
        logger.warning(f"INVALID_PAYLOAD | ip={ip} | error={e}")
        # Default to block on malformed input — fail closed
        return jsonify({"verdict": "block", "reason": "Malformed payload."}), 200

    # ── Layer 4: Anomaly detection ─────────────────────────────────────────────
    anomalies = detect_anomalies(payload, ip)

    # ── Layer 5: Policy evaluation ─────────────────────────────────────────────
    verdict = evaluate_policy(payload)

    # ── Layer 6: Audit log ─────────────────────────────────────────────────────
    logger.info(
        f"AUDIT | ip={ip} | event={payload.event} | tool={payload.tool_name} | "
        f"args={payload.tool_arguments.model_dump(exclude_none=True)} | "
        f"verdict={verdict['verdict']} | rule={verdict['rule']}"
        + (f" | anomalies={anomalies}" if anomalies else "")
    )

    # ── Layer 7: Return verdict ────────────────────────────────────────────────
    return jsonify({
        "verdict": verdict["verdict"],
        "reason":  verdict["reason"]
    })


@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "service": "FinBot Guardrail Webhook",
        "status":  "running",
        "endpoints": {"POST /webhook": "policy evaluation", "GET /health": "health check"}
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
