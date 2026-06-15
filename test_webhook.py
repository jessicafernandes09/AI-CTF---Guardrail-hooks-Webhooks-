"""
Local test script — run this BEFORE deploying to verify your webhook logic.
Usage: python test_webhook.py
"""

import requests
import json
import hmac
import hashlib
import time

BASE_URL = "http://localhost:5000"
SECRET   = ""  # Leave empty if WEBHOOK_SECRET not set locally

def make_headers(payload: dict) -> dict:
    body = json.dumps(payload).encode()
    timestamp = str(int(time.time()))
    headers = {
        "Content-Type": "application/json",
        "X-Webhook-Timestamp": timestamp,
    }
    if SECRET:
        sig = hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()
        headers["X-Webhook-Signature"] = f"sha256={sig}"
    return headers


def test(label: str, payload: dict, expected_verdict: str):
    headers = make_headers(payload)
    r = requests.post(f"{BASE_URL}/webhook", json=payload, headers=headers)
    result = r.json()
    verdict = result.get("verdict", "ERROR")
    status = "✅ PASS" if verdict == expected_verdict else "❌ FAIL"
    print(f"{status} | {label}")
    print(f"       payload : {payload['tool_name']} args={payload.get('tool_arguments', {})}")
    print(f"       response: {result}\n")


if __name__ == "__main__":
    print("=" * 60)
    print("FinBot Guardrail Webhook — Local Tests")
    print("=" * 60 + "\n")

    # ── Should BLOCK ───────────────────────────────────────────────
    test(
        label="Block: update_invoice_status approved",
        payload={
            "event": "before_tool",
            "tool_name": "update_invoice_status",
            "tool_arguments": {"invoice_id": "INV-001", "status": "approved"}
        },
        expected_verdict="block"
    )

    test(
        label="Block: update_invoice_status paid",
        payload={
            "event": "before_tool",
            "tool_name": "update_invoice_status",
            "tool_arguments": {"invoice_id": "INV-002", "status": "paid"}
        },
        expected_verdict="block"
    )

    test(
        label="Block: high-value invoice",
        payload={
            "event": "before_tool",
            "tool_name": "update_invoice_status",
            "tool_arguments": {"invoice_id": "INV-003", "status": "pending", "amount": 50000}
        },
        expected_verdict="block"
    )

    # ── Should ALLOW ───────────────────────────────────────────────
    test(
        label="Allow: read_invoice",
        payload={
            "event": "before_tool",
            "tool_name": "read_invoice",
            "tool_arguments": {"invoice_id": "INV-001"}
        },
        expected_verdict="allow"
    )

    test(
        label="Allow: update_invoice_status pending",
        payload={
            "event": "before_tool",
            "tool_name": "update_invoice_status",
            "tool_arguments": {"invoice_id": "INV-004", "status": "pending"}
        },
        expected_verdict="allow"
    )

    test(
        label="Allow: list_invoices",
        payload={
            "event": "before_tool",
            "tool_name": "list_invoices",
            "tool_arguments": {}
        },
        expected_verdict="allow"
    )
