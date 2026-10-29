"""
Module 3 — Banking Chatbot (lab stub)
Extended in Module 6 Project 3 with PCI DSS compliance guardrails.
"""

from __future__ import annotations

import json
import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from llm_client import get_llm_client, resolve_model

load_dotenv()

FINANCIAL_KEYWORDS = frozenset({
    "balance", "transfer", "account", "statement", "loan",
    "credit", "debit", "transaction", "payment",
})

_SESSION_RATE_LIMIT = 20
_MAX_MESSAGE_LENGTH = 5000

# Stores (count, last_updated_timestamp) per session_id for TTL-based expiry
_session_counts: dict[str, tuple[int, datetime]] = {}
_SESSION_TTL_HOURS = 24

AUDIT_PATH = Path("audit_log/chatbot_tool_calls.jsonl")


def _is_session_expired(last_updated: datetime) -> bool:
    age_hours = (datetime.now(timezone.utc) - last_updated).total_seconds() / 3600
    return age_hours >= _SESSION_TTL_HOURS


def is_financial_query(user_message: str) -> bool:
    """Return True if the message looks like a financial query."""
    tokens = set(user_message.lower().split())
    return bool(tokens & FINANCIAL_KEYWORDS)


def pre_response_pii_filter(response: str) -> str:
    # Unformatted card numbers (13-19 consecutive digits)
    response = re.sub(r"\b\d{13,19}\b", "[REDACTED-CARD]", response)
    # Formatted card numbers with spaces or dashes (e.g. 4111 1111 1111 1111)
    response = re.sub(
        r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{3,4}\b",
        "[REDACTED-CARD]",
        response,
    )
    # Account numbers (8-12 consecutive digits)
    response = re.sub(r"\b\d{8,12}\b", "[REDACTED-ACCT]", response)
    # SSN pattern
    response = re.sub(r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED-SSN]", response)
    return response


def rate_limit_check(session_id: str, user_message: str = "balance") -> None:
    if not is_financial_query(user_message):
        return
    now = datetime.now(timezone.utc)
    current_count, last_updated = _session_counts.get(session_id, (0, now))
    # Reset counter if session TTL has expired
    if _is_session_expired(last_updated):
        current_count = 0
    count = current_count + 1
    _session_counts[session_id] = (count, now)
    if count > _SESSION_RATE_LIMIT:
        raise RuntimeError(
            f"Rate limit exceeded: {count} financial queries in session {session_id}"
        )


def write_audit_log_entry(event: dict) -> None:
    AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "CHATBOT_TOOL_CALL",
        **event,
    }
    with open(AUDIT_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
    # Restrict log file permissions: owner read/write only (PCI DSS Req 10.6)
    try:
        os.chmod(AUDIT_PATH, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def _validate_message(user_message: str) -> str:
    """Validate and sanitize incoming user message (PCI DSS Req 6.5.1)."""
    if not isinstance(user_message, str):
        raise ValueError("user_message must be a string")
    # Enforce length limit
    if len(user_message) > _MAX_MESSAGE_LENGTH:
        raise ValueError(f"Message exceeds maximum length of {_MAX_MESSAGE_LENGTH}")
    # Ensure valid UTF-8 (re-encode to catch any bad bytes)
    user_message.encode("utf-8").decode("utf-8")
    return user_message


def run_with_guardrails(user_message: str, session_id: str) -> str:
    user_message = _validate_message(user_message)
    rate_limit_check(session_id, user_message)
    raw = call_claude(user_message)
    filtered = pre_response_pii_filter(raw)
    # Log a PII-filtered snapshot of the message for audit trail (Req 10.2.1)
    safe_message_preview = pre_response_pii_filter(user_message[:200])
    write_audit_log_entry({
        "session_id": session_id,
        "user_message_preview": safe_message_preview,
        "financial_query": is_financial_query(user_message),
        "response_length": len(filtered),
    })
    return filtered


def call_claude(user_message: str, tools: list[dict[str, Any]] | None = None) -> str:
    """Send a user message to Claude and return the text response."""
    client = get_llm_client()
    response = client.messages.create(
        model=resolve_model("claude-sonnet-4-5"),
        max_tokens=1024,
        tools=tools or [],
        messages=[{"role": "user", "content": user_message}],
    )
    for block in response.content:
        if block.type == "text":
            return block.text
    return ""


def handle_message(user_message: str) -> str:
    """Basic chatbot handler — guardrails added in Module 6 Project 3."""
    return call_claude(user_message)


if __name__ == "__main__":
    print(handle_message("What services does Heritage National Bank offer?"))
