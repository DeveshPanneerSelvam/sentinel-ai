"""SentinelAI MCP server.

Exposes SentinelAI's alerts as tools an AI agent (Claude Desktop, Claude Code,
or any MCP client) can call. Runs over stdio.

    pip install -r requirements.txt -r requirements-mcp.txt
    python mcp_server.py

Read-only by default. Set SENTINEL_MCP_ALLOW_WRITES=true to enable the note tool.
"""

import json
import logging
import os
import sys
import time
from collections.abc import Callable
from functools import wraps
from typing import Any

from mcp.server.fastmcp import FastMCP

from app.db import SessionLocal, init_db
from app.services import agent_tools

WRITES_ENABLED = os.getenv("SENTINEL_MCP_ALLOW_WRITES", "false").lower() == "true"

# stdio servers must never print to stdout (that's the protocol channel),
# so structured logs go to stderr as one JSON object per line.
logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="%(message)s")
log = logging.getLogger("sentinelai.mcp")

mcp = FastMCP("sentinelai")


def _run(tool_name: str, fn: Callable[..., dict[str, Any]], **kwargs: Any) -> dict[str, Any]:
    """Open a DB session, run a tool, and log a structured trace line."""
    started = time.perf_counter()
    status = "exception"
    db = SessionLocal()
    try:
        result = fn(db, **kwargs)
        status = "error" if "error" in result else "ok"
        return result
    except Exception as exc:  # never crash the server on one bad call
        log.exception("tool failed")
        return {"error": f"{tool_name} failed: {exc.__class__.__name__}"}
    finally:
        db.close()
        log.info(
            json.dumps(
                {
                    "event": "tool_call",
                    "tool": tool_name,
                    "args": kwargs,
                    "status": status,
                    "ms": round((time.perf_counter() - started) * 1000, 1),
                },
                default=str,
            )
        )


@mcp.tool()
def list_alerts(min_severity: str = "low", category: str | None = None, limit: int = 20) -> dict:
    """List security alerts, highest risk first.

    Args:
        min_severity: lowest severity to include: low, medium, high, or critical.
        category: optional filter, e.g. failed_login_burst, impossible_travel,
            privilege_escalation, beaconing, ml_anomaly.
        limit: max alerts to return (1-50).
    """
    return _run(
        "list_alerts",
        agent_tools.list_alerts,
        min_severity=min_severity,
        category=category,
        limit=limit,
    )


@mcp.tool()
def get_alert(alert_id: int) -> dict:
    """Get one alert's full detail: evidence, entities, MITRE mapping, explanation, and analyst notes."""
    return _run("get_alert", agent_tools.get_alert, alert_id=alert_id)


@mcp.tool()
def summarize_alerts() -> dict:
    """Get alert counts by severity and category, plus the three highest-risk alerts."""
    return _run("summarize_alerts", agent_tools.summarize_alerts)


@mcp.tool()
def add_investigation_note(alert_id: int, body: str) -> dict:
    """Add an investigation note to an alert (disabled unless the operator enables writes).

    Notes are prefixed with [agent] so analysts can tell them apart from human notes.
    """
    return _run(
        "add_investigation_note",
        agent_tools.add_investigation_note,
        alert_id=alert_id,
        body=body,
        writes_enabled=WRITES_ENABLED,
    )


if __name__ == "__main__":
    init_db()
    log.info(json.dumps({"event": "startup", "writes_enabled": WRITES_ENABLED}))
    mcp.run()
