"""Load synthetic telemetry and normalise it into the flat alert shape the
pipeline consumes. Real CloudTrail and Okta records are deeply nested; the
normaliser flattens the few fields the agents key on while preserving the
original nested fields so attacker-controllable values (userName, displayName)
still reach the triage fencing logic.
"""

from __future__ import annotations

import json
from pathlib import Path

DATA_DIR = Path(__file__).parent


def _flatten_cloudtrail(rec: dict) -> dict:
    ui = rec.get("userIdentity", {})
    flat = dict(rec)
    flat["id"] = rec.get("eventID", "unknown")
    flat["source"] = "cloudtrail"
    # Keep nested userIdentity (fencing reads userName/principalId from it).
    flat["sourceIPAddress"] = rec.get("sourceIPAddress", "")
    flat["_username"] = ui.get("userName") or ui.get("type", "")
    return flat


def _flatten_okta(rec: dict) -> dict:
    actor = rec.get("actor", {})
    client = rec.get("client", {})
    flat = dict(rec)
    flat["id"] = rec.get("uuid", "unknown")
    flat["source"] = "okta"
    flat["sourceIPAddress"] = client.get("ipAddress", "")
    flat["_username"] = actor.get("alternateId") or actor.get("displayName", "")
    return flat


def load_cloudtrail(path: str | None = None) -> list[dict]:
    p = Path(path) if path else DATA_DIR / "cloudtrail_samples.json"
    records = json.loads(p.read_text()).get("Records", [])
    return [_flatten_cloudtrail(r) for r in records]


def load_okta(path: str | None = None) -> list[dict]:
    p = Path(path) if path else DATA_DIR / "okta_samples.json"
    events = json.loads(p.read_text()).get("events", [])
    return [_flatten_okta(e) for e in events]


def load_all() -> list[dict]:
    return load_cloudtrail() + load_okta()


# --------------------------------------------------------------------------- #
# User-supplied logs (uploaded or pasted). Accepts JSON in several shapes, or  #
# plain text (one log line per alert). Everything is normalised into the flat  #
# alert shape the pipeline consumes, and attacker-controllable text is left    #
# intact so triage fencing still sees it.                                      #
# --------------------------------------------------------------------------- #


def parse_json_blob(blob: str) -> list[dict]:
    """Parse a JSON string in any of the shapes we support:
    a CloudTrail {"Records": [...]}, an Okta {"events": [...]}, a bare list of
    records, or a single record object."""
    data = json.loads(blob)
    alerts: list[dict] = []
    if isinstance(data, dict) and "Records" in data:
        alerts += [_flatten_cloudtrail(r) for r in data["Records"]]
    if isinstance(data, dict) and "events" in data:
        alerts += [_flatten_okta(e) for e in data["events"]]
    if not alerts:
        records = data if isinstance(data, list) else [data]
        for i, rec in enumerate(records):
            if not isinstance(rec, dict):
                continue
            # Guess the schema from telltale keys; default to a generic shape.
            if "eventName" in rec or "userIdentity" in rec:
                alerts.append(_flatten_cloudtrail(rec))
            elif "actor" in rec or "eventType" in rec:
                alerts.append(_flatten_okta(rec))
            else:
                rec.setdefault("id", f"user-json-{i}")
                rec.setdefault("source", "user")
                alerts.append(rec)
    return alerts


def parse_plaintext(text: str) -> list[dict]:
    """Wrap each non-empty line of a plain-text log as a generic alert. The whole
    line is preserved as an attacker-controllable field so fencing still applies."""
    alerts = []
    for i, line in enumerate(l for l in text.splitlines() if l.strip()):
        alerts.append(
            {
                "id": f"user-line-{i}",
                "source": "user-text",
                "raw": line,
                # _username mirrors the raw line so triage fencing inspects it.
                "_username": line,
            }
        )
    return alerts


def parse_upload(content: str, filename: str = "") -> list[dict]:
    """Route an uploaded/pasted blob to the right parser. Tries JSON first
    (regardless of extension), falls back to plain text."""
    content = content.strip()
    if not content:
        return []
    try:
        return parse_json_blob(content)
    except json.JSONDecodeError:
        return parse_plaintext(content)
