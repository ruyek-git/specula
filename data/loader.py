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
