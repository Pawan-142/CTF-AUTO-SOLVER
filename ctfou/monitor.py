"""Stateful 10-minute CTFd poller. Public challenge metadata only in state."""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from .solver import Finding, solve

CTF_URL = "https://ctfou.saikolabs.in"


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def load_state(path: Path) -> dict:
    if path.exists():
        try:
            value = json.loads(path.read_text("utf-8"))
            if isinstance(value, dict) and value.get("schema_version") == 1:
                return value
        except (OSError, ValueError):
            # Fail rather than rebaseline and potentially spam notifications.
            raise RuntimeError("State file unreadable; restore from version control") from None
        raise RuntimeError("Unknown state version; refusing to reset")
    return {"schema_version": 1, "initialized": False, "challenges": {}}


def save_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, ensure_ascii=False, sort_keys=True, indent=2) + "\n", "utf-8")
    tmp.replace(path)


def digest(detail: dict) -> str:
    data = {
        "description": detail.get("description", ""),
        "files": detail.get("files", []),
    }
    # File URLs contain short-lived signed credentials, don't store or hash their query params.
    data["files"] = [x.split("?", 1)[0] for x in data["files"] if isinstance(x, str)]
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()[:16]


def challenge_url(id_: str) -> str:
    # CTFd uses a /challenges SPA route; deep linking is not guaranteed.
    return f"{CTF_URL}/challenges"


def new_message(item: dict) -> str:
    return (f"🆕 New CTFOU Challenge\n"
            f"Question: {item.get('name', 'Unnamed')}\n"
            f"Category: {item.get('category', 'Unknown')}\n"
            f"Points: {item.get('value', '?')}\n"
            f"Challenge ID: {item.get('id', '?')}\n"
            f"Link: {challenge_url(str(item.get('id', '')))}\n"
            f"Solver: queued (no auto-submission)")


def solved_message(item: dict, finding: Finding) -> str:
    evidence = "Extracted from challenge evidence" if finding.evidence == "extracted" else "AI candidate — NOT verified"
    return (f"🚩 CTFOU Flag Found\n"
            f"Question: {item.get('name', 'Unnamed')}\n"
            f"Category: {item.get('category', 'Unknown')}\n"
            f"Points: {item.get('value', '?')}\n"
            f"Challenge ID: {item.get('id', '?')}\n"
            f"Flag: {finding.flag}\n"
            f"Status: {evidence}; not submitted\n"
            f"Explanation: {finding.explanation}\n"
            f"Link: {challenge_url(str(item.get('id', '')))}")


def boolenv(name: str, default=False) -> bool:
    return os.environ.get(name, str(default)).lower().strip() in {"true", "1", "yes", "on"}


def run_once(client, notifier, state: dict, solver: Callable = solve, timestamp=None) -> dict:
    """Pure-ish orchestrator; callers persist state after a successful run.

    Does not send or request challenge submissions. `client` only has GET APIs.
    """
    current = timestamp or now_utc()
    listings = client.challenges()  # If request fails, do not mutate baseline.
    if not isinstance(listings, list):
        raise RuntimeError("CTFd did not return a challenge list")
    first_run = not state.get("initialized", False)
    solve_existing = boolenv("SOLVE_EXISTING_ON_FIRST_RUN")
    max_attempts = max(1, min(15, int(os.environ.get("MAX_SOLVES_PER_RUN", "3"))))
    retry_hours = max(1, int(os.environ.get("RETRY_UNSOLVED_HOURS", "6")))
    records = state.setdefault("challenges", {})
    candidates: list[tuple[dict, dict]] = []
    for item in listings:
        if not isinstance(item, dict) or not str(item.get("id", "")).isdigit():
            continue
        if item.get("name") in ("???", "", None) or item.get("type") == "hidden":
            continue
        id_ = str(item["id"])
        record = records.get(id_)
        if record is None:
            if first_run and not solve_existing:
                records[id_] = {
                    "name": str(item.get("name", ""))[:160],
                    "status": "baseline",
                    "first_seen": current.isoformat(),
                    "attempts": 0,
                }
                continue
            notifier.send(new_message(item))
            record = {
                "name": str(item.get("name", ""))[:160],
                "status": "queued", "first_seen": current.isoformat(), "attempts": 0,
            }
            records[id_] = record
        if item.get("solved_by_me") is True:
            record["status"] = "already_solved_by_user"
            continue
        if record["status"] in ("found", "already_solved_by_user", "baseline"):
            continue
        if record["status"] == "pending":
            last = record.get("last_attempt")
            try:
                elapsed = current - datetime.fromisoformat(last)
                if elapsed < timedelta(hours=retry_hours):
                    continue
            except (TypeError, ValueError):
                pass
        candidates.append((item, record))

    state["initialized"] = True
    for item, record in candidates[:max_attempts]:
        id_ = str(item["id"])
        try:
            detail = client.challenge(id_)
            if detail.get("name") in ("???", "", None):
                record["status"] = "pending"
                record["last_attempt"] = current.isoformat()
                continue
            finding = solver(detail, client)
            if finding:
                # Mark found only after Telegram delivery.
                notifier.send(solved_message(detail, finding))
                record["status"] = "found"
                record["evidence"] = finding.evidence
            else:
                record["status"] = "pending"
                if boolenv("NOTIFY_UNSOLVED") and record["attempts"] == 0:
                    notifier.send(
                        f"🔎 CTFOU — not solved yet\nQuestion: {item.get('name')}\n"
                        f"No flag extracted. Will retry later.\n{challenge_url(id_)}"
                    )
            record["attempts"] += 1
            record["last_attempt"] = current.isoformat()
            record["detail_fingerprint"] = digest(detail)
            print(f"Challenge {id_}: {record['status']}")
        except Exception as exc:
            # Errors are logged without leaking API file URLs or token contents.
            print(f"Challenge {id_} failed ({type(exc).__name__}); scheduled to retry")
            record["status"] = "queued"
    return state
