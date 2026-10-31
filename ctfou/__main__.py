from __future__ import annotations

import os
import sys
from pathlib import Path

from .api import CTFdClient
from .monitor import load_state, run_once, save_state
from .notify import TelegramNotifier


def main() -> int:
    token = os.environ.get("CTFOU_ACCESS_TOKEN", "").strip()
    bot_token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
    missing = [name for name, value in [
        ("CTFOU_ACCESS_TOKEN", token),
        ("TELEGRAM_BOT_TOKEN", bot_token),
        ("TELEGRAM_CHAT_ID", chat_id),
    ] if not value]
    if missing:
        print("Missing environment secrets: " + ", ".join(missing))
        return 2
    state_path = Path(os.environ.get("CTFOU_STATE_PATH", "state/state.json"))
    try:
        client = CTFdClient(token)
        notifier = TelegramNotifier(bot_token, chat_id)
        state = load_state(state_path)
        new_state = run_once(client, notifier, state)
        save_state(state_path, new_state)
        print("Monitor completed: %d tracked challenges" % len(state["challenges"]))
        return 0
    except Exception as exc:
        print(f"Monitor failed ({type(exc).__name__}). Check API access and secrets.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
