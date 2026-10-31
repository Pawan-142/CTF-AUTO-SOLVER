"""Plain-text Telegram notifications. No Markdown injection and no flag submissions."""
from __future__ import annotations

import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class TelegramError(Exception):
    pass


class TelegramNotifier:
    def __init__(self, bot_token: str, chat_id: str):
        self.bot_token = bot_token.strip()
        self.chat_id = chat_id.strip()
        if not self.bot_token or not self.chat_id:
            raise ValueError("TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID are required")

    def send(self, content: str) -> None:
        payload = json.dumps({
            "chat_id": self.chat_id,
            "text": content[:4000],
            "disable_web_page_preview": True,
        }).encode("utf-8")
        # Telegram bot token is an HTTPS URL component, never print this URL.
        request = Request(
            f"https://api.telegram.org/bot{self.bot_token}/sendMessage",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=15) as response:
                result = json.load(response)
                if not result.get("ok"):
                    raise TelegramError("Telegram rejected the notification")
        except HTTPError as exc:
            raise TelegramError(f"Telegram API returned HTTP {exc.code}") from None
        except (URLError, TimeoutError, OSError, ValueError):
            raise TelegramError("Telegram notification could not be delivered") from None
