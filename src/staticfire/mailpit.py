"""Mailpit HTTP API client: what did the email injectors actually deliver?"""

from __future__ import annotations

import time

import httpx


class Mailpit:
    def __init__(self, base_url: str, timeout: float = 15.0):
        self.base_url = base_url.rstrip("/")
        self.http = httpx.Client(base_url=self.base_url, timeout=timeout)

    def info(self) -> dict:
        return self.http.get("/api/v1/info").raise_for_status().json()

    def search(self, query: str, limit: int = 50) -> list[dict]:
        """Message summaries matching a mailpit search query (e.g. ``to:"a@b.c"``)."""
        response = self.http.get("/api/v1/search", params={"query": query, "limit": limit})
        return response.raise_for_status().json().get("messages", [])

    def messages(self, limit: int = 100) -> list[dict]:
        """Latest message summaries, newest first."""
        response = self.http.get("/api/v1/messages", params={"limit": limit})
        return response.raise_for_status().json().get("messages", [])

    def part(self, message_id: str, part_id: str) -> bytes:
        """Raw content of a message part (an attachment)."""
        return (
            self.http.get(f"/api/v1/message/{message_id}/part/{part_id}").raise_for_status().content
        )

    def message(self, message_id: str) -> dict:
        return self.http.get(f"/api/v1/message/{message_id}").raise_for_status().json()

    def headers(self, message_id: str) -> dict[str, list[str]]:
        return self.http.get(f"/api/v1/message/{message_id}/headers").raise_for_status().json()

    def delete_search(self, query: str) -> None:
        self.http.delete("/api/v1/search", params={"query": query}).raise_for_status()

    def wait_for(self, query: str, timeout: float = 60.0, interval: float = 2.0) -> list[dict]:
        """Poll until at least one message matches ``query`` or the timeout expires."""
        deadline = time.monotonic() + timeout
        while True:
            messages = self.search(query)
            if messages or time.monotonic() >= deadline:
                return messages
            time.sleep(interval)

    def describe(self, message_id: str) -> dict:
        """The parts of a message a test usually asserts on, in one flat dict."""
        msg = self.message(message_id)
        headers = self.headers(message_id)

        def addresses(entries: list[dict] | None) -> list[str]:
            return [entry.get("Address", "") for entry in entries or []]

        return {
            "id": msg.get("ID"),
            "message_id": msg.get("MessageID"),
            "date": msg.get("Date"),
            "from": (msg.get("From") or {}).get("Address"),
            "to": addresses(msg.get("To")),
            "cc": addresses(msg.get("Cc")),
            "bcc": addresses(msg.get("Bcc")),
            "reply_to": addresses(msg.get("ReplyTo")),
            "return_path": msg.get("ReturnPath"),
            "subject": msg.get("Subject"),
            "text": msg.get("Text"),
            "html": msg.get("HTML"),
            "attachments": [
                {
                    "file_name": a.get("FileName"),
                    "content_type": a.get("ContentType"),
                    "size": a.get("Size"),
                    "part_id": a.get("PartID"),
                }
                for a in msg.get("Attachments") or []
            ],
            "custom_headers": {k: v for k, v in headers.items() if k.lower().startswith("x-")},
        }
