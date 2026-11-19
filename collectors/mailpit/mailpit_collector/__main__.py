"""Mailpit collector: a stand-in email security platform for end-to-end collector tests.

It speaks the real collector protocol (pyoaev CollectorDaemon: registration, ping, pending
agent expectations, expectation results and traces) and answers DETECTION and PREVENTION
expectations from what a mailpit server received, matching like an EDR collector does: an
expectation is matched when its implant name (its ``parent_process_name`` signature, e.g.
``openaev_email_smtp<inject>-agent-<agent>``) appears in a received message, in one of three
carriers:

* ``header``: the value of any message header (e.g. ``X-OpenAEV-Implant``);
* ``url``: a URL of the text or HTML body;
* ``attachment``: an attachment's file name or text content.

A matched message is a detection (and not a prevention): "Detected" / "Not Prevented". The
carrier is recorded in the result metadata and in the trace name. Unmatched expectations are left
pending, as an EDR collector leaves them, so expectations meant for other collectors are not
touched.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import requests
from pyoaev.configuration import Configuration
from pyoaev.daemons import CollectorDaemon

ICON = Path(__file__).parent / "img" / "icon.png"
URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+")
# Attachments bigger than this are matched on their name only
MAX_ATTACHMENT_SCAN = 1024 * 1024
RECENT_MESSAGES = 200


def _parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    # OpenAEV sends nanoseconds; datetime only keeps microseconds
    value = value.replace("Z", "+00:00")
    if "." in value:
        head, tail = value.split(".", 1)
        digits = "".join(ch for ch in tail if ch.isdigit())
        zone = tail[len(digits) :]
        value = f"{head}.{digits[:6]}{zone}"
    parsed = datetime.fromisoformat(value)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def find_carrier(implant: str, carriers: dict[str, list[str]]) -> str | None:
    """The first carrier (header, url, attachment) one of whose texts contains the implant."""
    for carrier, texts in carriers.items():
        if any(implant in text for text in texts):
            return carrier
    return None


class MailpitCollector(CollectorDaemon):
    def __init__(self, configuration: Configuration):
        super().__init__(
            configuration=configuration,
            callback=self._process,
            collector_type="staticfire_mailpit",
        )
        self.mailpit_url = self._configuration.get("mailpit_url").rstrip("/")
        self._carriers_by_message: dict[str, dict[str, list[str]]] = {}

    # -- what a message exposes --

    def _get(self, path: str, **params) -> requests.Response:
        response = requests.get(f"{self.mailpit_url}{path}", params=params or None, timeout=15)
        response.raise_for_status()
        return response

    def _recent_messages(self, since: datetime) -> list[dict]:
        messages = self._get("/api/v1/messages", limit=RECENT_MESSAGES).json().get("messages", [])
        return [m for m in messages if (_parse_date(m.get("Created")) or since) >= since]

    def _carriers(self, message_id: str) -> dict[str, list[str]]:
        """Texts of a message per carrier, read once per message."""
        if message_id not in self._carriers_by_message:
            message = self._get(f"/api/v1/message/{message_id}").json()
            headers = self._get(f"/api/v1/message/{message_id}/headers").json()
            body = f"{message.get('Text') or ''}\n{message.get('HTML') or ''}"
            attachments = []
            for attachment in message.get("Attachments") or []:
                attachments.append(attachment.get("FileName") or "")
                if (attachment.get("Size") or 0) <= MAX_ATTACHMENT_SCAN:
                    part = self._get(f"/api/v1/message/{message_id}/part/{attachment['PartID']}")
                    attachments.append(part.content.decode("utf-8", errors="ignore"))
            self._carriers_by_message[message_id] = {
                "header": [value for values in headers.values() for value in values],
                "url": URL_PATTERN.findall(body),
                "attachment": attachments,
            }
        return self._carriers_by_message[message_id]

    # -- answering --

    def _answer(self, expectation: dict, message: dict, carrier: str) -> None:
        detection = expectation["inject_expectation_type"] == "DETECTION"
        result, success = ("Detected", True) if detection else ("Not Prevented", False)
        collector_id = self._configuration.get("collector_id")
        self.api.inject_expectation.update(
            expectation["inject_expectation_id"],
            {
                "collector_id": collector_id,
                "result": result,
                "is_success": success,
                "metadata": {"alertId": message["ID"], "carrier": carrier},
            },
        )
        self.api.inject_expectation_trace.bulk_create(
            payload={
                "expectation_traces": [
                    {
                        "inject_expectation_trace_expectation": expectation[
                            "inject_expectation_id"
                        ],
                        "inject_expectation_trace_source_id": collector_id,
                        "inject_expectation_trace_alert_name": (
                            f"{message.get('Subject')} (implant in {carrier})"
                        ),
                        "inject_expectation_trace_alert_link": (
                            f"{self.mailpit_url}/view/{message['ID']}"
                        ),
                        "inject_expectation_trace_date": message.get("Created"),
                    }
                ]
            }
        )
        self.logger.info(
            f"Answered {expectation['inject_expectation_type']} expectation "
            f"{expectation['inject_expectation_id']} of inject "
            f"{expectation['inject_expectation_inject']}: {result} (implant in {carrier})"
        )

    def _process(self) -> None:
        expectations = [
            e
            for e in self.api.inject_expectation.expectations_assets_for_source(
                self._configuration.get("collector_id")
            )
            if e.get("inject_expectation_type") in ("DETECTION", "PREVENTION")
        ]
        self.logger.info(f"{len(expectations)} pending expectations")
        if not expectations:
            return
        now = datetime.now(UTC)
        created = [_parse_date(e.get("inject_expectation_created_at")) or now for e in expectations]
        messages = self._recent_messages(min(created) - timedelta(minutes=1))
        for expectation, created_at in zip(expectations, created, strict=True):
            implants = [
                s["value"]
                for s in expectation.get("inject_expectation_signatures") or []
                if s.get("type") == "parent_process_name"
            ]
            match = self._match(implants, messages, created_at - timedelta(minutes=1))
            if match:
                self._answer(expectation, *match)

    def _match(
        self, implants: list[str], messages: list[dict], since: datetime
    ) -> tuple[dict, str] | None:
        for message in messages:
            if (_parse_date(message.get("Created")) or since) < since:
                continue
            carriers = self._carriers(message["ID"])
            for implant in implants:
                if carrier := find_carrier(implant, carriers):
                    return message, carrier
        return None


def main() -> None:
    configuration = Configuration(
        config_hints={
            "openaev_url": {"env": "OPENAEV_URL", "file_path": ["openaev", "url"]},
            "openaev_token": {"env": "OPENAEV_TOKEN", "file_path": ["openaev", "token"]},
            "collector_id": {"env": "COLLECTOR_ID", "file_path": ["collector", "id"]},
            "collector_name": {
                "env": "COLLECTOR_NAME",
                "file_path": ["collector", "name"],
                "default": "Mailpit (staticfire)",
            },
            "collector_period": {
                "env": "COLLECTOR_PERIOD",
                "file_path": ["collector", "period"],
                "is_number": True,
                "default": 15,
            },
            "collector_log_level": {
                "env": "COLLECTOR_LOG_LEVEL",
                "file_path": ["collector", "log_level"],
                "default": "info",
            },
            "collector_platform": {
                "env": "COLLECTOR_PLATFORM",
                "file_path": ["collector", "platform"],
                "default": "EMAIL_SECURITY",
            },
            "collector_icon_filepath": {"data": str(ICON)},
            "mailpit_url": {"env": "MAILPIT_URL", "file_path": ["mailpit", "url"]},
        },
    )
    MailpitCollector(configuration).start()


if __name__ == "__main__":
    main()
