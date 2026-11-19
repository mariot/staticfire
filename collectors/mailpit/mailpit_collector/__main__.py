"""Mailpit collector: a stand-in email security platform for end-to-end collector tests.

It speaks the real collector protocol (pyoaev CollectorDaemon: registration, ping, pending
agent expectations, expectation results and traces) and answers DETECTION and PREVENTION
expectations of email injects from what a mailpit server received:

* the recipients come from the expectation's ``target_email`` signatures when the platform
  attached some, otherwise from the inject content (``to``/``cc``/``bcc``), with its subject;
* a delivered matching message is a detection (and not a prevention): "Detected" /
  "Not Prevented";
* no message after ``COLLECTOR_MAILPIT_GRACE`` seconds counts as blocked: "Not Detected" /
  "Prevented".

Expectations of injects that are not emails (no recipient) are left to other collectors.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import requests
from pyoaev.configuration import Configuration
from pyoaev.daemons import CollectorDaemon

ICON = Path(__file__).parent / "img" / "icon.png"
RECIPIENT_FIELDS = ("to", "cc", "bcc")


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


def _split(addresses: str | list | None) -> list[str]:
    if not addresses:
        return []
    if isinstance(addresses, list):
        addresses = ",".join(str(a) for a in addresses)
    return [a.strip() for a in addresses.replace(";", ",").split(",") if a.strip()]


class MailpitCollector(CollectorDaemon):
    def __init__(self, configuration: Configuration):
        super().__init__(
            configuration=configuration,
            callback=self._process,
            collector_type="staticfire_mailpit",
        )
        self.mailpit_url = self._configuration.get("mailpit_url").rstrip("/")
        self.grace = int(self._configuration.get("mailpit_grace") or 120)
        self._injects: dict[str, dict] = {}

    # -- matching data --

    def _inject_content(self, inject_id: str) -> dict:
        if inject_id not in self._injects:
            inject = self.api.http_get(f"/injects/{inject_id}")
            self._injects[inject_id] = (inject or {}).get("inject_content") or {}
        return self._injects[inject_id]

    def _criteria(self, expectation: dict) -> tuple[list[str], str | None]:
        signatures = expectation.get("inject_expectation_signatures") or []
        recipients = [s["value"] for s in signatures if s.get("type") == "target_email"]
        content = self._inject_content(expectation["inject_expectation_inject"])
        if not recipients:
            for field in RECIPIENT_FIELDS:
                recipients += _split(content.get(field))
        return recipients, content.get("subject")

    def _delivered(self, recipient: str, subject: str | None, since: datetime) -> list[dict]:
        query = f'to:"{recipient}"'
        if subject:
            query += ' subject:"' + subject.replace('"', " ") + '"'
        response = requests.get(
            f"{self.mailpit_url}/api/v1/search", params={"query": query}, timeout=15
        )
        response.raise_for_status()
        messages = response.json().get("messages", [])
        return [m for m in messages if (_parse_date(m.get("Created")) or since) >= since]

    # -- answering --

    def _answer(self, expectation: dict, message: dict | None) -> None:
        detection = expectation["inject_expectation_type"] == "DETECTION"
        if message:
            result, success = ("Detected", True) if detection else ("Not Prevented", False)
        else:
            result, success = ("Not Detected", False) if detection else ("Prevented", True)
        collector_id = self._configuration.get("collector_id")
        update = {"collector_id": collector_id, "result": result, "is_success": success}
        if message:
            update["metadata"] = {"alertId": message["ID"]}
        self.api.inject_expectation.update(expectation["inject_expectation_id"], update)
        if message:
            self.api.inject_expectation_trace.bulk_create(
                payload={
                    "expectation_traces": [
                        {
                            "inject_expectation_trace_expectation": expectation[
                                "inject_expectation_id"
                            ],
                            "inject_expectation_trace_source_id": collector_id,
                            "inject_expectation_trace_alert_name": message.get("Subject"),
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
            f"{expectation['inject_expectation_inject']}: {result}"
        )

    def _process(self) -> None:
        expectations = self.api.inject_expectation.expectations_assets_for_source(
            self._configuration.get("collector_id")
        )
        self.logger.info(f"{len(expectations)} pending expectations")
        now = datetime.now(UTC)
        for expectation in expectations:
            if expectation.get("inject_expectation_type") not in ("DETECTION", "PREVENTION"):
                continue
            recipients, subject = self._criteria(expectation)
            if not recipients:
                continue
            created = _parse_date(expectation.get("inject_expectation_created_at")) or now
            since = created - timedelta(minutes=1)
            messages = [m for r in recipients for m in self._delivered(r, subject, since)]
            if messages:
                self._answer(expectation, messages[0])
            elif (now - created).total_seconds() > self.grace:
                self._answer(expectation, None)


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
            "mailpit_grace": {
                "env": "COLLECTOR_MAILPIT_GRACE",
                "file_path": ["mailpit", "grace"],
                "is_number": True,
                "default": 120,
            },
        },
    )
    MailpitCollector(configuration).start()


if __name__ == "__main__":
    main()
