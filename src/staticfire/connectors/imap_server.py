"""A minimal IMAP4rev1 server over TLS (the certificate ofapi uses), for connectors reading mail.

Not a connector: it serves the messages of ofapi's ``/mailbox/messages`` (loaded each time a
client selects the mailbox, which also records the visit in ofapi's journal). It speaks what
``imaplib`` and ``imap_tools`` need: LOGIN, SELECT, SEARCH (FROM, SINCE), FETCH, their UID
forms, CLOSE and LOGOUT. It runs in a thread of the process running the test.
"""

from __future__ import annotations

import asyncio
import re
import ssl
import threading
from datetime import UTC, datetime
from email import message_from_bytes
from email.utils import parseaddr, parsedate_to_datetime

import httpx

from staticfire.fakes import Ofapi, tls_files

_server: dict = {}
_lock = threading.Lock()


def ensure(fake: Ofapi) -> int:
    """The port of the running server (started on first use, for the life of the process)."""
    with _lock:
        if "port" not in _server:
            ready = threading.Event()
            threading.Thread(target=_serve, args=(fake, ready), daemon=True).start()
            if not ready.wait(10):
                raise RuntimeError("the IMAP fake did not start")
        return _server["port"]


def _serve(fake: Ofapi, ready: threading.Event) -> None:
    loop = asyncio.new_event_loop()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    cert, key = tls_files()
    context.load_cert_chain(cert, key)

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await Session(fake, reader, writer).run()

    async def main() -> None:
        server = await asyncio.start_server(handler, "127.0.0.1", 0, ssl=context)
        _server["port"] = server.sockets[0].getsockname()[1]
        ready.set()
        await server.serve_forever()

    loop.run_until_complete(main())


class Session:
    def __init__(self, fake: Ofapi, reader, writer) -> None:
        self.fake = fake
        self.reader = reader
        self.writer = writer
        self.messages: list[tuple[int, bytes]] = []

    def send(self, line: str) -> None:
        self.writer.write(line.encode() + b"\r\n")

    async def run(self) -> None:
        self.send("* OK [CAPABILITY IMAP4rev1 UIDPLUS] staticfire IMAP ready")
        try:
            while line := await self.reader.readline():
                tag, _, rest = line.decode(errors="replace").rstrip("\r\n").partition(" ")
                command, _, args = rest.partition(" ")
                if await self.handle(tag, command.upper(), args):
                    break
                await self.writer.drain()
        except (ConnectionError, ssl.SSLError):
            pass
        finally:
            self.writer.close()

    async def handle(self, tag: str, command: str, args: str) -> bool:
        """Answer one command; True once the session is over."""
        if command == "UID" and args.split(" ", 1)[0].upper() in ("SEARCH", "FETCH", "STORE"):
            command, _, args = args.partition(" ")
            return self.dispatch(tag, command.upper(), args, uid=True)
        return self.dispatch(tag, command, args, uid=False)

    def dispatch(self, tag: str, command: str, args: str, uid: bool) -> bool:
        if command == "CAPABILITY":
            self.send("* CAPABILITY IMAP4rev1 UIDPLUS")
        elif command in ("SELECT", "EXAMINE"):
            self.select()
            return self.done(tag, "OK [READ-WRITE] SELECT completed")
        elif command == "LIST":
            self.send('* LIST () "/" "INBOX"')
        elif command == "SEARCH":
            self.search(args, uid)
        elif command == "FETCH":
            self.fetch(args, uid)
        elif command == "LOGOUT":
            self.send("* BYE staticfire IMAP closing")
            self.send(f"{tag} OK LOGOUT completed")
            return True
        elif command not in ("LOGIN", "NOOP", "CHECK", "CLOSE", "STORE", "UNSELECT"):
            self.send(f"{tag} BAD unsupported command")
            return False
        return self.done(tag, f"OK {command} completed")

    def done(self, tag: str, status: str) -> bool:
        self.send(f"{tag} {status}")
        return False

    def select(self) -> None:
        # Read for the connector, so unmarked: its visit is what the journal must show
        with httpx.Client(base_url=self.fake.base, verify=str(self.fake.cert), timeout=10) as http:
            items = http.get("/mailbox/messages").raise_for_status().json()["messages"]
        self.messages = [(item["uid"], item["raw"].encode()) for item in items]
        self.send(f"* {len(self.messages)} EXISTS")
        self.send("* 0 RECENT")
        self.send("* OK [UIDVALIDITY 1] UIDs valid")
        self.send(f"* OK [UIDNEXT {len(self.messages) + 1}] Predicted next UID")
        self.send("* FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)")

    def search(self, args: str, uid: bool) -> None:
        sender = re.search(r'FROM "?([^"\s)]+)"?', args, re.I)
        since = re.search(r"SINCE (\d{1,2}-\w{3}-\d{4})", args, re.I)
        floor = datetime.strptime(since.group(1), "%d-%b-%Y").replace(tzinfo=UTC) if since else None
        found = []
        for number, (message_uid, raw) in enumerate(self.messages, 1):
            message = message_from_bytes(raw)
            if sender and sender.group(1).lower() not in parseaddr(message["From"])[1].lower():
                continue
            if floor and parsedate_to_datetime(message["Date"]) < floor:
                continue
            found.append(message_uid if uid else number)
        self.send("* SEARCH " + " ".join(map(str, found)))

    def fetch(self, args: str, uid: bool) -> None:
        selection, _, items = args.partition(" ")
        wanted = set()
        for part in selection.split(","):
            low, _, high = part.partition(":")
            if not high:
                wanted.add(int(low))
            else:
                last = len(self.messages) + 1 if high == "*" else int(high)
                wanted.update(range(int(low), last + 1))
        items = items.strip("() ").upper()
        for number, (message_uid, raw) in enumerate(self.messages, 1):
            if (message_uid if uid else number) not in wanted:
                continue
            attributes = []
            if uid or "UID" in items:
                attributes.append(f"UID {message_uid}")
            if "FLAGS" in items:
                attributes.append("FLAGS ()")
            if "RFC822.SIZE" in items:
                attributes.append(f"RFC822.SIZE {len(raw)}")
            name = "RFC822" if re.search(r"RFC822(?!\.)", items) else "BODY[]"
            body = f"{name} {{{len(raw)}}}\r\n".encode() + raw
            head = f"* {number} FETCH ({' '.join(attributes)} ".replace("( ", "(")
            self.writer.write(head.encode() + body + b")\r\n")
