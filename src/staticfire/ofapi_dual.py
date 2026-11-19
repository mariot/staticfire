"""Serve ofapi on a plain HTTP port and a TLS port from one process.

Collectors differ: most take an http:// base URL, some hardcode https://. Two uvicorn processes
would not share ofapi's scripted rules and journal, so one process serves the same app twice.

Run from the ofapi checkout: uv run --directory <ofapi> python ofapi_dual.py HTTP HTTPS CERT KEY
"""

import asyncio
import os
import sys

import uvicorn

sys.path.insert(0, os.getcwd())

from app.main import app  # noqa: E402  (ofapi's app, importable once its checkout is on the path)


async def main(http_port: int, https_port: int, cert: str, key: str) -> None:
    servers = [
        uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=http_port, log_level="info")),
        uvicorn.Server(
            uvicorn.Config(
                app,
                host="127.0.0.1",
                port=https_port,
                ssl_certfile=cert,
                ssl_keyfile=key,
                log_level="info",
            )
        ),
    ]
    await asyncio.gather(*(server.serve() for server in servers))


if __name__ == "__main__":
    asyncio.run(main(int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4]))
