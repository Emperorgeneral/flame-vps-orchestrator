"""Entrypoint: `python -m app` or `uvicorn app.main:app`."""
from __future__ import annotations

import logging

import uvicorn

from .api import app  # re-export for `uvicorn app.main:app`
from .settings import SETTINGS


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s :: %(message)s",
    )
    uvicorn.run(
        "app.api:app",
        host=SETTINGS.host,
        port=SETTINGS.port,
        log_level="info",
    )


if __name__ == "__main__":
    main()
