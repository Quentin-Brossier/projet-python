"""Utility helpers for IO and requests."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Optional

import requests


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def read_json_file(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json_file(path: Path, data: dict[str, Any]) -> None:
    ensure_dir(path.parent)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)


def request_json(url: str, delay_s: float = 0, session: Optional[requests.Session] = None) -> dict[str, Any]:
    if delay_s:
        time.sleep(delay_s)
    http = session or requests.Session()
    response = http.get(url, timeout=30)
    response.raise_for_status()
    return response.json()
