"""Enrich CVEs using the FIRST EPSS API."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .config import EPSS_CACHE_DIR, REQUEST_DELAY_S
from .utils import read_json_file, request_json, write_json_file

EPSS_API_BASE = "https://api.first.org/data/v1/epss?cve="


def fetch_epss(cve_id: str, use_cache: bool = True) -> dict[str, Any]:
    cache_path = Path(EPSS_CACHE_DIR) / f"{cve_id}.json"
    if use_cache and cache_path.exists():
        return read_json_file(cache_path)
    data = request_json(f"{EPSS_API_BASE}{cve_id}", delay_s=REQUEST_DELAY_S)
    write_json_file(cache_path, data)
    return data


def parse_epss(data: dict[str, Any]) -> dict[str, Any]:
    epss_items = data.get("data", [])
    if not epss_items:
        return {"epss_score": None, "epss_percentile": None}
    item = epss_items[0]
    return {
        "epss_score": _coerce_float(item.get("epss")),
        "epss_percentile": _coerce_float(item.get("percentile")),
    }


def _coerce_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
