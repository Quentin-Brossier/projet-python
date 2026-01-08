"""Load ANSSI bulletin JSON and extract CVEs."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Optional

from .config import REQUEST_DELAY_S
from .utils import read_json_file, request_json

CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}")


def load_bulletin_json(json_url: str | None = None, local_path: Path | None = None) -> dict[str, Any]:
    if local_path:
        return read_json_file(local_path)
    if not json_url:
        raise ValueError("json_url or local_path must be provided")
    return request_json(json_url, delay_s=REQUEST_DELAY_S)


def extract_cves_from_bulletin(data: dict[str, Any]) -> list[str]:
    cves: list[str] = []
    if "cves" in data and isinstance(data["cves"], list):
        for item in data["cves"]:
            if isinstance(item, dict) and "name" in item:
                cves.append(item["name"])
            elif isinstance(item, str):
                cves.append(item)
    if not cves:
        blob = json.dumps(data)
        cves.extend(CVE_REGEX.findall(blob))
    return sorted(set(cves))


def get_anssi_id_from_url(url: str) -> str:
    match = re.search(r"CERTFR-[\d]{4}-(?:ALE|AVI)-\d{3}", url)
    return match.group(0) if match else ""
