"""Enrich CVEs using the MITRE CVE API."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .config import MITRE_CACHE_DIR, REQUEST_DELAY_S
from .utils import read_json_file, request_json, write_json_file

MITRE_API_BASE = "https://cveawg.mitre.org/api/cve/"


def fetch_mitre(cve_id: str, use_cache: bool = True) -> dict[str, Any]:
    cache_path = Path(MITRE_CACHE_DIR) / f"{cve_id}.json"
    if use_cache and cache_path.exists():
        return read_json_file(cache_path)
    data = request_json(f"{MITRE_API_BASE}{cve_id}", delay_s=REQUEST_DELAY_S)
    write_json_file(cache_path, data)
    return data


def parse_mitre(data: dict[str, Any]) -> dict[str, Any]:
    cna = data.get("containers", {}).get("cna", {})
    description = _extract_description(cna)
    cvss_score, cvss_version, severity = _extract_cvss(cna)
    cwe_id, cwe_desc = _extract_cwe(cna)
    vendor, product, versions_affected = _extract_affected(cna)
    return {
        "description": description,
        "cvss_score": cvss_score,
        "cvss_version": cvss_version,
        "severity": severity,
        "cwe_id": cwe_id,
        "cwe_desc": cwe_desc,
        "vendor": vendor,
        "product": product,
        "versions_affected": versions_affected,
    }


def _extract_description(cna: dict[str, Any]) -> str | None:
    descriptions = cna.get("descriptions", [])
    for desc in descriptions:
        if desc.get("lang") == "en":
            return desc.get("value")
    if descriptions:
        return descriptions[0].get("value")
    return None


def _extract_cvss(cna: dict[str, Any]) -> tuple[float | None, str | None, str | None]:
    metrics = cna.get("metrics", [])
    for metric in metrics:
        for key, value in metric.items():
            if key.lower().startswith("cvssv") and isinstance(value, dict):
                score = value.get("baseScore")
                severity = value.get("baseSeverity")
                version = value.get("version")
                return _coerce_float(score), version, severity
    return None, None, None


def _extract_cwe(cna: dict[str, Any]) -> tuple[str | None, str | None]:
    problem_types = cna.get("problemTypes", [])
    for problem in problem_types:
        for desc in problem.get("descriptions", []):
            cwe_id = desc.get("cweId") or desc.get("value")
            cwe_desc = desc.get("description")
            if cwe_id or cwe_desc:
                return cwe_id, cwe_desc
    return None, None


def _extract_affected(cna: dict[str, Any]) -> tuple[str | None, str | None, list[str]]:
    affected_list = cna.get("affected", [])
    vendors = []
    products = []
    versions = []
    for item in affected_list:
        vendor = item.get("vendor")
        product = item.get("product")
        if vendor:
            vendors.append(vendor)
        if product:
            products.append(product)
        for version_info in item.get("versions", []):
            version_value = version_info.get("version") or version_info.get("lessThan")
            if version_value:
                versions.append(version_value)
    return _first_unique(vendors), _first_unique(products), sorted(set(versions))


def _first_unique(values: list[str]) -> str | None:
    return values[0] if values else None


def _coerce_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
