"""Build consolidated DataFrame for bulletins and CVEs."""
from __future__ import annotations

from typing import Any

import pandas as pd

from .anssi_bulletin import extract_cves_from_bulletin, load_bulletin_json
from .enrich_epss import fetch_epss, parse_epss
from .enrich_mitre import fetch_mitre, parse_mitre


def build_rows(bulletins: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for bulletin in bulletins:
        data = load_bulletin_json(
            json_url=bulletin.get("link_json"),
            local_path=bulletin.get("local_path"),
        )
        cves = extract_cves_from_bulletin(data)
        for cve_id in cves:
            mitre_data = parse_mitre(fetch_mitre(cve_id))
            epss_data = parse_epss(fetch_epss(cve_id))
            rows.append(
                {
                    "anssi_id": bulletin.get("id_anssi"),
                    "anssi_type": bulletin.get("type"),
                    "anssi_title": bulletin.get("title") or data.get("title"),
                    "anssi_date": bulletin.get("published") or data.get("date"),
                    "anssi_link": bulletin.get("link_html"),
                    "cve_id": cve_id,
                    **mitre_data,
                    **epss_data,
                }
            )
    return rows


def rows_to_dataframe(rows: list[dict[str, Any]]) -> pd.DataFrame:
    return pd.DataFrame(rows)


def save_csv(df: pd.DataFrame, path: str = "outputs/consolidated.csv") -> None:
    df.to_csv(path, index=False)
