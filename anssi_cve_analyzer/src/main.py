"""Main execution workflow for ANSSI CVE analyzer."""
from __future__ import annotations

import argparse
from pathlib import Path

from .analysis_viz import load_df, save_figs
from .anssi_rss import fetch_rss
from .alerts_email import filter_alerts, format_email_body, send_email
from .build_dataframe import build_rows, rows_to_dataframe, save_csv
from .config import (
    ALERT_MIN_CVSS,
    ALERT_MIN_EPSS,
    ALERTES_DIR,
    AVIS_DIR,
    EMAIL_FROM,
    EMAIL_PASSWORD,
    EMAIL_SMTP_HOST,
    EMAIL_SMTP_PORT,
    EMAIL_TO,
    EMAIL_USERNAME,
    OUTPUT_DIR,
    RSS_ALERTES,
    RSS_AVIS,
)
from .utils import ensure_dir


def _load_offline_bulletins(directory: Path, bulletin_type: str) -> list[dict]:
    bulletins: list[dict] = []
    for file_path in sorted(directory.glob("*.json")):
        bulletins.append(
            {
                "id_anssi": file_path.stem,
                "type": bulletin_type,
                "title": None,
                "published": None,
                "link_html": None,
                "link_json": None,
                "local_path": file_path,
            }
        )
    return bulletins


def run(offline: bool = False, limit: int | None = None) -> None:
    ensure_dir(OUTPUT_DIR)
    if offline:
        bulletins = _load_offline_bulletins(AVIS_DIR, "Avis") + _load_offline_bulletins(ALERTES_DIR, "Alerte")
    else:
        bulletins = fetch_rss(RSS_AVIS) + fetch_rss(RSS_ALERTES)
    if limit:
        bulletins = bulletins[:limit]

    rows = build_rows(bulletins)
    df = rows_to_dataframe(rows)
    save_csv(df, str(OUTPUT_DIR / "consolidated.csv"))

    df_loaded = load_df(str(OUTPUT_DIR / "consolidated.csv"))
    save_figs(df_loaded)

    alerts = filter_alerts(df_loaded, min_cvss=ALERT_MIN_CVSS, min_epss=ALERT_MIN_EPSS)
    alert_body = format_email_body(alerts)
    alert_path = OUTPUT_DIR / "alerts.txt"
    alert_path.write_text(alert_body, encoding="utf-8")

    if EMAIL_TO:
        send_email(
            subject="ANSSI CVE Alerts",
            body=alert_body,
            smtp_host=EMAIL_SMTP_HOST,
            smtp_port=EMAIL_SMTP_PORT,
            username=EMAIL_USERNAME,
            password=EMAIL_PASSWORD,
            sender=EMAIL_FROM,
            recipients=list(EMAIL_TO),
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="ANSSI CVE analyzer")
    parser.add_argument("--offline", action="store_true", help="Use offline JSON files")
    parser.add_argument("--limit", type=int, help="Limit number of bulletins")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    run(offline=args.offline, limit=args.limit)


if __name__ == "__main__":
    main()
