"""Filtering alerts and email notifications."""
from __future__ import annotations

import smtplib
from email.message import EmailMessage
from typing import Iterable

import pandas as pd


def filter_alerts(
    df: pd.DataFrame,
    products_watchlist: Iterable[str] | None = None,
    min_cvss: float = 9.0,
    min_epss: float = 0.7,
) -> pd.DataFrame:
    watchlist = set(p.lower() for p in products_watchlist or [])
    alerts = df[(df["cvss_score"].fillna(0) >= min_cvss) | (df["epss_score"].fillna(0) >= min_epss)]
    if watchlist:
        alerts = alerts[
            alerts["product"].fillna("").str.lower().isin(watchlist)
            | alerts["vendor"].fillna("").str.lower().isin(watchlist)
        ]
    return alerts


def format_email_body(df_alerts: pd.DataFrame) -> str:
    if df_alerts.empty:
        return "Aucune alerte détectée."
    lines = ["Alertes CVE critiques détectées:\n"]
    for _, row in df_alerts.iterrows():
        lines.append(
            f"- {row.get('cve_id')} | CVSS {row.get('cvss_score')} | EPSS {row.get('epss_score')} "
            f"| {row.get('vendor')} {row.get('product')} | {row.get('anssi_link')}"
        )
    return "\n".join(lines)


def send_email(
    subject: str,
    body: str,
    smtp_host: str,
    smtp_port: int,
    username: str,
    password: str,
    sender: str,
    recipients: list[str],
) -> None:
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = sender
    message["To"] = ", ".join(recipients)
    message.set_content(body)

    with smtplib.SMTP(smtp_host, smtp_port) as server:
        server.starttls()
        server.login(username, password)
        server.send_message(message)
