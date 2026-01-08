"""Fetch and normalize ANSSI RSS feeds."""
from __future__ import annotations

import time
from typing import Any
from urllib.parse import urlparse

import feedparser
from dateutil import parser as dateparser

from .config import REQUEST_DELAY_S


def fetch_rss(url: str) -> list[dict[str, Any]]:
    feed = feedparser.parse(url)
    entries = []
    for entry in feed.entries:
        entries.append(normalize_entry(entry))
    if REQUEST_DELAY_S:
        time.sleep(REQUEST_DELAY_S)
    return entries


def normalize_entry(entry: Any) -> dict[str, Any]:
    link_html = entry.get("link")
    published = entry.get("published") or entry.get("updated")
    if published:
        try:
            published = dateparser.parse(published).isoformat()
        except (ValueError, TypeError):
            pass
    return {
        "id_anssi": entry.get("id") or entry.get("guid") or entry.get("title"),
        "type": _infer_type(link_html),
        "title": entry.get("title"),
        "published": published,
        "link_html": link_html,
        "link_json": build_json_url(link_html) if link_html else None,
    }


def build_json_url(html_url: str) -> str:
    if html_url.endswith("/json/"):
        return html_url
    if not html_url.endswith("/"):
        html_url = f"{html_url}/"
    return f"{html_url}json/"


def _infer_type(link_html: str | None) -> str:
    if not link_html:
        return ""
    path = urlparse(link_html).path
    if "/alerte/" in path:
        return "Alerte"
    if "/avis/" in path:
        return "Avis"
    return ""
