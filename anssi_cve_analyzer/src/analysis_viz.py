"""Analysis and visualization for consolidated CVE data."""
from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd

from .config import FIGURES_DIR
from .utils import ensure_dir


def load_df(csv_path: str) -> pd.DataFrame:
    return pd.read_csv(csv_path)


def save_figs(df: pd.DataFrame, output_dir: Path = FIGURES_DIR) -> None:
    ensure_dir(output_dir)
    _histogram_cvss(df, output_dir / "cvss_hist.png")
    _scatter_cvss_epss(df, output_dir / "cvss_epss_scatter.png")
    _top_vendors(df, output_dir / "top_vendors.png")
    _severity_distribution(df, output_dir / "severity_distribution.png")
    _top_cwe(df, output_dir / "top_cwe.png")


def _histogram_cvss(df: pd.DataFrame, path: Path) -> None:
    plt.figure(figsize=(8, 5))
    df["cvss_score"].dropna().plot(kind="hist", bins=20, color="#4c78a8")
    plt.title("Distribution des scores CVSS")
    plt.xlabel("CVSS Score")
    plt.ylabel("Nombre de CVE")
    plt.tight_layout()
    plt.savefig(path)
    plt.close()


def _scatter_cvss_epss(df: pd.DataFrame, path: Path) -> None:
    plt.figure(figsize=(8, 5))
    plt.scatter(df["cvss_score"], df["epss_score"], alpha=0.7)
    plt.title("CVSS vs EPSS")
    plt.xlabel("CVSS Score")
    plt.ylabel("EPSS Score")
    plt.tight_layout()
    plt.savefig(path)
    plt.close()


def _top_vendors(df: pd.DataFrame, path: Path) -> None:
    plt.figure(figsize=(8, 5))
    top = df["vendor"].dropna().value_counts().head(10)
    top.plot(kind="bar", color="#72b7b2")
    plt.title("Top 10 Vendors")
    plt.ylabel("Nombre de CVE")
    plt.tight_layout()
    plt.savefig(path)
    plt.close()


def _severity_distribution(df: pd.DataFrame, path: Path) -> None:
    plt.figure(figsize=(6, 4))
    df["severity"].dropna().value_counts().plot(kind="bar", color="#f58518")
    plt.title("Répartition des sévérités")
    plt.ylabel("Nombre de CVE")
    plt.tight_layout()
    plt.savefig(path)
    plt.close()


def _top_cwe(df: pd.DataFrame, path: Path) -> None:
    plt.figure(figsize=(8, 5))
    top = df["cwe_id"].dropna().value_counts().head(10)
    top.plot(kind="bar", color="#e45756")
    plt.title("Top 10 CWE")
    plt.ylabel("Nombre de CVE")
    plt.tight_layout()
    plt.savefig(path)
    plt.close()
