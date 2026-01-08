"""Configuration for ANSSI CVE analyzer."""
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data"
OUTPUT_DIR = BASE_DIR / "outputs"
FIGURES_DIR = OUTPUT_DIR / "figures"

RSS_AVIS = "https://www.cert.ssi.gouv.fr/avis/feed/"
RSS_ALERTES = "https://www.cert.ssi.gouv.fr/alerte/feed/"
ANSSI_JSON_BASE = "https://www.cert.ssi.gouv.fr"
REQUEST_DELAY_S = 2

RSS_DIR = DATA_DIR / "rss"
AVIS_DIR = DATA_DIR / "avis"
ALERTES_DIR = DATA_DIR / "alertes"
MITRE_CACHE_DIR = DATA_DIR / "mitre"
EPSS_CACHE_DIR = DATA_DIR / "first"

EMAIL_SMTP_HOST = "smtp.gmail.com"
EMAIL_SMTP_PORT = 587
EMAIL_USERNAME = ""
EMAIL_PASSWORD = ""
EMAIL_FROM = ""
EMAIL_TO = []

ALERT_MIN_CVSS = 9.0
ALERT_MIN_EPSS = 0.7
