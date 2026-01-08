# ANSSI CVE Analyzer

Pipeline to collect ANSSI bulletins, extract CVEs, enrich them with MITRE and EPSS, and produce analytics/alerts.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run

Online (live RSS + APIs):

```bash
python -m anssi_cve_analyzer.src.main
```

Offline (using cached JSON files in `data/avis` and `data/alertes`):

```bash
python -m anssi_cve_analyzer.src.main --offline
```

Limit bulletins:

```bash
python -m anssi_cve_analyzer.src.main --limit 10
```

Outputs:
- `outputs/consolidated.csv`
- `outputs/figures/*.png`
- `outputs/alerts.txt`
