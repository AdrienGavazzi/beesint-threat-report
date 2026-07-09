# BeeSINT Threat Report

Pipeline ETL (Polars/Pydantic/Pandera) publiant un rapport hebdomadaire de cyber threat intelligence
(NVD, CISA KEV, abuse.ch) vers un stockage objet S3-compatible (Oracle Object Storage).

> README définitif (architecture, quickstart, compétences démontrées) livré au Lot 8.

## Installation

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```
