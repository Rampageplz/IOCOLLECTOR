"""Funções utilitárias para geração de arquivos e carregamento de configurações."""

import datetime
import json
import logging
import os
import subprocess
import sys
from pathlib import Path

from dotenv import load_dotenv


def generate_requirements(path: Path) -> None:
    """Generate a requirements file using pip freeze."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "freeze"], capture_output=True, text=True, check=True
        )
        path.write_text(result.stdout)
    except Exception as exc:
        logging.error("Erro ao gerar requirements.txt: %s", exc)


def load_api_key() -> str:
    """Load the AbuseIPDB API key from a .env file."""
    load_dotenv(dotenv_path=Path(__file__).resolve().with_name(".env"))
    key = os.getenv("ABUSEIPDB_API_KEY")
    if not key:
        raise RuntimeError("Chave de API não encontrada no arquivo .env")
    return key


def save_daily_iocs(iocs, folder: Path) -> Path:
    """Save the IOCs to a daily JSON file under the provided folder."""
    folder.mkdir(parents=True, exist_ok=True)
    filename = datetime.date.today().strftime("%Y-%m-%d.json")
    path = folder / filename
    with path.open("w", encoding="utf-8") as fh:
        json.dump(iocs, fh, indent=2, ensure_ascii=False)
    return path


def transform_data(details):
    """Convert check and report details into IOC dictionaries."""
    today = datetime.date.today().isoformat()
    iocs = []
    for item in details:
        check = item.get("check", {})
        reports = item.get("reports", [])
        ip = check.get("ipAddress")
        score = check.get("abuseConfidenceScore")
        total = check.get("totalReports")
        country = check.get("countryCode")
        last = check.get("lastReportedAt")
        if not ip:
            continue
        iocs.append(
            {
                "date": today,
                "source": "AbuseIPDB",
                "ioc_type": "IP",
                "ioc_value": ip,
                "abuse_confidence_score": score,
                "totalReports": total,
                "countryCode": country,
                "lastReportedAt": last,
                "reports": reports,
                "description": f"IP com score {score} e {total} reports.",
                "tags": [],
                "mitigation": [
                    "Block IP in firewall",
                    "Monitor login attempts from this IP",
                ],
            }
        )
    return iocs
