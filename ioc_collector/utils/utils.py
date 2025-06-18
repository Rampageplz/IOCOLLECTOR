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
    except Exception:
        logging.exception("Erro ao gerar requirements.txt")


def load_api_keys() -> dict:
    """Load API keys for all collectors from a .env file or prompt the user."""
    env_path = Path(__file__).resolve().parents[1] / ".env"
    load_dotenv(dotenv_path=env_path)

    keys = {
        "ABUSEIPDB_API_KEY": os.getenv("ABUSEIPDB_API_KEY"),
        "OTX_API_KEY": os.getenv("OTX_API_KEY"),
        "URLHAUS_API_KEY": os.getenv("URLHAUS_API_KEY"),
    }

    mock = os.getenv("ABUSE_MOCK_FILE")
    if not keys["ABUSEIPDB_API_KEY"] and not mock:
        raise RuntimeError("Chave ABUSEIPDB_API_KEY não encontrada e ABUSE_MOCK_FILE não definido")

    if not (keys.get("OTX_API_KEY") and keys.get("URLHAUS_API_KEY")) and not os.getenv("NO_PROMPT"):
        from .prompt import prompt_api_keys

        keys.update(prompt_api_keys(keys))

    return keys


def load_config() -> dict:
    """Load configuration values from config.json if present."""
    config_path = Path(__file__).resolve().parents[2] / "config.json"
    if config_path.exists():
        try:
            with config_path.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception:
            logging.exception("Erro ao carregar config.json")
            data = {}
    else:
        data = {}

    active = os.getenv("ACTIVE_COLLECTORS", data.get("ACTIVE_COLLECTORS", "abuseipdb"))
    active_list = [name.strip() for name in active.split(',') if name.strip()]

    return {
        "CONFIDENCE_MINIMUM": data.get("CONFIDENCE_MINIMUM", 80),
        "LIMIT_DETAILS": data.get("LIMIT_DETAILS", 100),
        "MAX_AGE_IN_DAYS": data.get("MAX_AGE_IN_DAYS", 1),
        "ACTIVE_COLLECTORS": active_list,
        "GENERATE_REQUIREMENTS": data.get("GENERATE_REQUIREMENTS", True),
    }


def save_daily_iocs(iocs, folder: Path) -> Path:
    """Save the IOCs to a daily JSON file under the provided folder."""
    folder.mkdir(parents=True, exist_ok=True)
    filename = datetime.date.today().strftime("%Y-%m-%d.json")
    path = folder / filename
    prepared = [ioc.to_dict() if isinstance(ioc, IOC) else ioc for ioc in iocs]
    with path.open("w", encoding="utf-8") as fh:
        json.dump(prepared, fh, indent=2, ensure_ascii=False)
    return path


from ..models import IOC


def transform_abuse_data(details):
    """Convert AbuseIPDB check and report data into IOC objects."""
    today = datetime.date.today().isoformat()
    iocs = []
    for item in details:
        check = item.get("check", {})
        reports = item.get("reports", [])
        ip = check.get("ipAddress")
        if not ip:
            continue
        score = check.get("abuseConfidenceScore")
        total = check.get("totalReports")
        country = check.get("countryCode")
        last = check.get("lastReportedAt")

        iocs.append(
            IOC(
                date=today,
                source="AbuseIPDB",
                ioc_type="IP",
                ioc_value=ip,
                description=f"IP com score {score} e {total} reports.",
                tags=[],
                mitigation=["Block IP in firewall", "Monitor login attempts from this IP"],
                extra={
                    "abuse_confidence_score": score,
                    "totalReports": total,
                    "countryCode": country,
                    "lastReportedAt": last,
                    "reports": reports,
                },
            )
        )
    return iocs
