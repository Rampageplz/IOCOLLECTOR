"""Funções utilitárias para geração de arquivos e carregamento de configurações."""

import datetime
import json
import logging
import os
import subprocess
import sys
from pathlib import Path

from ..models import IOC


def encrypt_key(key: str) -> str:
    """Placeholder to encrypt a key for future use."""
    return key


def decrypt_key(key: str) -> str:
    """Placeholder to decrypt a key for future use."""
    return key


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
    """Return API keys loaded via :func:`load_config` (deprecated)."""
    config = load_config()
    return config.get("API_KEYS", {})


def load_config() -> dict:
    """Load configuration and API keys from ``config.json``.

    If the file does not exist it is created with a default template. Values in
    environment variables override missing keys.
    """
    config_path = Path(__file__).resolve().parents[2] / "config.json"
    if config_path.exists():
        try:
            with config_path.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception:
            logging.exception("Erro ao carregar config.json")
            data = {}
    else:
        data = {
            "CONFIDENCE_MINIMUM": 80,
            "LIMIT_DETAILS": 100,
            "MAX_AGE_IN_DAYS": 1,
            "ACTIVE_COLLECTORS": "abuseipdb,otx,urlhaus",
            "GENERATE_REQUIREMENTS": True,
            "API_KEYS": {"ABUSEIPDB": "", "OTX": "", "URLHAUS": ""},
        }
        config_path.write_text(json.dumps(data, indent=2))
        logging.warning("Arquivo config.json n\u00e3o encontrado. Template criado em %s", config_path)

    active = os.getenv("ACTIVE_COLLECTORS", data.get("ACTIVE_COLLECTORS", "abuseipdb"))
    active_list = [name.strip() for name in active.split(',') if name.strip()]

    keys = data.get("API_KEYS", {})
    env_keys = {
        "ABUSEIPDB": os.getenv("ABUSEIPDB_API_KEY"),
        "OTX": os.getenv("OTX_API_KEY"),
        "URLHAUS": os.getenv("URLHAUS_API_KEY"),
    }
    for k, env_val in env_keys.items():
        if not keys.get(k) and env_val:
            keys[k] = env_val
        if keys.get(k):
            keys[k] = decrypt_key(keys[k])

    return {
        "CONFIDENCE_MINIMUM": data.get("CONFIDENCE_MINIMUM", 80),
        "LIMIT_DETAILS": data.get("LIMIT_DETAILS", 100),
        "MAX_AGE_IN_DAYS": data.get("MAX_AGE_IN_DAYS", 1),
        "ACTIVE_COLLECTORS": active_list,
        "GENERATE_REQUIREMENTS": data.get("GENERATE_REQUIREMENTS", True),
        "API_KEYS": keys,
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


def transform_abuse_data(details):
    """Convert AbuseIPDB check and report data into IOC objects."""
    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    today = timestamp.split("T")[0]
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
                time=timestamp,
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
