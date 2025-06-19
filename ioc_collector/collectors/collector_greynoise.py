"""Collector for GreyNoise API."""

import datetime
import logging
from typing import List

import requests

from ..models import IOC


def collect_greynoise(api_key: str | None) -> List[IOC]:
    """Enrich IPs via GreyNoise or fetch recent malicious IPs."""
    if not api_key:
        logging.warning("GREYNOISE_API_KEY não definido; ignorando coletor")
        return []

    url = "https://api.greynoise.io/v3/community/quick"
    headers = {"key": api_key}
    params = {"ip": "1.1.1.1"}

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=30)
        resp.raise_for_status()
    except requests.RequestException:
        logging.exception("Erro ao acessar GreyNoise")
        return []

    data = resp.json()
    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    today = timestamp.split("T")[0]
    iocs = [
        IOC(
            date=today,
            time=timestamp,
            source="GreyNoise",
            ioc_type="IP",
            ioc_value=data.get("ip"),
            description=data.get("classification"),
            tags=[],
            mitigation=[],
            extra={"noise": data.get("noise")},
        )
    ]
    logging.info("GreyNoise retornou 1 IOC")
    return iocs
