"""Collector for AlienVault OTX."""

import datetime
import logging
from typing import Any, Dict, List

import requests


def collect_otx(api_key: str) -> List[Dict[str, Any]]:
    """Fetch indicators from subscribed pulses."""
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    headers = {"X-OTX-API-KEY": api_key}
    params = {"limit": 50}

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=30)
        resp.raise_for_status()
    except requests.RequestException as exc:
        logging.exception("Erro ao acessar OTX")
        return []

    pulses = resp.json().get("results", [])
    today = datetime.date.today().isoformat()
    iocs: List[Dict[str, Any]] = []
    for pulse in pulses:
        tags = pulse.get("tags", [])
        for ind in pulse.get("indicators", []):
            iocs.append(
                {
                    "date": today,
                    "source": "OTX",
                    "ioc_type": ind.get("type"),
                    "ioc_value": ind.get("indicator"),
                    "description": ind.get("description") or pulse.get("name"),
                    "tags": tags,
                    "mitigation": [],
                    "pulse_id": pulse.get("id"),
                    "pulse_name": pulse.get("name"),
                }
            )

    logging.info("OTX retornou %s IOCs", len(iocs))
    return iocs
