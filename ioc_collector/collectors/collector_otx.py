"""Collector for AlienVault OTX."""

import datetime
import logging
from typing import List

import requests

from ..models import IOC


def collect_otx(api_key: str) -> List[IOC]:
    """Fetch indicators from subscribed pulses."""
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    headers = {"X-OTX-API-KEY": api_key}
    params = {"limit": 50}

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=30)
        resp.raise_for_status()
    except requests.RequestException:
        logging.exception("Erro ao acessar OTX")
        return []

    pulses = resp.json().get("results", [])
    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    today = timestamp.split("T")[0]
    iocs: List[IOC] = []
    for pulse in pulses:
        tags = pulse.get("tags", [])
        for ind in pulse.get("indicators", []):
            iocs.append(
                IOC(
                    date=today,
                    time=timestamp,
                    source="OTX",
                    ioc_type=ind.get("type"),
                    ioc_value=ind.get("indicator"),
                    description=ind.get("description") or pulse.get("name"),
                    tags=tags,
                    mitigation=[],
                    extra={"pulse_id": pulse.get("id"), "pulse_name": pulse.get("name")},
                )
            )

    logging.info("OTX retornou %s IOCs", len(iocs))
    return iocs
