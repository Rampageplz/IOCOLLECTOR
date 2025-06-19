"""Collector for Abuse.ch ThreatFox API."""

import datetime
import logging
from typing import List

import requests

from ..models import IOC


API_URL = "https://threatfox-api.abuse.ch/api/v1/"


def collect_threatfox() -> List[IOC]:
    """Fetch recent IOCs from ThreatFox."""
    payload = {"query": "get_iocs", "limit": 50}
    try:
        resp = requests.post(API_URL, json=payload, timeout=30)
        resp.raise_for_status()
    except requests.RequestException:
        logging.exception("Erro ao acessar ThreatFox")
        return []

    data = resp.json().get("data", [])
    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    today = timestamp.split("T")[0]
    iocs: List[IOC] = []
    for item in data:
        iocs.append(
            IOC(
                date=today,
                time=timestamp,
                source="ThreatFox",
                ioc_type=item.get("ioc_type"),
                ioc_value=item.get("ioc"),
                description=item.get("threat_type_desc"),
                tags=item.get("tags", []),
                mitigation=[],
                extra={"first_seen": item.get("first_seen")},
            )
        )
    logging.info("ThreatFox retornou %s IOCs", len(iocs))
    return iocs
