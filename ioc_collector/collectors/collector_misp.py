"""Collector for MISP REST API."""

import datetime
import logging
from typing import List

import requests

from ..models import IOC


def collect_misp(api_key: str | None) -> List[IOC]:
    """Fetch recent events from MISP instance."""
    if not api_key:
        logging.warning("MISP_API_KEY não definido; ignorando coletor")
        return []

    url = "https://misp.example.com/events/index"
    headers = {"Authorization": api_key, "Accept": "application/json"}
    params = {"limit": 50}

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=30)
        resp.raise_for_status()
    except requests.RequestException:
        logging.exception("Erro ao acessar MISP")
        return []

    events = resp.json().get("response", [])
    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    today = timestamp.split("T")[0]
    iocs: List[IOC] = []
    for evt in events:
        for attr in evt.get("Event", {}).get("Attribute", []):
            iocs.append(
                IOC(
                    date=today,
                    time=timestamp,
                    source="MISP",
                    ioc_type=attr.get("type"),
                    ioc_value=attr.get("value"),
                    description=evt.get("Event", {}).get("info"),
                    tags=[],
                    mitigation=[],
                    extra={"event_id": evt.get("Event", {}).get("id")},
                )
            )
    logging.info("MISP retornou %s IOCs", len(iocs))
    return iocs
