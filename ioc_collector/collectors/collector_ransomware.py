"""Collector for abuse.ch ransomware feed."""

import datetime
import logging
from typing import List

import requests

from ..models import IOC

FEED_URL = "https://ransomwaretracker.abuse.ch/feeds/csv/"


def collect_ransomware() -> List[IOC]:
    """Fetch ransomware feed from abuse.ch."""
    try:
        resp = requests.get(FEED_URL, timeout=30)
        resp.raise_for_status()
    except requests.RequestException:
        logging.exception("Erro ao acessar ransomware feed")
        return []

    lines = resp.text.splitlines()
    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    today = timestamp.split("T")[0]
    iocs: List[IOC] = []
    for line in lines:
        if line.startswith("#") or not line:
            continue
        parts = line.split(",")
        if len(parts) < 2:
            continue
        iocs.append(
            IOC(
                date=today,
                time=timestamp,
                source="AbuseCH-Ransomware",
                ioc_type="URL",
                ioc_value=parts[1],
                description=parts[0],
                tags=[],
                mitigation=[],
                extra={},
            )
        )
    logging.info("Ransomware feed retornou %s IOCs", len(iocs))
    return iocs
