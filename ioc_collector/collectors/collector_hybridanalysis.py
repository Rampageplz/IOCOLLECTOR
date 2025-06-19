"""Collector for Hybrid Analysis API."""

import datetime
import logging
from typing import List

import requests

from ..models import IOC


def collect_hybridanalysis(api_key: str | None) -> List[IOC]:
    """Fetch recent submissions from Hybrid Analysis."""
    if not api_key:
        logging.warning("HYBRID_API_KEY não definido; ignorando coletor")
        return []

    url = "https://www.hybrid-analysis.com/api/v2/feed/latest"
    headers = {"api-key": api_key, "user-agent": "Falcon Sandbox"}

    try:
        resp = requests.get(url, headers=headers, timeout=30)
        resp.raise_for_status()
    except requests.RequestException:
        logging.exception("Erro ao acessar Hybrid Analysis")
        return []

    data = resp.json()
    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    today = timestamp.split("T")[0]
    iocs: List[IOC] = []
    for item in data:
        sha256 = item.get("sha256")
        if not sha256:
            continue
        iocs.append(
            IOC(
                date=today,
                time=timestamp,
                source="HybridAnalysis",
                ioc_type="sha256",
                ioc_value=sha256,
                description=item.get("threat_score"),
                tags=item.get("tags", []),
                mitigation=[],
                extra={"file_type": item.get("type"), "url": item.get("submit_url")},
            )
        )
    logging.info("Hybrid Analysis retornou %s IOCs", len(iocs))
    return iocs
