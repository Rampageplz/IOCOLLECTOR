"""Collector for VirusTotal API."""

import datetime
import logging
from typing import List

import requests

from ..models import IOC


def collect_virustotal(api_key: str | None) -> List[IOC]:
    """Fetch recent malicious files from VirusTotal."""
    if not api_key:
        logging.warning("VT_API_KEY não definido; ignorando coletor")
        return []

    url = "https://www.virustotal.com/api/v3/files/search"
    headers = {"x-apikey": api_key}
    params = {"query": "type:peexe positives:10+", "limit": 50}

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=30)
        resp.raise_for_status()
    except requests.RequestException:
        logging.exception("Erro ao acessar VirusTotal")
        return []

    data = resp.json().get("data", [])
    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    today = timestamp.split("T")[0]
    iocs: List[IOC] = []
    for item in data:
        attr = item.get("attributes", {})
        sha256 = attr.get("sha256")
        if not sha256:
            continue
        iocs.append(
            IOC(
                date=today,
                time=timestamp,
                source="VirusTotal",
                ioc_type="sha256",
                ioc_value=sha256,
                description=attr.get("meaningful_name"),
                tags=attr.get("tags", []),
                mitigation=[],
                extra={"first_submission": attr.get("first_submission_date")},
            )
        )
    logging.info("VirusTotal retornou %s IOCs", len(iocs))
    return iocs
