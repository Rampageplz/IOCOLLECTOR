"""Collector for Shodan API."""

import datetime
import logging
from typing import List

import requests

from ..models import IOC


def collect_shodan(api_key: str | None) -> List[IOC]:
    """Fetch data from Shodan using the Trends endpoint."""
    if not api_key:
        logging.warning("SHODAN_API_KEY não definido; ignorando coletor")
        return []

    url = "https://api.shodan.io/shodan/host/search"
    params = {"query": "malware", "key": api_key}

    try:
        resp = requests.get(url, params=params, timeout=30)
        resp.raise_for_status()
    except requests.RequestException:
        logging.exception("Erro ao acessar Shodan")
        return []

    data = resp.json().get("matches", [])
    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    today = timestamp.split("T")[0]
    iocs: List[IOC] = []
    for item in data:
        ip = item.get("ip_str")
        if not ip:
            continue
        iocs.append(
            IOC(
                date=today,
                time=timestamp,
                source="Shodan",
                ioc_type="IP",
                ioc_value=ip,
                description=item.get("hostnames"),
                tags=item.get("tags", []),
                mitigation=[],
                extra={"org": item.get("org"), "ports": item.get("ports")},
            )
        )
    logging.info("Shodan retornou %s IOCs", len(iocs))
    return iocs
