"""Collector for Censys Search API."""

import datetime
import logging
from typing import List

import requests

from ..models import IOC


def collect_censys(api_key: str | None) -> List[IOC]:
    """Fetch recent malicious hosts from Censys."""
    if not api_key:
        logging.warning("CENSYS_API_KEY não definido; ignorando coletor")
        return []

    url = "https://search.censys.io/api/v2/hosts/search"
    headers = {"Authorization": f"Bearer {api_key}"}
    params = {"q": "services.banner:malware", "per_page": 50}

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=30)
        resp.raise_for_status()
    except requests.RequestException:
        logging.exception("Erro ao acessar Censys")
        return []

    data = resp.json().get("result", {}).get("hits", [])
    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    today = timestamp.split("T")[0]
    iocs: List[IOC] = []
    for item in data:
        ip = item.get("ip")
        if not ip:
            continue
        iocs.append(
            IOC(
                date=today,
                time=timestamp,
                source="Censys",
                ioc_type="IP",
                ioc_value=ip,
                description="Censys malicious host",
                tags=[],
                mitigation=[],
                extra={"services": item.get("services")},
            )
        )
    logging.info("Censys retornou %s IOCs", len(iocs))
    return iocs
