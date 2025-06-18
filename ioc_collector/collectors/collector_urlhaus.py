"""Collector for URLHaus feed."""

import datetime
import logging
from typing import List

import requests

# A API do URLHaus não exige autenticação no endpoint utilizado.
# A variável URLHAUS_API_KEY é carregada apenas para compatibilidade futura.

from ..models import IOC


def collect_urlhaus() -> List[IOC]:
    """Fetch recent URLs from URLHaus API."""
    url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
    except requests.RequestException:
        logging.exception("Erro ao acessar URLHaus")
        return []

    data = resp.json()
    entries = data.get("urls", [])
    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    today = timestamp.split("T")[0]
    iocs: List[IOC] = []
    for item in entries:
        iocs.append(
            IOC(
                date=today,
                time=timestamp,
                source="URLHaus",
                ioc_type="URL",
                ioc_value=item.get("url"),
                description=item.get("threat"),
                tags=item.get("tags", []),
                mitigation=["Block URL", "Monitor web traffic"],
                extra={
                    "url_status": item.get("url_status"),
                    "reference": item.get("urlhaus_reference"),
                    "host": item.get("host"),
                },
            )
        )
    logging.info("URLHaus retornou %s IOCs", len(iocs))
    return iocs
