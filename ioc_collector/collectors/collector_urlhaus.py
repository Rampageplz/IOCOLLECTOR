"""Collector for URLHaus feed."""

import datetime
import logging
from typing import Any, Dict, List

import requests


def collect_urlhaus() -> List[Dict[str, Any]]:
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
    today = datetime.date.today().isoformat()
    iocs: List[Dict[str, Any]] = []
    for item in entries:
        iocs.append(
            {
                "date": today,
                "source": "URLHaus",
                "ioc_type": "URL",
                "ioc_value": item.get("url"),
                "description": item.get("threat"),
                "tags": item.get("tags", []),
                "mitigation": ["Block URL", "Monitor web traffic"],
                "url_status": item.get("url_status"),
                "reference": item.get("urlhaus_reference"),
                "host": item.get("host"),
            }
        )
    logging.info("URLHaus retornou %s IOCs", len(iocs))
    return iocs
