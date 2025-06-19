"""Collector for Google Safe Browsing API."""

import datetime
import logging
from typing import List

import requests

from ..models import IOC


def collect_gsb(api_key: str | None) -> List[IOC]:
    """Check a test URL against Google Safe Browsing."""
    if not api_key:
        logging.warning("GSB_API_KEY não definido; ignorando coletor")
        return []

    url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    body = {
        "client": {"clientId": "test", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": "http://malware.test"}],
        },
    }
    params = {"key": api_key}

    try:
        resp = requests.post(url, params=params, json=body, timeout=30)
        resp.raise_for_status()
    except requests.RequestException:
        logging.exception("Erro ao acessar GSB")
        return []

    data = resp.json().get("matches", [])
    if not data:
        return []
    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    today = timestamp.split("T")[0]
    iocs: List[IOC] = []
    for match in data:
        url_val = match.get("threat", {}).get("url")
        iocs.append(
            IOC(
                date=today,
                time=timestamp,
                source="GoogleSB",
                ioc_type="URL",
                ioc_value=url_val,
                description=match.get("threatType"),
                tags=[],
                mitigation=[],
                extra={},
            )
        )
    logging.info("GSB retornou %s IOCs", len(iocs))
    return iocs
