"""Coletores de dados da API AbuseIPDB."""

import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict

import requests
from requests import Response
from tqdm import tqdm



def _request_with_retry(
    url: str,
    headers: Dict[str, str],
    params: Dict[str, Any],
    max_retries: int = 5,
) -> Response:
    """Execute a GET request with exponential backoff retries."""
    backoff = 1
    for attempt in range(max_retries):
        try:
            resp = requests.get(url, headers=headers, params=params, timeout=30)
            if resp.status_code == 429:
                raise RuntimeError("Limite de requisi\u00e7\u00f5es excedido (HTTP 429)")
            resp.raise_for_status()
            return resp
        except (requests.RequestException, RuntimeError) as exc:
            if attempt == max_retries - 1:
                raise RuntimeError(f"Falha ao conectar \u00e0 API: {exc}") from exc
            time.sleep(backoff)
            backoff *= 2


def fetch_blacklist(api_key: str, config: Dict[str, Any]):
    """Return IPs from AbuseIPDB blacklist respecting configured parameters."""
    url = "https://api.abuseipdb.com/api/v2/blacklist"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {
        "confidenceMinimum": str(config.get("CONFIDENCE_MINIMUM", 80)),
        "days": str(config.get("MAX_AGE_IN_DAYS", 1)),
    }
    resp = _request_with_retry(url, headers, params)
    return resp.json().get("data", [])


def fetch_check(ip: str, api_key: str, config: Dict[str, Any]):
    """Fetch AbuseIPDB check information for a given IP."""
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {
        "ipAddress": ip,
        "maxAgeInDays": str(config.get("MAX_AGE_IN_DAYS", 1)),
    }
    resp = _request_with_retry(url, headers, params)
    return resp.json().get("data", {})


def fetch_reports(ip: str, api_key: str, config: Dict[str, Any]):
    """Get recent reports for an IP from AbuseIPDB."""
    url = "https://api.abuseipdb.com/api/v2/reports"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {
        "ipAddress": ip,
        "maxAgeInDays": str(config.get("MAX_AGE_IN_DAYS", 1)),
        "page": "1",
    }
    resp = _request_with_retry(url, headers, params)
    return resp.json().get("data", [])


def fetch_ip_details(api_key: str, blacklist, config: Dict[str, Any]):
    """Gather check and report data for the provided blacklist entries."""
    limit = int(config.get("LIMIT_DETAILS", 100))
    details = []
    for item in tqdm(blacklist[:limit], desc="Coletando detalhes"):
        ip = item.get("ipAddress")
        if not ip:
            continue
        try:
            check_data = fetch_check(ip, api_key, config)
            reports = fetch_reports(ip, api_key, config)
            if check_data:
                details.append({"check": check_data, "reports": reports})
        except RuntimeError as exc:
            logging.error(exc)
    return details


def collect_abuse(api_key: str, config: Dict[str, Any]):
    """Return transformed IOCs from AbuseIPDB.

    If the environment variable ``ABUSE_MOCK_FILE`` is set, data will be loaded
    from the specified JSON file instead of calling the API. This helps during
    testing when the AbuseIPDB rate limit is exceeded.
    """

    mock_path = os.getenv("ABUSE_MOCK_FILE")
    if mock_path:
        path = Path(mock_path)
        if path.exists():
            with path.open("r", encoding="utf-8") as fh:
                details = json.load(fh)
            logging.info("Usando dados simulados do AbuseIPDB (%s entradas)", len(details))
            from ..utils.utils import transform_abuse_data
            return transform_abuse_data(details)
        logging.warning("Arquivo ABUSE_MOCK_FILE %s não encontrado", mock_path)

    try:
        blacklist = fetch_blacklist(api_key, config)
    except RuntimeError as exc:
        logging.error(exc)
        return []
    details = fetch_ip_details(api_key, blacklist, config)
    from ..utils.utils import transform_abuse_data

    return transform_abuse_data(details)
