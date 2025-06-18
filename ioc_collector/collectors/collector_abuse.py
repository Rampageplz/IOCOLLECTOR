import requests
from pathlib import Path


def fetch_blacklist(api_key: str):
    """Return IPs from AbuseIPDB blacklist with confidence >= 80 in last day."""
    url = "https://api.abuseipdb.com/api/v2/blacklist"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"confidenceMinimum": "80", "days": "1"}
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=30)
        if resp.status_code != 200:
            raise RuntimeError(
                f"Erro na requisição: {resp.status_code} - {resp.text}"
            )
        return resp.json().get("data", [])
    except requests.RequestException as exc:
        raise RuntimeError(f"Falha ao conectar à API: {exc}") from exc


def fetch_check(ip: str, api_key: str):
    """Fetch AbuseIPDB check information for a given IP."""
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": "1"}
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=30)
        if resp.status_code != 200:
            raise RuntimeError(
                f"Erro ao consultar {ip}: {resp.status_code} - {resp.text}"
            )
        return resp.json().get("data", {})
    except requests.RequestException as exc:
        raise RuntimeError(f"Falha ao consultar {ip}: {exc}") from exc


def fetch_reports(ip: str, api_key: str):
    """Get recent reports for an IP from AbuseIPDB."""
    url = "https://api.abuseipdb.com/api/v2/reports"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": "1", "page": "1"}
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=30)
        if resp.status_code != 200:
            raise RuntimeError(
                f"Erro ao buscar reports de {ip}: {resp.status_code} - {resp.text}"
            )
        return resp.json().get("data", [])
    except requests.RequestException as exc:
        raise RuntimeError(f"Falha ao buscar reports de {ip}: {exc}") from exc


def fetch_ip_details(api_key: str, blacklist, limit: int = 100):
    """Gather check and report data for the provided blacklist entries."""
    details = []
    for item in blacklist[:limit]:
        ip = item.get("ipAddress")
        if not ip:
            continue
        try:
            check_data = fetch_check(ip, api_key)
            reports = fetch_reports(ip, api_key)
            if check_data:
                details.append({"check": check_data, "reports": reports})
        except RuntimeError as exc:
            print(exc)
    return details
