import os
import json
import datetime
import subprocess
import sys
from pathlib import Path
import argparse
from collections import Counter

import requests
from dotenv import load_dotenv


def generate_requirements(path: Path):
    """Generate requirements.txt using pip freeze."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "freeze"], capture_output=True, text=True, check=True
        )
        path.write_text(result.stdout)
    except Exception as exc:
        print(f"Erro ao gerar requirements.txt: {exc}")


def load_api_key() -> str:
    """Load API key from .env file."""
    load_dotenv(dotenv_path=Path(__file__).with_name(".env"))
    key = os.getenv("ABUSEIPDB_API_KEY")
    if not key:
        raise RuntimeError("Chave de API não encontrada no arquivo .env")
    return key


def fetch_blacklist(api_key: str):
    url = "https://api.abuseipdb.com/api/v2/blacklist"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"confidenceMinimum": "80", "days": "1"}
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=30)
        if resp.status_code != 200:
            raise RuntimeError(
                f"Erro na requisição: {resp.status_code} - {resp.text}"
            )
        data = resp.json().get("data", [])
        return data
    except requests.RequestException as exc:
        raise RuntimeError(f"Falha ao conectar à API: {exc}") from exc


def fetch_check(ip: str, api_key: str):
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
    """Obter os reports recentes de um IP."""
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
    """Buscar dados de check e reports para cada IP."""
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


def save_daily_iocs(iocs, folder: Path) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    filename = datetime.date.today().strftime("%Y-%m-%d.json")
    path = folder / filename
    with path.open("w", encoding="utf-8") as fh:
        json.dump(iocs, fh, indent=2, ensure_ascii=False)
    return path


def update_alerts(new_iocs, alerts_file: Path) -> int:
    alerts_file.parent.mkdir(parents=True, exist_ok=True)
    if alerts_file.exists():
        with alerts_file.open("r", encoding="utf-8") as fh:
            alerts = json.load(fh)
    else:
        alerts = []

    existing_values = {item.get("ioc_value") for item in alerts}
    added = 0
    for ioc in new_iocs:
        if ioc["ioc_value"] not in existing_values:
            alerts.append(ioc)
            existing_values.add(ioc["ioc_value"])
            added += 1

    with alerts_file.open("w", encoding="utf-8") as fh:
        json.dump(alerts, fh, indent=2, ensure_ascii=False)

    return added


def check_duplicates(alerts_file: Path):
    """Retorna lista de IPs duplicados em alerts.json, se houver."""
    if not alerts_file.exists():
        return []
    with alerts_file.open("r", encoding="utf-8") as fh:
        alerts = json.load(fh)
    values = [item.get("ioc_value") for item in alerts]
    counts = Counter(values)
    return [ip for ip, count in counts.items() if count > 1]


def transform_data(details):
    """Transformar dados de check e reports em formato de IOC."""
    today = datetime.date.today().isoformat()
    iocs = []
    for item in details:
        check = item.get("check", {})
        reports = item.get("reports", [])
        ip = check.get("ipAddress")
        score = check.get("abuseConfidenceScore")
        total = check.get("totalReports")
        country = check.get("countryCode")
        last = check.get("lastReportedAt")
        if not ip:
            continue
        iocs.append(
            {
                "date": today,
                "source": "AbuseIPDB",
                "ioc_type": "IP",
                "ioc_value": ip,
                "abuse_confidence_score": score,
                "totalReports": total,
                "countryCode": country,
                "lastReportedAt": last,
                "reports": reports,
                "description": f"IP com score {score} e {total} reports.",
                "tags": [],
                "mitigation": [
                    "Block IP in firewall",
                    "Monitor login attempts from this IP",
                ],
            }
        )
    return iocs



def collect(api_key: str):
    try:
        blacklist = fetch_blacklist(api_key)
    except RuntimeError as exc:
        print(exc)
        return

    if blacklist:
        print("IPs com score >= 80 nas últimas 24h:")
        for item in blacklist:
            ip = item.get("ipAddress")
            score = item.get("abuseConfidenceScore")
            print(f"  {ip} - score {score}")
        print(f"Total: {len(blacklist)}")
    else:
        print("Nenhum IP reportado nas últimas 24h com score >= 80.")

    details = fetch_ip_details(api_key, blacklist, limit=20)
    processed = transform_data(details)
    print(f"IOCs coletados: {len(processed)}")

    abuse_folder = Path(__file__).parent / "abuseipdb"
    save_daily_iocs(processed, abuse_folder)

    alerts_path = Path(__file__).parent / "alerts.json"
    added = update_alerts(processed, alerts_path)
    if added:
        print(f"Novos IOCs adicionados: {added}")
    else:
        print("alerts.json está atualizado. Nenhum novo IOC.")

    dups = check_duplicates(alerts_path)
    if dups:
        print(f"IPs duplicados em alerts.json: {', '.join(dups)}")
    else:
        print("Nenhum IP duplicado em alerts.json.")

    generate_requirements(Path(__file__).with_name("requirements.txt"))

    today = datetime.date.today().isoformat()
    print_top_reported(today, alerts_path)


def print_top_reported(date_str: str, alerts_file: Path, top: int = 5):
    if not alerts_file.exists():
        print("Arquivo de alertas não encontrado.")
        return
    with alerts_file.open("r", encoding="utf-8") as fh:
        alerts = json.load(fh)
    daily = [a for a in alerts if a.get("date") == date_str]
    if not daily:
        print(f"Sem registros para {date_str}.")
        return
    daily.sort(key=lambda x: x.get("totalReports", 0), reverse=True)
    print(f"IPs mais reportados em {date_str}:")
    for item in daily[:top]:
        ip = item.get("ioc_value")
        total = item.get("totalReports", 0)
        print(f"  {ip} - {total} reports")


def main():
    parser = argparse.ArgumentParser(description="Coletor de IOCs do AbuseIPDB")
    parser.add_argument(
        "--top",
        help="Mostrar IPs mais reportados na data (YYYY-MM-DD) a partir de alerts.json",
    )
    args = parser.parse_args()

    try:
        api_key = load_api_key()
    except RuntimeError as exc:
        print(exc)
        return

    alerts_path = Path(__file__).parent / "alerts.json"

    if args.top:
        print_top_reported(args.top, alerts_path)
        return

    collect(api_key)


if __name__ == "__main__":
    main()
