import os
import json
import datetime
import subprocess
import sys
from pathlib import Path

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


def fetch_iocs(api_key: str):
    url = "https://api.abuseipdb.com/api/v2/blacklist"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"confidenceMinimum": "90"}
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


def transform_data(raw_data):
    today = datetime.date.today().isoformat()
    iocs = []
    for item in raw_data:
        ip = item.get("ipAddress")
        score = item.get("abuseConfidenceScore")
        if not ip:
            continue
        iocs.append(
            {
                "date": today,
                "source": "AbuseIPDB",
                "ioc_type": "IP",
                "ioc_value": ip,
                "description": f"IP com score {score} de abuso.",
                "tags": [],
                "mitigation": [
                    "Block IP in firewall",
                    "Monitor login attempts from this IP",
                ],
            }
        )
    return iocs


def main():
    try:
        api_key = load_api_key()
    except RuntimeError as exc:
        print(exc)
        return

    try:
        raw_data = fetch_iocs(api_key)
    except RuntimeError as exc:
        print(exc)
        return

    processed = transform_data(raw_data)
    print(f"IOCs coletados: {len(processed)}")

    abuse_folder = Path(__file__).parent / "abuseipdb"
    save_daily_iocs(processed, abuse_folder)

    alerts_path = Path(__file__).parent / "alerts.json"
    added = update_alerts(processed, alerts_path)
    if added:
        print(f"Novos IOCs adicionados: {added}")
    else:
        print("alerts.json está atualizado. Nenhum novo IOC.")

    generate_requirements(Path(__file__).with_name("requirements.txt"))


if __name__ == "__main__":
    main()
