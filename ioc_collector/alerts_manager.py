import json
from collections import Counter
from pathlib import Path


def update_alerts(new_iocs, alerts_file: Path) -> int:
    """Append new IOCs to alerts.json, avoiding duplicates."""
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
    """Return duplicate IPs present in alerts.json."""
    if not alerts_file.exists():
        return []
    with alerts_file.open("r", encoding="utf-8") as fh:
        alerts = json.load(fh)
    values = [item.get("ioc_value") for item in alerts]
    counts = Counter(values)
    return [ip for ip, count in counts.items() if count > 1]


def print_top_reported(date_str: str, alerts_file: Path, top: int = 5) -> None:
    """Print IPs with the most reports for a given date."""
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
