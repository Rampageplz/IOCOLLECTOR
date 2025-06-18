import argparse
import datetime
import json
from collections import Counter, defaultdict
from pathlib import Path

ALERTS_FILE = Path(__file__).resolve().parent / "alerts.json"


def generate_report(date: str) -> dict:
    if not ALERTS_FILE.exists():
        raise FileNotFoundError("alerts.json não encontrado")
    with ALERTS_FILE.open("r", encoding="utf-8") as fh:
        alerts = json.load(fh)
    daily = [a for a in alerts if a.get("date") == date]
    total = len(daily)

    by_source = Counter(a.get("source") for a in daily)
    by_type = Counter(a.get("ioc_type") for a in daily)

    occurrences = defaultdict(list)
    for a in daily:
        occurrences[a.get("ioc_value")].append(a.get("source"))

    duplicates = {
        val: list(set(srcs)) for val, srcs in occurrences.items() if len(set(srcs)) > 1
    }

    top_values = Counter([a.get("ioc_value") for a in daily]).most_common(10)

    return {
        "date": date,
        "total_iocs": total,
        "by_source": dict(by_source),
        "by_type": dict(by_type),
        "duplicates": duplicates,
        "top_values": top_values,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Gera relatório de IOCs")
    parser.add_argument(
        "--date",
        default=datetime.date.today().isoformat(),
        help="Data dos IOCs (YYYY-MM-DD)",
    )
    parser.add_argument("--output", help="Salvar relatório em arquivo JSON")
    args = parser.parse_args()

    report = generate_report(args.date)
    print(json.dumps(report, indent=2, ensure_ascii=False))
    if args.output:
        out = Path(args.output)
        out.write_text(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
