import argparse
import datetime
import logging
from pathlib import Path

from collectors.collector_abuse import fetch_blacklist, fetch_ip_details
from utils.utils import generate_requirements, load_api_key, save_daily_iocs, transform_data
from alerts_manager import update_alerts, check_duplicates, print_top_reported


LOG_DIR = Path(__file__).resolve().parent.parent / "logs"
DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "abuseipdb"
ALERTS_FILE = Path(__file__).resolve().parent / "alerts.json"


def setup_logging() -> None:
    """Configure logging to file under the logs directory."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_path = LOG_DIR / "collector.log"
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.FileHandler(log_path, encoding="utf-8"), logging.StreamHandler()],
    )


def collect(api_key: str) -> None:
    """Perform the entire IOC collection workflow."""
    try:
        blacklist = fetch_blacklist(api_key)
    except RuntimeError as exc:
        logging.error(exc)
        return

    if blacklist:
        logging.info("IPs com score >= 80 nas últimas 24h:")
        for item in blacklist:
            ip = item.get("ipAddress")
            score = item.get("abuseConfidenceScore")
            logging.info("  %s - score %s", ip, score)
        logging.info("Total: %s", len(blacklist))
    else:
        logging.info("Nenhum IP reportado nas últimas 24h com score >= 80.")

    details = fetch_ip_details(api_key, blacklist, limit=20)
    processed = transform_data(details)
    logging.info("IOCs coletados: %s", len(processed))

    save_daily_iocs(processed, DATA_DIR)
    added = update_alerts(processed, ALERTS_FILE)
    if added:
        logging.info("Novos IOCs adicionados: %s", added)
    else:
        logging.info("alerts.json está atualizado. Nenhum novo IOC.")

    dups = check_duplicates(ALERTS_FILE)
    if dups:
        logging.info("IPs duplicados em alerts.json: %s", ", ".join(dups))
    else:
        logging.info("Nenhum IP duplicado em alerts.json.")

    generate_requirements(Path(__file__).with_name("requirements.txt"))

    today = datetime.date.today().isoformat()
    print_top_reported(today, ALERTS_FILE)


def main() -> None:
    """Parse command line arguments and start the collection."""
    setup_logging()
    parser = argparse.ArgumentParser(description="Coletor de IOCs do AbuseIPDB")
    parser.add_argument(
        "--top",
        help="Mostrar IPs mais reportados na data (YYYY-MM-DD) a partir de alerts.json",
    )
    args = parser.parse_args()

    try:
        api_key = load_api_key()
    except RuntimeError as exc:
        logging.error(exc)
        return

    if args.top:
        print_top_reported(args.top, ALERTS_FILE)
        return

    collect(api_key)


if __name__ == "__main__":
    main()
