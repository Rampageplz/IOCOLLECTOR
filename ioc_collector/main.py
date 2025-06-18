"""Script principal que orquestra a coleta e exibição dos IOCs."""

import argparse
import datetime
import logging
from pathlib import Path

from rich.logging import RichHandler
from pythonjsonlogger import jsonlogger

from ioc_collector.collectors.collector_abuse import collect_abuse
from ioc_collector.collectors.collector_otx import collect_otx
from ioc_collector.collectors.collector_urlhaus import collect_urlhaus
from ioc_collector.utils.utils import (
    generate_requirements,
    load_api_keys,
    load_config,
    save_daily_iocs,
)
from ioc_collector.alerts_manager import (
    update_alerts,
    check_duplicates,
    print_top_reported,
)


LOG_DIR = Path(__file__).resolve().parent.parent / "logs"
DATA_ROOT = Path(__file__).resolve().parent.parent / "data"
ALERTS_FILE = Path(__file__).resolve().parent / "alerts.json"


def setup_logging() -> None:
    """Configure file and console logging with RichHandler and JSON file."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_path = LOG_DIR / f"{datetime.date.today().strftime('%Y-%m-%d')}.log"
    json_log_path = LOG_DIR / f"{datetime.date.today().strftime('%Y-%m-%d')}.json"

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    )

    json_handler = logging.FileHandler(json_log_path, encoding="utf-8")
    json_handler.setFormatter(jsonlogger.JsonFormatter())

    console_handler = RichHandler(rich_tracebacks=True)

    logging.basicConfig(
        level=logging.DEBUG,
        handlers=[file_handler, json_handler, console_handler],
    )


def run_collectors(config: dict, keys: dict) -> None:
    """Execute all active collectors defined in configuration."""
    active = config.get("ACTIVE_COLLECTORS", ["abuseipdb"])
    all_iocs = []

    for name in active:
        logging.info("In\u00edcio da coleta %s", name)
        if name == "abuseipdb":
            iocs = collect_abuse(keys.get("ABUSEIPDB_API_KEY"), config)
        elif name == "otx":
            api = keys.get("OTX_API_KEY")
            if not api:
                logging.warning("OTX_API_KEY não definido; ignorando coletor")
                continue
            iocs = collect_otx(api)
        elif name == "urlhaus":
            iocs = collect_urlhaus()
        else:
            logging.warning("Coletor desconhecido: %s", name)
            continue

        logging.info("%s IOCs coletados de %s", len(iocs), name)
        folder = DATA_ROOT / name
        save_daily_iocs(iocs, folder)
        all_iocs.extend(iocs)
        logging.info("Fim da coleta %s", name)

    if not all_iocs:
        logging.info("Nenhum IOC coletado")
        return

    added = update_alerts(all_iocs, ALERTS_FILE)
    if added:
        logging.info("Novos IOCs adicionados: %s", added)
    else:
        logging.info("alerts.json está atualizado. Nenhum novo IOC.")

    dups = check_duplicates(ALERTS_FILE)
    if dups:
        logging.warning("Valores duplicados em alerts.json: %s", ", ".join(dups))

    generate_requirements(Path(__file__).with_name("requirements.txt"))


def main() -> None:
    """Parse command line arguments and start the collection."""
    setup_logging()
    parser = argparse.ArgumentParser(description="Coletor de IOCs de múltiplos feeds")
    parser.add_argument(
        "--top",
        help="Mostrar IPs mais reportados na data (YYYY-MM-DD) a partir de alerts.json",
    )
    args = parser.parse_args()

    try:
        api_keys = load_api_keys()
        config = load_config()
    except RuntimeError:
        logging.exception("Erro ao carregar configuração ou API keys")
        return

    if args.top:
        print_top_reported(args.top, ALERTS_FILE)
        return

    run_collectors(config, api_keys)


if __name__ == "__main__":
    main()
