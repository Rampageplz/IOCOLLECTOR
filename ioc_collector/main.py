"""Script principal que orquestra a coleta e exibição dos IOCs."""

import argparse
import datetime
import json
import logging
import os
from pathlib import Path

from rich.logging import RichHandler
from pythonjsonlogger import jsonlogger

from ioc_collector.collectors.collector_abuse import collect_abuse
from ioc_collector.collectors.collector_otx import collect_otx
from ioc_collector.collectors.collector_urlhaus import collect_urlhaus
from ioc_collector.utils.utils import (
    generate_requirements,
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


def show_banner() -> None:
    """Exibe informações iniciais e coleta chaves de API se necessário."""
    banner = (
        "\n" +
        "########################\n" +
        "#        Inteltool       #\n" +
        "#  O que é: coleta de   #\n" +
        "#  IOCs de múltiplos    #\n" +
        "#  feeds.               #\n" +
        "########################\n"
    )
    print(banner)


def setup_logging(level: int = logging.INFO) -> None:
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

    logging.basicConfig(level=level, handlers=[file_handler, json_handler, console_handler])


def run_collectors(config: dict, selected: list | None = None) -> None:
    """Execute all active collectors defined in configuration."""
    active = selected or config.get("ACTIVE_COLLECTORS", ["abuseipdb"])
    keys = config.get("API_KEYS", {})
    all_iocs = []

    for name in active:
        logging.info("In\u00edcio da coleta %s", name)
        if name == "abuseipdb":
            iocs = collect_abuse(keys.get("ABUSEIPDB"), config)
        elif name == "otx":
            api = keys.get("OTX")
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
        dicts = [ioc.to_dict() for ioc in iocs]
        save_daily_iocs(dicts, folder)
        if dicts:
            preview = json.dumps(dicts[:2], indent=4, ensure_ascii=False)
            logging.info("Previa de %s:\n%s", name, preview)
            print(f"\nPrévia {name}:")
            print(preview)
        else:
            msg = f"Nenhum IOC retornado de {name}"
            logging.info(msg)
            print(msg)
        all_iocs.extend(dicts)
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

    if config.get("GENERATE_REQUIREMENTS", True):
        generate_requirements(Path(__file__).with_name("requirements.txt"))


def main() -> None:
    """Parse command line arguments and start the collection."""
    parser = argparse.ArgumentParser(description="Coletor de IOCs de múltiplos feeds")
    parser.add_argument(
        "--top",
        help="Mostrar IPs mais reportados na data (YYYY-MM-DD) a partir de alerts.json",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Nível de log do programa",
    )
    parser.add_argument(
        "--collectors",
        help="Lista de coletores a executar (separados por vírgula)",
    )
    args = parser.parse_args()

    show_banner()

    setup_logging(getattr(logging, args.log_level))

    try:
        config = load_config()
    except RuntimeError:
        logging.exception("Erro ao carregar configuração")
        return

    keys = config.get("API_KEYS", {})

    from rich.console import Console
    from rich.table import Table

    console = Console()
    table = Table(title="Status dos Coletores", show_lines=True)
    table.add_column("Coletor")
    table.add_column("Ativo")
    table.add_column("API Key")
    for coll in ["abuseipdb", "otx", "urlhaus"]:
        active = "Sim" if coll in config.get("ACTIVE_COLLECTORS", []) else "Não"
        key_present = "Sim" if keys.get(coll.upper()) else "Não"
        table.add_row(coll, active, key_present)
    console.print(table)

    missing = []
    if "abuseipdb" in config.get("ACTIVE_COLLECTORS", []) and not (keys.get("ABUSEIPDB") or os.getenv("ABUSE_MOCK_FILE")):
        missing.append("ABUSEIPDB")
    if "otx" in config.get("ACTIVE_COLLECTORS", []) and not keys.get("OTX"):
        missing.append("OTX")
    if missing:
        msg = "API Keys ausentes: " + ", ".join(missing)
        logging.error(msg)
        console.print(f"[red]{msg}[/red]")
        return

    if args.top:
        print_top_reported(args.top, ALERTS_FILE)
        return

    selected = None
    if args.collectors:
        selected = [c.strip() for c in args.collectors.split(',') if c.strip()]

    run_collectors(config, selected)


if __name__ == "__main__":
    main()
