import sqlite3
import logging
from pathlib import Path
from typing import Iterable, Dict, Any, List

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "iocs.sqlite"


def init_db(path: Path = DEFAULT_DB_PATH) -> None:
    """Create database and table if not present."""
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS iocs (" 
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "ioc_value TEXT, "
        "ioc_type TEXT, "
        "source TEXT, "
        "date TEXT, "
        "UNIQUE(ioc_value, ioc_type)" 
        ")"
    )
    conn.commit()
    conn.close()


def insert_iocs(iocs: Iterable[Dict[str, Any]], path: Path = DEFAULT_DB_PATH) -> int:
    """Insert IOCs ignoring duplicates. Return number of new entries."""
    init_db(path)
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    added = 0
    for ioc in iocs:
        try:
            cur.execute(
                "INSERT OR IGNORE INTO iocs (ioc_value, ioc_type, source, date) VALUES (?, ?, ?, ?)",
                (
                    ioc.get("ioc_value"),
                    ioc.get("ioc_type"),
                    ioc.get("source"),
                    ioc.get("date"),
                ),
            )
            if cur.rowcount:
                added += 1
        except Exception:
            logging.exception("Erro ao inserir IOC %s", ioc.get("ioc_value"))
    conn.commit()
    conn.close()
    return added


def filter_existing_iocs(iocs: List[Dict[str, Any]], path: Path = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    """Return only IOCs not yet present in database."""
    init_db(path)
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    new_items: List[Dict[str, Any]] = []
    for ioc in iocs:
        cur.execute(
            "SELECT 1 FROM iocs WHERE ioc_value=? AND ioc_type=?",
            (ioc.get("ioc_value"), ioc.get("ioc_type")),
        )
        if cur.fetchone() is None:
            new_items.append(ioc)
    conn.close()
    return new_items
