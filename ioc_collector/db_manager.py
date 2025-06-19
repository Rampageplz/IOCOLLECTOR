import json
import logging
import sqlite3
from pathlib import Path
from typing import Iterable, Dict


def init_db(db_path: Path) -> None:
    """Create SQLite database and iocs table if it doesn't exist."""
    conn = sqlite3.connect(db_path)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ioc_value TEXT NOT NULL,
                ioc_type TEXT NOT NULL,
                source TEXT,
                date TEXT,
                time TEXT,
                description TEXT,
                tags TEXT,
                extra TEXT,
                UNIQUE(ioc_value, ioc_type)
        )"""
    )
    conn.commit()
    conn.close()


def insert_iocs(iocs: Iterable[Dict[str, any]], db_path: Path) -> int:
    """Insert IOCs into the database skipping duplicates."""
    init_db(db_path)
    conn = sqlite3.connect(db_path)
    inserted = 0
    for ioc in iocs:
        try:
            conn.execute(
                "INSERT INTO iocs (ioc_value, ioc_type, source, date, time, description, tags, extra) VALUES (?,?,?,?,?,?,?,?)",
                (
                    ioc.get("ioc_value"),
                    ioc.get("ioc_type"),
                    ioc.get("source"),
                    ioc.get("date"),
                    ioc.get("time"),
                    ioc.get("description"),
                    json.dumps(ioc.get("tags", [])),
                    json.dumps({k: v for k, v in ioc.items() if k not in {
                        "ioc_value",
                        "ioc_type",
                        "source",
                        "date",
                        "time",
                        "description",
                        "tags",
                    }}),
                ),
            )
            inserted += 1
        except sqlite3.IntegrityError:
            continue
        except Exception:
            logging.exception("Erro ao inserir IOC no banco")
    conn.commit()
    conn.close()
    return inserted
