from __future__ import annotations

import csv
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any


def initialize_database(database_path: Path) -> None:
    database_path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(database_path)) as connection:
        with connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                    ip_address TEXT NOT NULL,
                    status TEXT NOT NULL,
                    local_match INTEGER NOT NULL,
                    local_label TEXT NOT NULL,
                    local_score INTEGER,
                    api_status TEXT NOT NULL,
                    abuse_score INTEGER,
                    reports INTEGER,
                    country TEXT NOT NULL,
                    isp TEXT NOT NULL,
                    message TEXT NOT NULL
                )
                """
            )


def record_event(database_path: Path, result: dict[str, Any]) -> None:
    initialize_database(database_path)
    with closing(sqlite3.connect(database_path)) as connection:
        with connection:
            connection.execute(
                """
                INSERT INTO events (
                    ip_address, status, local_match, local_label, local_score,
                    api_status, abuse_score, reports, country, isp, message
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result["ip_address"],
                    result["status"],
                    int(result["local_match"]),
                    result["local_label"],
                    result["local_score"],
                    result["api_status"],
                    result["abuse_score"],
                    result["reports"],
                    result["country"],
                    result["isp"],
                    result["message"],
                ),
            )


def fetch_events(database_path: Path, limit: int = 500) -> list[dict[str, Any]]:
    initialize_database(database_path)
    with closing(sqlite3.connect(database_path)) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(row) for row in rows]


def export_events_csv(events: list[dict[str, Any]]) -> str:
    if not events:
        return ""
    import io

    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=list(events[0].keys()))
    writer.writeheader()
    writer.writerows(events)
    return output.getvalue()
