from datetime import datetime, timezone
from pathlib import Path


LOG_PATH = Path(__file__).resolve().parent / "logs" / "sample_server.log"

LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
with LOG_PATH.open("a", encoding="utf-8") as log_file:
    log_file.write(
        f'{datetime.now(timezone.utc).isoformat()} GET /health '
        'client=198.51.100.23 status=200\n'
    )

print(f"Added one sample entry to {LOG_PATH}")
