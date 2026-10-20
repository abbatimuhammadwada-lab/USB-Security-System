#!/usr/bin/env python3
"""
Standalone database initialization script.

Run this once (or any time - it is idempotent) to create the SQLite
database file and required tables without starting the full application:

    python scripts/init_db.py
"""

import logging
import sys
from pathlib import Path

# Allow running this script directly via `python scripts/init_db.py`
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config.settings import settings
from app.database.init_db import initialize_database, get_schema_version


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    print(f"Initializing database at: {settings.database_url}")
    try:
        initialize_database()
    except Exception as exc:
        print(f"FATAL: database initialization failed: {exc}", file=sys.stderr)
        return 1
    print(f"Database initialized successfully. schema_version={get_schema_version()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
