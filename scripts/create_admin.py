#!/usr/bin/env python3
"""
Secure, one-time initial administrator creation.

Interactive (recommended):
    python scripts/create_admin.py

Non-interactive (e.g. scripted demo/lab setup) - reads
DEFAULT_ADMIN_USERNAME / DEFAULT_ADMIN_PASSWORD from the environment
(or .env) instead of prompting:
    python scripts/create_admin.py --non-interactive

The password is never echoed to the terminal, never logged, and never
hardcoded anywhere in source. If an administrator account already
exists, this script refuses to create another one - use the
(Phase 4+) user management screen instead.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.database.init_db import initialize_database
from app.core.exceptions import ConfigurationError
from app.security.bootstrap import create_initial_administrator, administrator_exists
from app.security.password import validate_password_strength


def prompt_credentials() -> tuple[str, str]:
    username = input("New administrator username: ").strip()
    while True:
        password = getpass.getpass("New administrator password: ")
        problems = validate_password_strength(password)
        if problems:
            print("Password rejected:")
            for p in problems:
                print(f"  - {p}")
            continue
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("Passwords do not match. Try again.")
            continue
        return username, password


def non_interactive_credentials() -> tuple[str, str]:
    username = os.getenv("DEFAULT_ADMIN_USERNAME")
    password = os.getenv("DEFAULT_ADMIN_PASSWORD")
    if not username or not password:
        print(
            "FATAL: --non-interactive requires DEFAULT_ADMIN_USERNAME and "
            "DEFAULT_ADMIN_PASSWORD to be set in the environment or .env file.",
            file=sys.stderr,
        )
        sys.exit(1)
    return username, password


def main() -> int:
    parser = argparse.ArgumentParser(description="Create the initial USB Security System administrator.")
    parser.add_argument(
        "--non-interactive", action="store_true",
        help="Read credentials from DEFAULT_ADMIN_USERNAME/DEFAULT_ADMIN_PASSWORD instead of prompting.",
    )
    args = parser.parse_args()

    initialize_database()

    if administrator_exists():
        print("An administrator account already exists. Nothing to do.")
        return 0

    if args.non_interactive:
        username, password = non_interactive_credentials()
    else:
        username, password = prompt_credentials()

    try:
        admin = create_initial_administrator(username, password)
    except ConfigurationError as exc:
        print(f"FATAL: {exc}", file=sys.stderr)
        return 1

    print(f"Administrator account '{admin.username}' (id={admin.id}) created successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
