"""Intentionally vulnerable Python fixture for Semgrep demo/tests."""

import sqlite3
import subprocess


def run_command(cmd: str) -> int:
    return subprocess.call(cmd, shell=True)


def fetch_user(username: str) -> list[tuple]:
    connection = sqlite3.connect(":memory:")
    query = f"SELECT * FROM users WHERE name = '{username}'"
    return connection.execute(query).fetchall()


def always_true() -> bool:
    if 1 == 1:
        return True
    return False

