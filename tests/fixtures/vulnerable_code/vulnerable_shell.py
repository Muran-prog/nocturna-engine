"""Additional vulnerable fixture file for Semgrep parser coverage."""

import hashlib
import os


def execute_script(script_name: str) -> int:
    return os.system(f"bash {script_name}")


def weak_hash(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()

