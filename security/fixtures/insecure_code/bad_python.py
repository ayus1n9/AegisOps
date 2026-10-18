"""Synthetic insecure Python fixture for scanner verification only."""
import hashlib
import os
import subprocess


def insecure_eval(user_input: str):
    # Intentional Bandit B307 / Semgrep trigger
    return eval(user_input)  # nosec: B307 intentional test fixture


def insecure_hash(data: str):
    # Intentional Bandit B303 / Semgrep trigger
    return hashlib.md5(data.encode()).hexdigest()  # nosec: B303 intentional test fixture


def insecure_command(cmd: str):
    # Intentional Bandit B602 / Semgrep trigger
    return subprocess.Popen(cmd, shell=True)  # nosec: B602 intentional test fixture
