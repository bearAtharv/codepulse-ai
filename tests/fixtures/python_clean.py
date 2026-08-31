# This file contains CLEAN, SAFE code that should NOT trigger any
# AST heuristic.  Used to verify zero false-positives.

import hashlib
import json
import os
import subprocess
import logging

from yaml import SafeLoader

logger = logging.getLogger(__name__)


# ── Safe SQL (parameterised queries) ──────────────────────────────────

def get_user_by_id(cursor, user_id):
    cursor.execute("SELECT * FROM users WHERE id=%s", (user_id,))
    return cursor.fetchone()


# ── Safe eval alternative ─────────────────────────────────────────────

import ast

def process_formula(user_input):
    return ast.literal_eval(user_input)


# ── Safe subprocess (list form) ──────────────────────────────────────

def run_command(filename):
    subprocess.run(["cat", filename], check=True)


# ── Proper exception handling ─────────────────────────────────────────

def risky_operation():
    try:
        do_something()
    except Exception as e:
        logger.exception("Operation failed: %s", e)
        raise


# ── Secrets from environment ──────────────────────────────────────────

password = os.environ.get("PASSWORD")
api_key = os.environ["API_KEY"]


# ── Strong crypto ────────────────────────────────────────────────────

def hash_password(pw):
    return hashlib.sha256(pw.encode()).hexdigest()


# ── Safe configuration ───────────────────────────────────────────────

DEBUG = False
HOST = "127.0.0.1"


# ── Safe deserialization ─────────────────────────────────────────────

def load_data(raw_bytes):
    return json.loads(raw_bytes)


def load_yaml_config(text):
    return yaml.load(text, Loader=SafeLoader)


# ── Safe logging ─────────────────────────────────────────────────────

def login(user, password):
    logger.info("User %s logged in", user)


# ── Safe file handling (with statement) ──────────────────────────────

def read_file():
    with open("data.txt") as f:
        return f.read()
