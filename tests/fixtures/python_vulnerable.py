# This file contains INTENTIONALLY VULNERABLE code for testing
# the AST heuristic engine.  Do NOT use any of this in production.

import hashlib
import pickle
import subprocess
import os
import yaml
import jwt
import requests
import logging

logger = logging.getLogger(__name__)


# ── A03: SQL Injection (string concat) ─────────────────────────────────

def get_user_by_id(cursor, user_id):
    cursor.execute("SELECT * FROM users WHERE id=" + user_id)
    return cursor.fetchone()


# ── A03: SQL Injection (f-string) ──────────────────────────────────────

def get_user_by_name(cursor, name):
    cursor.execute(f"SELECT * FROM users WHERE name='{name}'")
    return cursor.fetchone()


# ── A03: eval / exec ──────────────────────────────────────────────────

def process_formula(user_input):
    return eval(user_input)


def run_code(code_string):
    exec(code_string)


# ── A03: Command injection ────────────────────────────────────────────

def run_command(cmd):
    os.system(cmd)


def run_subprocess(user_cmd):
    subprocess.run(user_cmd, shell=True)


# ── A04: Empty except ─────────────────────────────────────────────────

def risky_operation():
    try:
        do_something()
    except:
        pass


def broad_catch():
    try:
        do_something()
    except Exception:
        pass


# ── A02: Hardcoded secrets ────────────────────────────────────────────

password = "super_secret_123"
api_key = "sk-live-abc123def456"
SECRET_TOKEN = "ghp_xxxxxxxxxxxx"


# ── A02: Weak crypto ──────────────────────────────────────────────────

def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()


def hash_token(token):
    return hashlib.sha1(token.encode()).hexdigest()


# ── A05: Security misconfiguration ────────────────────────────────────

DEBUG = True
HOST = "0.0.0.0"


# ── A08: Dangerous deserialization ────────────────────────────────────

def load_data(raw_bytes):
    return pickle.loads(raw_bytes)


def load_yaml_config(text):
    return yaml.load(text)


# ── A09: Logging sensitive data ───────────────────────────────────────

def login(user, password):
    logger.info(password)
    print(password)


# ── A07: JWT verify disabled ─────────────────────────────────────────

def decode_token(token):
    return jwt.decode(token, options={"verify_signature": False})


# ── A10: SSRF ─────────────────────────────────────────────────────────

def fetch_url(user_url):
    return requests.get(user_url)


# ── Memory: unclosed resource ─────────────────────────────────────────

def read_file():
    f = open("data.txt")
    data = f.read()
    return data
