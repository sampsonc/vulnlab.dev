"""MariaDB connection helper for SQLi labs.

One connection per request, tied to flask.g. Reads credentials from env
(VULNLAB_SQLI_DB_*); the deploy systemd unit loads them from
/etc/vulnlab/sqli.env via EnvironmentFile=.

Important: connections are configured WITHOUT multi-statement support.
That keeps the labs honest about *which* injection class they teach — a
stacked-query exploit shouldn't accidentally work everywhere.
"""
from __future__ import annotations

import os

import pymysql
from flask import g


def _config() -> dict:
    return {
        "host": os.environ.get("VULNLAB_SQLI_DB_HOST", "127.0.0.1"),
        "port": int(os.environ.get("VULNLAB_SQLI_DB_PORT", "3306")),
        "user": os.environ["VULNLAB_SQLI_DB_USER"],
        "password": os.environ["VULNLAB_SQLI_DB_PASSWORD"],
        "database": os.environ["VULNLAB_SQLI_DB_NAME"],
        "charset": "utf8mb4",
        "autocommit": True,
        # DO NOT enable CLIENT.MULTI_STATEMENTS — labs target specific
        # injection classes; stacked queries would make many of them trivial
        # in ways that don't reflect what tools/scanners actually exercise.
    }


def get_conn() -> pymysql.connections.Connection:
    if "db" not in g:
        g.db = pymysql.connect(**_config())
    return g.db


def close_conn(_exc=None) -> None:
    db = g.pop("db", None)
    if db is not None:
        try:
            db.close()
        except Exception:
            pass
