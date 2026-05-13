"""SQLi lab: blind-time — INTENTIONALLY VULNERABLE.

Username availability check. The response is identical regardless of
whether the username exists, so there's no boolean oracle. The attacker
gets nothing — except control over how long the query takes, via SLEEP().

Time-based blind is the slowest extraction primitive, and it's the one
tools that lack a real timing model tend to miss.
"""
from __future__ import annotations

from pathlib import Path

import pymysql
from flask import Blueprint, render_template, request

from ..db import get_conn

bp = Blueprint("sqli_blind_time", __name__, url_prefix="/blind-time")

META = {
    "slug": "blind-time",
    "title": "Blind SQLi (time-based)",
    "summary": "Username availability returns identical responses; only query time leaks.",
    "hint": (
        "Query: SELECT username FROM users WHERE username='<input>' LIMIT 1. "
        "Response is the same string either way. Use SLEEP() inside a UNION "
        "or AND clause: nonexistent' UNION SELECT IF(SUBSTRING((SELECT "
        "value FROM secrets WHERE name='sqli-blind-time'),1,1)='V', "
        "SLEEP(2), 'x')-- "
    ),
    "sink": "string-concatenated SELECT (no response variation)",
    "source_path": str(Path(__file__).resolve()),
    "vulnerable": True,
}


@bp.route("/", methods=["GET"])
def lab():
    username = request.args.get("username", "")
    response_msg = None
    if username:
        # INTENTIONAL: raw concatenation. Note the response normalization
        # below — we never reveal which branch was taken.
        query = (
            f"SELECT username FROM users WHERE username='{username}' LIMIT 1"
        )
        try:
            with get_conn().cursor() as cur:
                cur.execute(query)
                cur.fetchall()  # drain
        except pymysql.MySQLError:
            pass
        # Same message either way. Timing is the only signal.
        response_msg = "Username check complete."
    return render_template("lab_blind_time.html", meta=META, username=username, msg=response_msg)
