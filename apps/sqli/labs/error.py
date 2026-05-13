"""SQLi lab: error — INTENTIONALLY VULNERABLE.

Login form whose handler concatenates both username and password into the
SQL and helpfully renders the raw exception when the query fails. The
exception text on MariaDB includes whatever value the attacker forced into
the error message, so EXTRACTVALUE/UPDATEXML-style extraction works.
"""
from __future__ import annotations

from pathlib import Path

import pymysql
from flask import Blueprint, render_template, request

from ..db import get_conn

bp = Blueprint("sqli_error", __name__, url_prefix="/error")

META = {
    "slug": "error",
    "title": "Error-based SQLi (login)",
    "summary": "Login query concatenates user input AND the app renders raw SQL errors.",
    "hint": (
        "Query: SELECT id, role FROM users WHERE username='<u>' AND "
        "password='<p>'. SQL errors are shown verbatim. Use EXTRACTVALUE: "
        "username=' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT value FROM "
        "secrets WHERE name='sqli-error')))-- "
    ),
    "sink": "string-concatenated SELECT + raw exception render",
    "source_path": str(Path(__file__).resolve()),
    "vulnerable": True,
}


@bp.route("/", methods=["GET", "POST"])
def lab():
    username = request.values.get("username", "")
    password = request.values.get("password", "")
    result = error = query = None
    if request.method == "POST" and (username or password):
        # INTENTIONAL: both fields concatenated into SQL.
        query = (
            f"SELECT id, role FROM users "
            f"WHERE username='{username}' AND password='{password}'"
        )
        try:
            with get_conn().cursor() as cur:
                cur.execute(query)
                row = cur.fetchone()
                if row:
                    result = f"Welcome, user id={row[0]}, role={row[1]}."
                else:
                    result = "Invalid credentials."
        except pymysql.MySQLError as e:
            # INTENTIONAL: full exception in the response.
            error = f"{type(e).__name__}: {e}"
    return render_template(
        "lab_error.html",
        meta=META,
        username=username,
        result=result,
        error=error,
        query=query,
    )
