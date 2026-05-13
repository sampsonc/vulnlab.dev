"""SQLi lab: blind-bool — INTENTIONALLY VULNERABLE.

Product details by id. The id is concatenated into the WHERE clause. The
response either shows the product or says "not found" — no error text, no
column reflection. The only signal is the binary "row / no row" state.

Classic boolean-blind oracle. A scanner that only knows in-band exfil
will give up here.
"""
from __future__ import annotations

from pathlib import Path

import pymysql
from flask import Blueprint, render_template, request

from ..db import get_conn

bp = Blueprint("sqli_blind_bool", __name__, url_prefix="/blind-bool")

META = {
    "slug": "blind-bool",
    "title": "Blind SQLi (boolean oracle)",
    "summary": "Product lookup leaks only existence. No errors, no reflection.",
    "hint": (
        "Query: SELECT name, description FROM products WHERE id=<input>. "
        "Try ?id=1 AND SUBSTRING((SELECT value FROM secrets WHERE "
        "name='sqli-blind-bool'),1,1)='V'. If the page shows product 1, the "
        "char is V; otherwise it's not. Walk character by character."
    ),
    "sink": "string-concatenated SELECT (no error reflection)",
    "source_path": str(Path(__file__).resolve()),
    "vulnerable": True,
}


@bp.route("/", methods=["GET"])
def lab():
    pid = request.args.get("id", "")
    product = None
    if pid:
        # INTENTIONAL: raw concatenation, no parameterization, no type cast.
        query = f"SELECT name, description FROM products WHERE id={pid}"
        try:
            with get_conn().cursor() as cur:
                cur.execute(query)
                row = cur.fetchone()
                if row:
                    product = {"name": row[0], "description": row[1]}
        except pymysql.MySQLError:
            # Errors are swallowed: the only signal is presence/absence of
            # the product. This is what makes it boolean-blind, not
            # error-based.
            product = None
    return render_template("lab_blind_bool.html", meta=META, pid=pid, product=product)
