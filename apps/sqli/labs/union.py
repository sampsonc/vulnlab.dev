"""SQLi lab: union — INTENTIONALLY VULNERABLE.

Product browser. Category filter is concatenated straight into the SQL
without parameters. Three columns are returned (name, description, price),
making UNION-based extraction straightforward — any attacker who can
guess the column count can pull arbitrary data out via UNION SELECT.
"""
from __future__ import annotations

from pathlib import Path

import pymysql
from flask import Blueprint, render_template, request

from ..db import get_conn

bp = Blueprint("sqli_union", __name__, url_prefix="/union")

META = {
    "slug": "union",
    "title": "In-band UNION-based SQLi",
    "summary": "Product category filter concatenated into SQL; result rows are rendered.",
    "hint": (
        "Query shape: SELECT name, description, price FROM products WHERE "
        "category='<input>'. The three columns are returned to you. Try "
        "?category=widgets' UNION SELECT name, value, 0 FROM secrets-- "
    ),
    "sink": "string-concatenated SELECT",
    "source_path": str(Path(__file__).resolve()),
    "vulnerable": True,
}


@bp.route("/", methods=["GET"])
def lab():
    category = request.args.get("category", "")
    rows = []
    error = None
    query = None
    if category:
        # INTENTIONAL: f-string into SQL.
        query = f"SELECT name, description, price FROM products WHERE category='{category}'"
        try:
            with get_conn().cursor() as cur:
                cur.execute(query)
                rows = cur.fetchall()
        except pymysql.MySQLError as e:
            error = f"{type(e).__name__}: {e}"
    return render_template(
        "lab_union.html",
        meta=META,
        category=category,
        rows=rows,
        error=error,
        query=query,
    )
