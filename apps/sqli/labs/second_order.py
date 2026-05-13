"""SQLi lab: second-order — INTENTIONALLY VULNERABLE.

Two-step injection that defeats "fixed at first-sink only" sanitizers:

  1. POST /register  — username is parameterized INSERT. Safe in isolation.
                       A static analyzer or a tainted-tracking DAST will
                       see prepared-statement use and clear this sink.

  2. GET  /profile?id=<n> — looks up the username (parameterized), then
                            *uses that username verbatim* in a downstream
                            SELECT against `notes` that IS concatenated.

The attacker registers a username that is itself a SQL payload, then
visits their profile. The downstream concatenated query carries the
stored payload into the SQL parser.
"""
from __future__ import annotations

from pathlib import Path

import pymysql
from flask import Blueprint, render_template, request

from ..db import get_conn

bp = Blueprint("sqli_second_order", __name__, url_prefix="/second-order")

META = {
    "slug": "second-order",
    "title": "Second-order SQLi",
    "summary": "Registration is parameterized; profile view re-uses stored input unsafely.",
    "hint": (
        "Register a user whose username is itself a SQL payload, e.g. "
        "' UNION SELECT value FROM secrets WHERE name='sqli-second-order'# "
        "(use # not `-- ` because the register handler strips trailing "
        "whitespace). Then visit /second-order/profile?id=<your new id> — "
        "the profile page joins notes by username via string concatenation, "
        "and your stored payload finally fires."
    ),
    "sink": "stored input -> later string-concatenated SELECT",
    "source_path": str(Path(__file__).resolve()),
    "vulnerable": True,
}


@bp.route("/", methods=["GET"])
def lab():
    # Show the register form + list recent registrations so users can find
    # their own id.
    with get_conn().cursor() as cur:
        cur.execute("SELECT id, username FROM users ORDER BY id DESC LIMIT 20")
        recent = cur.fetchall()
    return render_template("lab_second_order.html", meta=META, recent=recent, profile=None)


@bp.route("/register", methods=["POST"])
def register():
    username = (request.form.get("username") or "").strip()
    new_id = None
    error = None
    if username:
        try:
            with get_conn().cursor() as cur:
                # SAFE: parameterized. The payload sits in the column verbatim.
                cur.execute(
                    "INSERT INTO users (username, password, email, role) "
                    "VALUES (%s, %s, %s, %s)",
                    (username, "lab-placeholder", "", "user"),
                )
                new_id = cur.lastrowid
                # Seed a placeholder note for the new user, also parameterized.
                cur.execute(
                    "INSERT INTO notes (owner, body) VALUES (%s, %s)",
                    (username, "Welcome to vulnlab — this is your first note."),
                )
        except pymysql.MySQLError as e:
            error = f"{type(e).__name__}: {e}"
    with get_conn().cursor() as cur:
        cur.execute("SELECT id, username FROM users ORDER BY id DESC LIMIT 20")
        recent = cur.fetchall()
    return render_template(
        "lab_second_order.html",
        meta=META,
        recent=recent,
        profile=None,
        new_id=new_id,
        error=error,
    )


@bp.route("/profile", methods=["GET"])
def profile():
    uid = request.args.get("id", "")
    profile_data = None
    notes = []
    error = None
    query = None
    if uid:
        try:
            with get_conn().cursor() as cur:
                # SAFE: parameterized lookup.
                cur.execute("SELECT id, username, role FROM users WHERE id=%s", (uid,))
                row = cur.fetchone()
                if row:
                    profile_data = {"id": row[0], "username": row[1], "role": row[2]}
                    # INTENTIONAL: the username we just fetched is concatenated
                    # into this query. If the user registered with a SQL
                    # payload, it activates here.
                    query = f"SELECT body FROM notes WHERE owner='{row[1]}'"
                    cur.execute(query)
                    notes = [r[0] for r in cur.fetchall()]
        except pymysql.MySQLError as e:
            error = f"{type(e).__name__}: {e}"
    return render_template(
        "lab_second_order.html",
        meta=META,
        recent=None,
        profile=profile_data,
        notes=notes,
        error=error,
        query=query,
    )
