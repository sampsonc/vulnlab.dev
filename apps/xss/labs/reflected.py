"""XSS lab: reflected — INTENTIONALLY VULNERABLE.

The classic textbook XSS: take ?q from the query string, drop it into the
page unescaped. Every scanner that claims to find XSS should fire on this.
"""
from __future__ import annotations

from pathlib import Path

from flask import Blueprint, render_template, request
from markupsafe import Markup

bp = Blueprint("reflected", __name__, url_prefix="/reflected")

META = {
    "slug": "reflected",
    "title": "Reflected XSS",
    "summary": "Search box echoes your query into the page without escaping.",
    "hint": (
        "The query is rendered as raw HTML. Anything you put in ?q= ends up "
        "in the page body verbatim. Try the canonical <script>alert(1)</script>."
    ),
    "sink": "Markup() / |safe",
    "source_path": str(Path(__file__).resolve()),
    "vulnerable": True,
}


@bp.route("/", methods=["GET"])
def lab():
    q = request.args.get("q", "")
    # INTENTIONAL BUG: Markup() marks user input as already-safe HTML, so
    # Jinja renders it without escaping.
    rendered_query = Markup(q) if q else None
    return render_template("lab_reflected.html", meta=META, q=q, rendered_query=rendered_query)
