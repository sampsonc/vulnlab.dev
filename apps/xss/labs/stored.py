"""XSS lab: stored — INTENTIONALLY VULNERABLE.

A toy guestbook: POST a comment, it gets stored in memory and rendered
unescaped to everyone who visits the page afterward. Persistence is
process-local (a deque) so a service restart wipes it; that's fine for
a lab.
"""
from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
from pathlib import Path

from flask import Blueprint, redirect, render_template, request, url_for
from markupsafe import Markup

bp = Blueprint("stored", __name__, url_prefix="/stored")

META = {
    "slug": "stored",
    "title": "Stored XSS (guestbook)",
    "summary": "Comments are persisted and re-rendered as raw HTML for every visitor.",
    "hint": (
        "Submit a comment. It is stored in memory and rendered unescaped on "
        "every subsequent page load. Anyone who visits /stored/ after you "
        "executes whatever you put in."
    ),
    "sink": "Markup() / |safe",
    "source_path": str(Path(__file__).resolve()),
    "vulnerable": True,
}

_COMMENTS: deque = deque(maxlen=20)


@bp.route("/", methods=["GET", "POST"])
def lab():
    if request.method == "POST":
        author = (request.form.get("author") or "anon").strip()[:40]
        body = (request.form.get("body") or "").strip()[:2000]
        if body:
            _COMMENTS.appendleft({
                "author": author,
                "body_html": Markup(body),  # INTENTIONAL: stored as trusted HTML
                "ts": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ"),
            })
        return redirect(url_for("stored.lab"))
    return render_template("lab_stored.html", meta=META, comments=list(_COMMENTS))


@bp.route("/clear", methods=["POST"])
def clear():
    _COMMENTS.clear()
    return redirect(url_for("stored.lab"))
