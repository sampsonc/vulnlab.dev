"""XSS lab: dom — INTENTIONALLY VULNERABLE.

The server emits an entirely static HTML page; the bug lives in client
JavaScript that takes `location.hash` and slams it into innerHTML. No
server reflection — a DAST that only watches HTTP responses will miss
this. The taint flows source → sink purely in the browser.
"""
from __future__ import annotations

from pathlib import Path

from flask import Blueprint, render_template

bp = Blueprint("dom_lab", __name__, url_prefix="/dom")

META = {
    "slug": "dom",
    "title": "DOM-based XSS (location.hash → innerHTML)",
    "summary": "Pure client-side sink. No reflection through the server.",
    "hint": (
        "The page reads location.hash on load and writes it into the DOM via "
        "innerHTML. Try /dom/#<img src=x onerror=alert(1)>. Because the "
        "fragment is never sent to the server, server-side DAST scanners that "
        "only inspect responses will miss this entirely."
    ),
    "sink": "element.innerHTML",
    "source_path": str(Path(__file__).resolve()),
    "vulnerable": True,
}


@bp.route("/", methods=["GET"])
def lab():
    return render_template("lab_dom.html", meta=META)
