"""XSS lab: csp-bypass — INTENTIONALLY VULNERABLE.

A reflected XSS sink protected by what looks like a serious CSP:
`script-src 'self'`. Inline scripts are blocked, eval is blocked, external
script hosts are blocked.

The same origin happens to host a JSONP-style callback endpoint at
`/csp-bypass/jsonp?cb=<name>` that emits `<name>(<json>)` — a classic CSP
escape hatch. `<script src="/csp-bypass/jsonp?cb=alert(1)//"></script>`
passes the `'self'` allowlist and runs attacker JS.

The lab is here to demonstrate that a strict-*looking* CSP is not enough
if same-origin contains reflective/callback endpoints.
"""
from __future__ import annotations

import json
from pathlib import Path

from flask import Blueprint, Response, render_template, request
from markupsafe import Markup

bp = Blueprint("csp_bypass", __name__, url_prefix="/csp-bypass")

META = {
    "slug": "csp-bypass",
    "title": "Reflected XSS behind a CSP that has a JSONP endpoint on-origin",
    "summary": "CSP looks restrictive (script-src 'self') but same-origin /jsonp is a callback bypass.",
    "hint": (
        "Inline <script> is blocked by CSP. But this same origin exposes "
        "/csp-bypass/jsonp?cb=<name> which reflects <name> into executable JS. "
        "Try a payload that loads <script src=/csp-bypass/jsonp?cb=alert(1)//>."
    ),
    "sink": "Markup() / |safe",
    "source_path": str(Path(__file__).resolve()),
    "vulnerable": True,
}

CSP = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; base-uri 'none'"


@bp.route("/", methods=["GET"])
def lab():
    q = request.args.get("q", "")
    rendered_query = Markup(q) if q else None
    resp = Response(
        render_template("lab_csp.html", meta=META, q=q, rendered_query=rendered_query, csp=CSP),
        mimetype="text/html",
    )
    resp.headers["Content-Security-Policy"] = CSP
    return resp


@bp.route("/jsonp", methods=["GET"])
def jsonp():
    # INTENTIONAL: cb is reflected into the response body, content-type is JS.
    # No allowlist on the callback name. This is the bypass primitive.
    cb = request.args.get("cb", "callback")
    payload = {"status": "ok", "user": "anon"}
    body = f"{cb}({json.dumps(payload)});\n"
    return Response(body, mimetype="application/javascript")
