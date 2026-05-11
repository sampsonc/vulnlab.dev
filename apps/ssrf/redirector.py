"""Open redirector helper, mounted on ssrf.vulnlab.dev.

Not a lab itself — it exists so the redirect lab is fully self-contained.
A learner doesn't need to spin up their own attacker host; they can chain
requests through this endpoint instead.
"""
from __future__ import annotations

from flask import Blueprint, redirect, request

bp = Blueprint("redirector", __name__, url_prefix="/r")


@bp.route("/", methods=["GET"])
def go():
    target = request.args.get("to", "").strip()
    if not target:
        return (
            "Usage: /r/?to=<absolute-url>. Returns 302 Location: <url>.",
            200,
            {"Content-Type": "text/plain"},
        )
    return redirect(target, code=302)
