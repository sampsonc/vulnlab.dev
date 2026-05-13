"""SSTI lab: basic — INTENTIONALLY VULNERABLE.

Textbook Jinja2 SSTI: a "greeting" feature renders user input as a Flask
template via render_template_string. Any expression the user submits is
evaluated by the Jinja2 environment, which in Flask has access to the
running app's `config`, `request`, etc., and which can be walked from
any string object to subprocess via __class__.__mro__[1].__subclasses__().

Marker for the lab being exploited: the Flask app config exposes a
per-lab flag string at config['VULNLAB_SSTI_BASIC']. The canonical
extraction is {{ config['VULNLAB_SSTI_BASIC'] }}.
"""
from __future__ import annotations

from pathlib import Path

from flask import Blueprint, render_template, render_template_string, request

bp = Blueprint("ssti_basic", __name__, url_prefix="/basic")

META = {
    "slug": "basic",
    "title": "Jinja2 SSTI (render_template_string)",
    "summary": "User input rendered as a Flask template. Full Jinja2 evaluation.",
    "hint": (
        "render_template_string runs your input through Flask's full Jinja2 "
        "environment. Try {{ 7*7 }} to confirm template evaluation, then "
        "{{ config['VULNLAB_SSTI_BASIC'] }} to read the lab flag, then walk "
        "''.__class__.__mro__[1].__subclasses__() for RCE."
    ),
    "sink": "flask.render_template_string",
    "source_path": str(Path(__file__).resolve()),
    "vulnerable": True,
}


@bp.route("/", methods=["GET"])
def lab():
    greeting = request.args.get("greeting", "")
    rendered = error = None
    if greeting:
        try:
            # INTENTIONAL: user input passed directly as a Jinja template.
            rendered = render_template_string(greeting)
        except Exception as e:
            error = f"{type(e).__name__}: {e}"
    return render_template("lab_basic.html", meta=META, greeting=greeting, rendered=rendered, error=error)
