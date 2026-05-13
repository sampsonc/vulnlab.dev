"""SSTI lab: format — INTENTIONALLY VULNERABLE.

Python str.format() is a separate injection class from Jinja2 SSTI. The
attacker controls the format *template*, and .format() walks attributes
via {0.x.y} syntax. From any object reference the attacker can reach
__class__, __init__, __globals__, etc. — same RCE primitive as Jinja2
SSTI but through a different sink that Jinja-aware scanners often miss.

The "personalize" feature here lets the user supply the format template
that gets called with a real User-shaped object as `user`.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from flask import Blueprint, render_template, request

bp = Blueprint("ssti_format", __name__, url_prefix="/format")


@dataclass
class _User:
    name: str
    email: str
    role: str
    # INTENTIONAL: a "private" attribute that becomes reachable via
    # {user.flag} once the attacker controls the format template.
    flag: str = "VULNLAB{ssti-str-format-attribute-walk}"


USER = _User(name="alice", email="alice@vulnlab.dev", role="admin")

META = {
    "slug": "format",
    "title": "str.format() SSTI (Python format string)",
    "summary": "User-controlled format template + str.format(user=obj). Attribute walks reach anywhere.",
    "hint": (
        "The format template is taken from ?template= and called as "
        "template.format(user=USER). Try ?template=Hello {user.name} to "
        "confirm, then {user.flag} to read the lab flag, then "
        "{user.__class__.__init__.__globals__} to reach a global namespace "
        "(escalates to RCE in real apps)."
    ),
    "sink": "str.format(user=...)",
    "source_path": str(Path(__file__).resolve()),
    "vulnerable": True,
}


@bp.route("/", methods=["GET"])
def lab():
    template = request.args.get("template", "")
    rendered = error = None
    if template:
        try:
            # INTENTIONAL: user controls the format string. With a User
            # object passed in, {user.x.y.z} walks attributes recursively.
            rendered = template.format(user=USER)
        except Exception as e:
            error = f"{type(e).__name__}: {e}"
    return render_template("lab_format.html", meta=META, template=template, rendered=rendered, error=error)
