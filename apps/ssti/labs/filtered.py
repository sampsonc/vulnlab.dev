"""SSTI lab: filtered — INTENTIONALLY VULNERABLE.

Same render_template_string sink as `basic`, but with a substring
blocklist that strips a handful of "scary" tokens before rendering. The
filter is the kind of fix someone applies in production after a Bug Bash
finding without realizing how many ways there are around it.

Bypass paths the blocklist misses:
- attribute access via |attr filter: foo|attr("__class__")
- attribute access via dict-style: foo["__cl"+"ass__"]
- string concat / hex escape in the attribute name
- request.application or self introspection
"""
from __future__ import annotations

from pathlib import Path

from flask import Blueprint, render_template, render_template_string, request

bp = Blueprint("ssti_filtered", __name__, url_prefix="/filtered")

# INTENTIONAL: ineffective deny-list. Real bypass surface is enormous.
BLOCKED = ("__class__", "__mro__", "__subclasses__", "__globals__",
           "subprocess", "os.system", "popen", "import",
           "request.application")

META = {
    "slug": "filtered",
    "title": "Jinja2 SSTI behind a substring blocklist",
    "summary": "render_template_string with a substring deny-list. Trivially bypassable.",
    "hint": (
        f"The blocklist strips these tokens before rendering: {BLOCKED}. "
        "Jinja2 lets you reach the same attributes without those literal "
        "strings via the |attr filter: "
        "{{ ''|attr('__cl' ~ 'ass__')|attr('__mr' ~ 'o__') }}, or via "
        "dict-style indexing on the string concat. The lab flag is at "
        "{{ config['VULNLAB_SSTI_FILTERED'] }}."
    ),
    "sink": "flask.render_template_string (after substring blocklist)",
    "source_path": str(Path(__file__).resolve()),
    "vulnerable": True,
}


def _filter(s: str) -> str:
    out = s
    for token in BLOCKED:
        out = out.replace(token, "")
    return out


@bp.route("/", methods=["GET"])
def lab():
    raw = request.args.get("greeting", "")
    filtered = _filter(raw) if raw else ""
    rendered = error = None
    if filtered:
        try:
            rendered = render_template_string(filtered)
        except Exception as e:
            error = f"{type(e).__name__}: {e}"
    return render_template(
        "lab_filtered.html",
        meta=META,
        raw=raw,
        filtered=filtered,
        rendered=rendered,
        error=error,
        blocked=BLOCKED,
    )
