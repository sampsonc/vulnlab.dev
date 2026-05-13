"""XSS lab: mxss — INTENTIONALLY VULNERABLE.

A "live preview" comment box. The server sanitizes input by stripping
`<script>` tags and `on*` attributes with a regex (the classic naive
defense) and renders the result inside a hidden `<template>`. Client JS
then copies `template.innerHTML` into a visible preview element — and the
roundtrip through innerHTML re-parses the HTML, giving the attacker a
second bite at the apple via tags whose contents change parsing modes
(`<noscript>`, `<style>`, `<svg>`, …).

This is recognizably mutation XSS: the server-emitted markup is harmless
when first parsed, but mutates into something executable when reparsed by
the client.
"""
from __future__ import annotations

import re
from pathlib import Path

from flask import Blueprint, render_template, request
from markupsafe import Markup

bp = Blueprint("mxss", __name__, url_prefix="/mxss")

META = {
    "slug": "mxss",
    "title": "Mutation XSS via innerHTML round-trip",
    "summary": "Regex sanitizer + client-side innerHTML reparse = parser-mode escape.",
    "hint": (
        "The server strips <script> and on* attributes with regex. The "
        "client then does preview.innerHTML = template.innerHTML, which "
        "reparses the markup. Tags that change tokenization mode "
        "(<noscript>, <style>, <svg>) can carry a payload past the sanitizer "
        "and reactivate it after the reparse."
    ),
    "sink": "regex sanitizer + element.innerHTML round-trip",
    "source_path": str(Path(__file__).resolve()),
    "vulnerable": True,
}

# INTENTIONAL: regex-based "sanitizer". It strips <script>…</script> blocks
# and any on*= attribute. It looks reasonable. It is not.
SCRIPT_RE = re.compile(r"<\s*script\b[^>]*>.*?<\s*/\s*script\s*>", re.IGNORECASE | re.DOTALL)
ON_ATTR_RE = re.compile(r"\s+on[a-z]+\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)", re.IGNORECASE)


def sanitize(raw: str) -> str:
    out = SCRIPT_RE.sub("", raw)
    out = ON_ATTR_RE.sub("", out)
    return out


@bp.route("/", methods=["GET"])
def lab():
    raw = request.args.get("comment", "")
    sanitized = sanitize(raw) if raw else ""
    return render_template(
        "lab_mxss.html",
        meta=META,
        raw=raw,
        sanitized_html=Markup(sanitized),
        sanitized_text=sanitized,
    )
