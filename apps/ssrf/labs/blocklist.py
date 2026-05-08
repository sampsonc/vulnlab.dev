"""SSRF lab: blocklist — INTENTIONALLY VULNERABLE.

A naive substring deny-list. Bypassable a hundred ways: decimal IP, hex IP,
IPv4-mapped IPv6, shorthand notation, redirect chains, DNS aliases.
"""
from __future__ import annotations

from pathlib import Path
from urllib.request import urlopen

from flask import Blueprint, render_template, request

bp = Blueprint("blocklist", __name__, url_prefix="/blocklist")

META = {
    "slug": "blocklist",
    "title": "SSRF behind a substring blocklist",
    "summary": "Rejects URLs containing 'localhost' or '127.0.0.1', then fetches.",
    "hint": (
        "Same internal target as /basic. The validator only checks for the "
        "literal strings 'localhost' and '127.0.0.1'. Find another way to "
        "spell that address."
    ),
    "sink": "urllib.request.urlopen",
    "source_path": str(Path(__file__).resolve()),
    "vulnerable": True,
}

BANNED = ("localhost", "127.0.0.1")


@bp.route("/", methods=["GET"])
def lab():
    url = request.args.get("url", "").strip()
    body = error = None
    if url:
        if any(needle in url.lower() for needle in BANNED):
            error = f"URL rejected: contains banned substring (one of {BANNED})."
        else:
            try:
                with urlopen(url, timeout=5) as r:
                    body = r.read(4096).decode("utf-8", "replace")
            except Exception as e:
                error = f"{type(e).__name__}: {e}"
    return render_template("lab.html", meta=META, url=url, body=body, error=error)
