"""SSRF lab: scheme — INTENTIONALLY VULNERABLE.

The validator only checks for "blocked words" in the URL, but doesn't restrict
the scheme. urllib supports file://, ftp://, and (with some installs) more,
making local file disclosure trivially possible.
"""
from __future__ import annotations

from pathlib import Path
from urllib.request import urlopen

from flask import Blueprint, render_template, request

bp = Blueprint("scheme", __name__, url_prefix="/scheme")

META = {
    "slug": "scheme",
    "title": "SSRF with unrestricted URL scheme",
    "summary": "Any scheme urllib supports works — including file:// for local file read.",
    "hint": (
        "There's a flag at /etc/vulnlab/flag.txt on the lab host. The "
        "validator filters 'localhost' and '127.0.0.1' but says nothing "
        "about the URL scheme."
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
