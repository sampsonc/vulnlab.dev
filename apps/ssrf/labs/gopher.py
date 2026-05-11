"""SSRF lab: gopher — INTENTIONALLY VULNERABLE.

Sink is pycurl, and libcurl speaks gopher://. That means a URL fetch can
deliver attacker-chosen bytes to any TCP service the lab process can
reach. There's a fake Redis-like listener on 127.0.0.1:6479 standing in
for "the internal service nobody thought was reachable over HTTP."
"""
from __future__ import annotations

import io
from pathlib import Path

import pycurl
from flask import Blueprint, render_template, request

bp = Blueprint("gopher", __name__, url_prefix="/gopher")

META = {
    "slug": "gopher",
    "title": "SSRF via gopher:// to a non-HTTP service",
    "summary": "Fetcher uses libcurl, which speaks gopher://. A TCP service is listening on 127.0.0.1:6479.",
    "hint": (
        "libcurl supports gopher://. The format is "
        "gopher://host:port/_<url-encoded-payload>. Try "
        "gopher://127.0.0.1:6479/_PING%0d%0a — whatever you send is forwarded "
        "verbatim, and the service replies with a flag."
    ),
    "sink": "pycurl",
    "source_path": str(Path(__file__).resolve()),
    "vulnerable": True,
}


@bp.route("/", methods=["GET"])
def lab():
    url = request.args.get("url", "").strip()
    body = error = None
    if url:
        buf = io.BytesIO()
        c = pycurl.Curl()
        try:
            c.setopt(c.URL, url)
            c.setopt(c.WRITEDATA, buf)
            c.setopt(c.TIMEOUT, 5)
            c.setopt(c.CONNECTTIMEOUT, 3)
            c.setopt(c.FOLLOWLOCATION, True)
            c.perform()
            body = buf.getvalue()[:4096].decode("utf-8", "replace")
        except pycurl.error as e:
            error = f"pycurl error: {e}"
        except Exception as e:
            error = f"{type(e).__name__}: {e}"
        finally:
            c.close()
    return render_template("lab.html", meta=META, url=url, body=body, error=error)
