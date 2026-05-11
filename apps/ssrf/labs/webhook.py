"""SSRF lab: webhook — INTENTIONALLY VULNERABLE.

POST a JSON payload to a user-controlled webhook URL, then echo back the
HTTP status, response length, content-type, and any X-* headers from the
response. The body itself is never returned. A "semi-blind" SSRF: partial
metadata is enough to fingerprint internal services, and any flag leaked
through a custom header is exfiltrable.
"""
from __future__ import annotations

from pathlib import Path

import requests
from flask import Blueprint, render_template, request

bp = Blueprint("webhook", __name__, url_prefix="/webhook")

META = {
    "slug": "webhook",
    "title": "Semi-blind SSRF via a webhook poster",
    "summary": "POSTs your URL with a JSON body and echoes status, length, content-type, X-* headers.",
    "hint": (
        "The body is hidden but headers aren't. The internal service at "
        "http://127.0.0.1:8089/webhook-callback returns the flag in a "
        "response header."
    ),
    "sink": "requests.post",
    "source_path": str(Path(__file__).resolve()),
    "vulnerable": True,
}


@bp.route("/", methods=["GET", "POST"])
def lab():
    url = (request.values.get("url") or "").strip()
    payload = request.values.get("payload") or '{"event":"test"}'
    body = error = None
    if url:
        try:
            r = requests.post(
                url,
                data=payload.encode("utf-8"),
                headers={"Content-Type": "application/json", "User-Agent": "vulnlab-webhook/1.0"},
                timeout=5,
                allow_redirects=False,
            )
            x_headers = {k: v for k, v in r.headers.items() if k.lower().startswith("x-")}
            lines = [
                f"status: {r.status_code}",
                f"content-length: {len(r.content)}",
                f"content-type: {r.headers.get('Content-Type', '(none)')}",
                "x-headers:",
            ]
            if x_headers:
                lines.extend(f"  {k}: {v}" for k, v in x_headers.items())
            else:
                lines.append("  (none)")
            lines.append("\n(body intentionally hidden — this lab leaks only metadata)")
            body = "\n".join(lines)
        except Exception as e:
            error = f"{type(e).__name__}: {e}"
    return render_template("lab.html", meta=META, url=url, body=body, error=error)
