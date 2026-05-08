"""SSRF lab: metadata — INTENTIONALLY VULNERABLE.

A "fetch a banner image for your profile" feature, deployed on (mock) AWS EC2.
The mock IMDS lives at 169.254.169.254. Hit IMDSv1 endpoints to lift fake
IAM credentials.
"""
from __future__ import annotations

from pathlib import Path

import requests
from flask import Blueprint, render_template, request

bp = Blueprint("metadata", __name__, url_prefix="/metadata")

META = {
    "slug": "metadata",
    "title": "SSRF in cloud-hosted (mock AWS) app",
    "summary": "A profile-image fetcher running on a fake EC2. Reach the metadata service.",
    "hint": (
        "This box is pretending to be an EC2 instance. AWS IMDSv1 lives at "
        "http://169.254.169.254/latest/meta-data/. Try walking the tree."
    ),
    "sink": "requests.get",
    "source_path": str(Path(__file__).resolve()),
    "vulnerable": True,
}


@bp.route("/", methods=["GET"])
def lab():
    url = request.args.get("url", "").strip()
    body = error = None
    if url:
        try:
            r = requests.get(url, timeout=5, allow_redirects=True)
            body = r.text[:4096]
        except Exception as e:
            error = f"{type(e).__name__}: {e}"
    return render_template("lab.html", meta=META, url=url, body=body, error=error)
