"""SSRF lab: metadata-gcp — INTENTIONALLY VULNERABLE.

A "fetch a thumbnail" feature, deployed on (mock) GCP Compute Engine. The
app uses a Google-aware HTTP wrapper that adds 'Metadata-Flavor: Google' to
every outbound request — which is exactly what's needed to read GCP's
instance metadata service. Tools that only know AWS IMDS will miss this.
"""
from __future__ import annotations

from pathlib import Path

import requests
from flask import Blueprint, render_template, request

bp = Blueprint("metadata_gcp", __name__, url_prefix="/metadata-gcp")

META = {
    "slug": "metadata-gcp",
    "title": "SSRF in cloud-hosted (mock GCP) app",
    "summary": "GCP-style metadata service. The app injects Metadata-Flavor: Google.",
    "hint": (
        "GCE metadata is at http://169.254.169.254/computeMetadata/v1/. The "
        "service-accounts/default/token endpoint returns a fake OAuth2 token. "
        "metadata.google.internal also resolves there in real GCP."
    ),
    "sink": "requests.get",
    "source_path": str(Path(__file__).resolve()),
    "vulnerable": True,
}

INJECTED_HEADERS = {"Metadata-Flavor": "Google"}


@bp.route("/", methods=["GET"])
def lab():
    url = request.args.get("url", "").strip()
    body = error = None
    if url:
        try:
            r = requests.get(url, timeout=5, allow_redirects=True, headers=INJECTED_HEADERS)
            body = r.text[:4096]
        except Exception as e:
            error = f"{type(e).__name__}: {e}"
    return render_template("lab.html", meta=META, url=url, body=body, error=error)
