"""SSTI lab: second-order — INTENTIONALLY VULNERABLE.

A "draft email" feature with two endpoints:

  1. POST /second-order/save  — stores a template snippet under a key the
                                user picks. Snippet is stored verbatim in
                                an in-process dict (no rendering yet).
                                A static analyzer looking at the storage
                                path sees no template sink — just a write.

  2. GET  /second-order/preview?id=<key> — fetches the snippet and renders
                                            it via render_template_string.

The save sink and the render sink are in different files, and the data
flows through process state in between. Cross-sink taint trackers that
don't model storage-then-render miss this.
"""
from __future__ import annotations

from pathlib import Path

from flask import Blueprint, redirect, render_template, render_template_string, request, url_for

bp = Blueprint("ssti_second_order", __name__, url_prefix="/second-order")

# Process-local; restart wipes state. Fine for a lab.
_DRAFTS: dict[str, str] = {}

META = {
    "slug": "second-order",
    "title": "Second-order SSTI (stored draft, rendered later)",
    "summary": "Save endpoint stores raw template text; preview endpoint renders it.",
    "hint": (
        "Save a draft whose body is an SSTI payload, e.g. "
        "{{ config['VULNLAB_SSTI_SECOND_ORDER'] }}, then GET "
        "/second-order/preview?id=<the key you used>. Storage and render "
        "live in different endpoints; a per-sink scanner that only inspects "
        "render_template_string callers will miss the cross-endpoint flow."
    ),
    "sink": "stored snippet -> render_template_string in a later request",
    "source_path": str(Path(__file__).resolve()),
    "vulnerable": True,
}


@bp.route("/", methods=["GET"])
def lab():
    return render_template(
        "lab_second_order.html",
        meta=META,
        drafts=sorted(_DRAFTS.keys()),
        rendered=None,
        active_key=None,
    )


@bp.route("/save", methods=["POST"])
def save():
    key = (request.form.get("key") or "").strip()[:64]
    body = (request.form.get("body") or "")[:4096]
    if key and body:
        _DRAFTS[key] = body
    return redirect(url_for("ssti_second_order.lab"))


@bp.route("/preview", methods=["GET"])
def preview():
    key = request.args.get("id", "")
    body = _DRAFTS.get(key)
    rendered = error = None
    if body is not None:
        try:
            # INTENTIONAL: the stored text — which came from a previous,
            # apparently-safe POST — is now rendered as a Jinja template.
            rendered = render_template_string(body)
        except Exception as e:
            error = f"{type(e).__name__}: {e}"
    return render_template(
        "lab_second_order.html",
        meta=META,
        drafts=sorted(_DRAFTS.keys()),
        rendered=rendered,
        active_key=key,
        error=error,
        body=body,
    )
