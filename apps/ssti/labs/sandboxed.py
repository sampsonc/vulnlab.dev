"""SSTI lab: sandboxed — INTENTIONALLY VULNERABLE.

Uses jinja2.sandbox.SandboxedEnvironment, which blocks the usual SSTI
escalation primitives (no __class__/__mro__/__subclasses__ attribute
access). A scanner that only knows the textbook Jinja2 RCE chain will
declare this safe and move on.

The bug isn't in the sandbox — the sandbox is doing its job. The bug is
that the developer exposed a custom global `dump_diagnostics` that
itself returns sensitive runtime state. The sandbox can't reason about
the side effects of registered globals.
"""
from __future__ import annotations

from pathlib import Path

from flask import Blueprint, current_app, render_template, request
from jinja2.sandbox import SandboxedEnvironment

bp = Blueprint("ssti_sandboxed", __name__, url_prefix="/sandboxed")

META = {
    "slug": "sandboxed",
    "title": "Jinja2 SSTI inside a SandboxedEnvironment",
    "summary": "Sandbox blocks the textbook RCE chain. A registered global ruins it.",
    "hint": (
        "The textbook SSTI chain ({{''.__class__.__mro__...}}) is blocked. "
        "But the app registered a global called `dump_diagnostics` that "
        "leaks the full app config. Call {{ dump_diagnostics() }} and read "
        "the VULNLAB_SSTI_SANDBOXED entry. The lesson: a sandbox can't "
        "reason about the side effects of helpers you expose to it."
    ),
    "sink": "SandboxedEnvironment + over-privileged registered global",
    "source_path": str(Path(__file__).resolve()),
    "vulnerable": True,
}


def _make_env() -> SandboxedEnvironment:
    env = SandboxedEnvironment(autoescape=False)

    def dump_diagnostics():
        # INTENTIONAL: returns the live app config so the developer can
        # "debug rendering issues from a template." The sandbox treats
        # this as a trusted global and doesn't introspect what it returns.
        return {k: str(v) for k, v in current_app.config.items()}

    env.globals["dump_diagnostics"] = dump_diagnostics
    return env


@bp.route("/", methods=["GET"])
def lab():
    greeting = request.args.get("greeting", "")
    rendered = error = None
    if greeting:
        try:
            tmpl = _make_env().from_string(greeting)
            rendered = tmpl.render()
        except Exception as e:
            error = f"{type(e).__name__}: {e}"
    return render_template("lab_sandboxed.html", meta=META, greeting=greeting, rendered=rendered, error=error)
