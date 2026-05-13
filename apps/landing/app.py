"""vulnlab.dev landing page.

Serves the index of vulnerability classes hosted across *.vulnlab.dev.
"""
from __future__ import annotations

from flask import Flask, render_template

CLASSES = [
    {
        "slug": "ssrf",
        "name": "Server-Side Request Forgery",
        "host": "ssrf.vulnlab.dev",
        "status": "live",
        "labs": 12,
        "blurb": (
            "The server fetches a URL you control. Find ways past the validators "
            "and reach things you shouldn't."
        ),
    },
    {
        "slug": "xss",
        "name": "Cross-Site Scripting",
        "host": "xss.vulnlab.dev",
        "status": "live",
        "labs": 5,
        "blurb": (
            "Reflected, stored, DOM, CSP-bypass, and mutation XSS — the variants "
            "tools differ on. Each lab shows what the scanner should fire on."
        ),
    },
    {
        "slug": "sqli",
        "name": "SQL Injection",
        "host": "sqli.vulnlab.dev",
        "status": "live",
        "labs": 5,
        "blurb": (
            "In-band UNION, error-based, blind boolean, blind time-based, and "
            "second-order — sitting on a real MariaDB backend."
        ),
    },
]


def create_app() -> Flask:
    app = Flask(__name__)

    @app.get("/")
    def index():
        return render_template("index.html", classes=CLASSES)

    @app.get("/robots.txt")
    def robots():
        return (
            "User-agent: *\nAllow: /\nSitemap: https://vulnlab.dev/sitemap.xml\n",
            200,
            {"Content-Type": "text/plain"},
        )

    @app.get("/.well-known/security.txt")
    def security_txt():
        body = (
            "Contact: mailto:carl.sampson@gmail.com\n"
            "Expires: 2027-12-31T23:59:59Z\n"
            "Preferred-Languages: en\n"
            "Canonical: https://vulnlab.dev/.well-known/security.txt\n"
            "Policy: https://vulnlab.dev/\n"
            "# This site is INTENTIONALLY VULNERABLE. You do not need to report\n"
            "# vulnerabilities found on vulnlab.dev or any *.vulnlab.dev host.\n"
            "# Please do not abuse outbound connectivity or use these labs as a pivot.\n"
        )
        return body, 200, {"Content-Type": "text/plain"}

    return app


app = create_app()
