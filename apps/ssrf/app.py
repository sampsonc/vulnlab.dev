"""ssrf.vulnlab.dev — entrypoint.

Mounts each lab as a Flask blueprint, exposes /, /source/<slug> (Pygments),
and a tiny "internal-only" endpoint at /internal that the labs are meant to
reach (and which the public, in theory, is not).
"""
from __future__ import annotations

from pathlib import Path

from flask import Flask, abort, render_template
from pygments import highlight
from pygments.formatters import HtmlFormatter
from pygments.lexers import PythonLexer

from .labs import BLUEPRINTS, LABS

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = Path(__file__).resolve().parent


def create_app() -> Flask:
    app = Flask(__name__)

    for bp in BLUEPRINTS:
        app.register_blueprint(bp)

    @app.after_request
    def add_banner(resp):
        resp.headers["X-Vulnlab"] = "intentionally-vulnerable"
        return resp

    @app.get("/")
    def index():
        return render_template("index.html", labs=LABS)

    @app.get("/source/<slug>")
    def source(slug: str):
        lab = next((l for l in LABS if l["slug"] == slug), None)
        if lab is None:
            abort(404)
        path = Path(lab["source_path"])
        if not path.is_file() or SRC_DIR not in path.parents:
            abort(404)
        code = path.read_text()
        formatter = HtmlFormatter(style="github-dark", linenos="table", cssclass="src")
        css = formatter.get_style_defs(".src")
        html = highlight(code, PythonLexer(), formatter)
        return render_template(
            "source.html",
            lab=lab,
            code_html=html,
            css=css,
            filename=path.name,
        )

    @app.get("/robots.txt")
    def robots():
        return (
            "User-agent: *\nAllow: /\nSitemap: https://ssrf.vulnlab.dev/sitemap.xml\n",
            200,
            {"Content-Type": "text/plain"},
        )

    @app.get("/.well-known/security.txt")
    def security_txt():
        body = (
            "Contact: mailto:carl.sampson@gmail.com\n"
            "Expires: 2027-12-31T23:59:59Z\n"
            "Preferred-Languages: en\n"
            "Canonical: https://ssrf.vulnlab.dev/.well-known/security.txt\n"
            "Policy: https://vulnlab.dev/\n"
            "# Intentionally vulnerable. No need to report.\n"
        )
        return body, 200, {"Content-Type": "text/plain"}

    return app


app = create_app()
