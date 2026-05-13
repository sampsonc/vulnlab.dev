"""xss.vulnlab.dev — entrypoint.

Mounts each XSS lab as a Flask blueprint. Mirrors the ssrf app: exposes /,
/source/<slug>, /meta/<slug>, /meta/, and a couple of well-known endpoints.

No CSP, X-Frame-Options, or X-XSS-Protection headers — adding them would
mask the very behavior tools are supposed to detect. (The csp-bypass lab
sets its own CSP locally on its responses; that's the lab.)
"""
from __future__ import annotations

from pathlib import Path

from flask import Flask, abort, jsonify, render_template
from pygments import highlight
from pygments.formatters import HtmlFormatter
from pygments.lexers import PythonLexer

from .labs import BLUEPRINTS, LABS
from .labs.detect import DETECT_HINTS

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

    @app.get("/meta/")
    def meta_index():
        items = []
        for lab in LABS:
            slug = lab["slug"]
            items.append({
                "slug": slug,
                "title": lab["title"],
                "url": f"/{slug}/",
                "source_url": f"/source/{slug}",
                "meta_url": f"/meta/{slug}",
                "sink": lab["sink"],
                "has_detect_hint": slug in DETECT_HINTS,
            })
        return jsonify(labs=items)

    @app.get("/meta/<slug>")
    def meta(slug: str):
        lab = next((l for l in LABS if l["slug"] == slug), None)
        if lab is None:
            abort(404)
        hint = DETECT_HINTS.get(slug)
        payload = {
            "slug": slug,
            "title": lab["title"],
            "summary": lab["summary"],
            "sink": lab["sink"],
            "vulnerable": lab["vulnerable"],
            "lab_url": f"/{slug}/",
            "source_url": f"/source/{slug}",
            "detect": hint,
        }
        return jsonify(payload)

    @app.get("/robots.txt")
    def robots():
        return (
            "User-agent: *\nAllow: /\nSitemap: https://xss.vulnlab.dev/sitemap.xml\n",
            200,
            {"Content-Type": "text/plain"},
        )

    @app.get("/.well-known/security.txt")
    def security_txt():
        body = (
            "Contact: mailto:carl.sampson@gmail.com\n"
            "Expires: 2027-12-31T23:59:59Z\n"
            "Preferred-Languages: en\n"
            "Canonical: https://xss.vulnlab.dev/.well-known/security.txt\n"
            "Policy: https://vulnlab.dev/\n"
            "# Intentionally vulnerable. No need to report.\n"
        )
        return body, 200, {"Content-Type": "text/plain"}

    return app


app = create_app()
