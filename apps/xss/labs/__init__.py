"""XSS lab blueprints.

Each module exposes:
  - bp: Flask Blueprint
  - META: dict with title, slug, summary, hint, source_path, sink, vulnerable
"""
from . import csp_bypass, dom, mxss, reflected, stored

LABS = [
    reflected.META,
    stored.META,
    dom.META,
    csp_bypass.META,
    mxss.META,
]

BLUEPRINTS = [
    reflected.bp,
    stored.bp,
    dom.bp,
    csp_bypass.bp,
    mxss.bp,
]
