"""SSRF lab blueprints.

Each module exposes:
  - bp: Flask Blueprint
  - META: dict with title, slug, description, hint, source_path, sink, vulnerable
"""
from . import basic, blocklist, allowlist, scheme, blind, metadata

LABS = [
    basic.META,
    blocklist.META,
    allowlist.META,
    scheme.META,
    blind.META,
    metadata.META,
]

BLUEPRINTS = [
    basic.bp,
    blocklist.bp,
    allowlist.bp,
    scheme.bp,
    blind.bp,
    metadata.bp,
]
