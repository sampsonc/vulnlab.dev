"""SSRF lab blueprints.

Each module exposes:
  - bp: Flask Blueprint
  - META: dict with title, slug, description, hint, source_path, sink, vulnerable
"""
from . import (
    allowlist,
    basic,
    blind,
    blocklist,
    gopher,
    metadata,
    metadata_azure,
    metadata_gcp,
    parser,
    redirect,
    scheme,
    webhook,
)

LABS = [
    basic.META,
    blocklist.META,
    allowlist.META,
    parser.META,
    redirect.META,
    scheme.META,
    blind.META,
    webhook.META,
    metadata.META,
    metadata_gcp.META,
    metadata_azure.META,
    gopher.META,
]

BLUEPRINTS = [
    basic.bp,
    blocklist.bp,
    allowlist.bp,
    parser.bp,
    redirect.bp,
    scheme.bp,
    blind.bp,
    webhook.bp,
    metadata.bp,
    metadata_gcp.bp,
    metadata_azure.bp,
    gopher.bp,
]
