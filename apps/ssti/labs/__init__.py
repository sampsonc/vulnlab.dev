"""SSTI lab blueprints.

Each module exposes:
  - bp: Flask Blueprint
  - META: dict with title, slug, summary, hint, source_path, sink, vulnerable
"""
from . import basic, filtered, format_string, sandboxed, second_order

LABS = [
    basic.META,
    format_string.META,
    filtered.META,
    sandboxed.META,
    second_order.META,
]

BLUEPRINTS = [
    basic.bp,
    format_string.bp,
    filtered.bp,
    sandboxed.bp,
    second_order.bp,
]
