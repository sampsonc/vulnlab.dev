"""SQLi lab blueprints.

Each module exposes:
  - bp: Flask Blueprint
  - META: dict with title, slug, summary, hint, source_path, sink, vulnerable
"""
from . import blind_bool, blind_time, error, second_order, union

LABS = [
    union.META,
    error.META,
    blind_bool.META,
    blind_time.META,
    second_order.META,
]

BLUEPRINTS = [
    union.bp,
    error.bp,
    blind_bool.bp,
    blind_time.bp,
    second_order.bp,
]
