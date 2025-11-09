# -*- coding: utf-8 -*-
"""Shared detector helpers."""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Pattern


@lru_cache(maxsize=512)
def _compile(pattern: str) -> Pattern:
    return re.compile(pattern, re.IGNORECASE)


def get_regex(pattern: str) -> Pattern:
    """Return a compiled regex, caching results for reuse."""
    return _compile(pattern)


# Historical name used throughout the codebase.
regex_pool = get_regex
