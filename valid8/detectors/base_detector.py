#!/usr/bin/env python3
from __future__ import annotations
"""
Copyright (c) 2025 Valid8 Security
All rights reserved.

This software is proprietary and confidential. Unauthorized copying,
modification, distribution, or use of this software, via any medium is
strictly prohibited without the express written permission of Valid8 Security.

"""

# -*- coding: utf-8 -*-
"""Shared detector helpers."""


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
