# Parry (C) by Lemonade Stand. Written by Andy Kurapati and Shreyan Mitra
"""
Parry Security Scanner - Privacy-first AI-powered security scanner

This module serves as the main entry point for the Parry Security Scanner package.
It exports the core classes that are used throughout the application for scanning,
AI-powered fix generation, and patch management.
"""

# Version string following semantic versioning (MAJOR.MINOR.PATCH)
__version__ = "0.1.0"
# Author information for the package
__author__ = "Parry Security"

# Import the Scanner class which handles security vulnerability detection
from parry.scanner import Scanner
# Import the LLMClient class which interfaces with Large Language Models for AI-powered fixes
from parry.llm import LLMClient
# Import the PatchGenerator class which creates code patches to remediate vulnerabilities
from parry.patch import PatchGenerator

# Define the public API that is exposed when using "from parry import *"
__all__ = ["Scanner", "LLMClient", "PatchGenerator"]


