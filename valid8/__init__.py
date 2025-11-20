"""
Valid8 Security Scanner - Privacy-first AI-powered security scanner
"""

__version__ = "1.0.0"
__author__ = "Valid8 Security"

# Robust imports that work in different contexts
try:
    from .scanner import Scanner
    from .llm import LLMClient  
    from .patch import PatchGenerator
    __all__ = ["Scanner", "LLMClient", "PatchGenerator"]
except ImportError:
    # Fallback for when relative imports fail
    try:
        from valid8.scanner import Scanner
        from valid8.llm import LLMClient
        from valid8.patch import PatchGenerator
        __all__ = ["Scanner", "LLMClient", "PatchGenerator"]
    except ImportError:
        # Minimal fallback
        __all__ = []
        Scanner = None
        LLMClient = None
        PatchGenerator = None
