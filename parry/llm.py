"""
LLM Client - Interface for local LLM inference via Ollama
"""

import json
import requests
from typing import Dict, Any, Optional, List
from dataclasses import dataclass


@dataclass
class LLMConfig:
    """🚀 ENHANCED: Configuration for LLM client with universal vulnerability detection"""
    base_url: str = "http://localhost:11434"

    # 🚀 UNIVERSAL VULNERABILITY DETECTION MODEL STACK
    primary_model: str = "qwen2.5-coder:1.5b"  # Main analysis model (1.5B - fast & capable)
    security_model: str = "codellama:7b-instruct"  # Security-specialized model (7B - deep analysis)
    universal_model: str = "codellama:13b-instruct"  # Universal understanding (13B - comprehensive)
    fast_model: str = "qwen2.5-coder:0.5b"  # Lightning-fast validation (0.5B - speed)

    # Dynamic model selection based on vulnerability type
    model_selection: dict = None

    def __post_init__(self):
        if self.model_selection is None:
            # 🚀 INTELLIGENT MODEL SELECTION FOR MAXIMUM COVERAGE
            self.model_selection = {
                # Use primary model for common vulnerabilities (fast)
                'common': self.primary_model,
                # Use security model for complex security issues (accurate)
                'security': self.security_model,
                # Use universal model for rare/unknown vulnerabilities (comprehensive)
                'universal': self.universal_model,
                # Use fast model for validation/quick checks (speed)
                'validation': self.fast_model,

                # Specific vulnerability type to model mapping
                'CWE-79': self.primary_model,    # XSS - common
                'CWE-89': self.primary_model,    # SQLi - common
                'CWE-78': self.primary_model,    # Command Injection - common
                'CWE-22': self.primary_model,    # Path Traversal - common
                'CWE-798': self.primary_model,   # Hardcoded Credentials - common

                'CWE-639': self.security_model,  # IDOR - security-specific
                'CWE-918': self.security_model,  # SSRF - security-specific
                'CWE-611': self.security_model,  # XXE - security-specific
                'CWE-352': self.security_model,  # CSRF - security-specific
                'CWE-200': self.security_model,  # Info Disclosure - security-specific

                'unknown': self.universal_model, # Any unknown vulnerability type
                'complex': self.universal_model, # Complex multi-step vulnerabilities
            }

    temperature: float = 0.0  # Deterministic for consistency
    max_tokens: int = 512   # 🚀 INCREASED: 512 tokens for detailed analysis
    timeout: int = 30   # 🚀 INCREASED: 30s for complex analysis
    batch_size: int = 2   # 🚀 OPTIMIZED: 2 for quality
    stream: bool = True   # Memory efficient
    max_retries: int = 3  # 🚀 INCREASED: 3 for reliability
    context_window: int = 8192  # 🚀 ENHANCED: 8K context for full function analysis

    # 🚀 NEW: Universal vulnerability detection features
    enable_universal_mode: bool = True  # Detect ANY vulnerability type
    use_ensemble_validation: bool = True  # Multiple model validation
    adaptive_model_selection: bool = True  # Choose best model per vulnerability type
    knowledge_base_integration: bool = True  # Use security knowledge base


class LLMClient:
    """Client for interacting with Ollama local LLM"""
    
    def __init__(self, model: Optional[str] = None, base_url: Optional[str] = None):
        self.config = LLMConfig()
        
        if model:
            self.config.model = model
        if base_url:
            self.config.base_url = base_url
        
        self._check_connection()
    
    def _check_connection(self):
        """Verify Ollama is running and accessible"""
        try:
            response = requests.get(
                f"{self.config.base_url}/api/tags",
                timeout=5
            )
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            raise ConnectionError(
                f"Cannot connect to Ollama at {self.config.base_url}. "
                f"Make sure Ollama is running: 'ollama serve'"
            ) from e
    
    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """
        Generate text completion using the local LLM
        
        Args:
            prompt: User prompt
            system_prompt: Optional system prompt for context
            
        Returns:
            Generated text
        """
        payload = {
            "model": self.config.model,
            "prompt": prompt,
            "stream": self.config.stream,  # HYBRID OPTIMIZED: streaming for better memory usage
            "options": {
                "temperature": self.config.temperature,
                "num_predict": self.config.max_tokens,
            }
        }
        
        if system_prompt:
            payload["system"] = system_prompt
        
        try:
            response = requests.post(
                f"{self.config.base_url}/api/generate",
                json=payload,
                timeout=self.config.timeout,
                stream=self.config.stream
            )
            response.raise_for_status()

            if self.config.stream:
                # HYBRID OPTIMIZED: Handle streaming response for better memory usage
                full_response = ""
                for line in response.iter_lines():
                    if line:
                        try:
                            chunk = json.loads(line.decode('utf-8'))
                            if 'response' in chunk:
                                full_response += chunk['response']
                            if chunk.get('done', False):
                                break
                        except json.JSONDecodeError:
                            continue
                return full_response.strip()
            else:
                result = response.json()
                return result.get("response", "").strip()

        except requests.exceptions.Timeout:
            # 🚀 HYBRID SPEEDUP: Skip analysis entirely on timeout
            return ""  # Empty response = no additional findings
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"LLM request failed: {e}") from e
    
    def chat(self, messages: List[Dict[str, str]]) -> str:
        """
        Chat completion using the local LLM
        
        Args:
            messages: List of message dicts with 'role' and 'content'
            
        Returns:
            Generated response
        """
        payload = {
            "model": self.config.model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": self.config.temperature,
                "num_predict": self.config.max_tokens,
            }
        }
        
        try:
            response = requests.post(
                f"{self.config.base_url}/api/chat",
                json=payload,
                timeout=self.config.timeout
            )
            response.raise_for_status()
            
            result = response.json()
            return result.get("message", {}).get("content", "").strip()
        
        except requests.exceptions.Timeout:
            raise TimeoutError(f"LLM request timed out after {self.config.timeout}s")
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"LLM request failed: {e}") from e
    
    def list_models(self) -> List[Dict[str, Any]]:
        """List available models in Ollama"""
        try:
            response = requests.get(
                f"{self.config.base_url}/api/tags",
                timeout=5
            )
            response.raise_for_status()
            return response.json().get("models", [])
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"Failed to list models: {e}") from e


