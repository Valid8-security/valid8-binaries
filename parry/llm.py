"""
LLM Client - Interface for local LLM inference via Ollama
"""

import json
import requests
from typing import Dict, Any, Optional, List
from dataclasses import dataclass


@dataclass
class LLMConfig:
    """Configuration for LLM client"""
    base_url: str = "http://localhost:11434"
    model: str = "codellama:7b-instruct"
    temperature: float = 0.1
    max_tokens: int = 2048
    timeout: int = 120


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
            "stream": False,
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
                timeout=self.config.timeout
            )
            response.raise_for_status()
            
            result = response.json()
            return result.get("response", "").strip()
        
        except requests.exceptions.Timeout:
            raise TimeoutError(f"LLM request timed out after {self.config.timeout}s")
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


