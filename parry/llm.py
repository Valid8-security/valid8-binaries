# Parry (C) by Lemonade Stand. Written by Andy Kurapati and Shreyan Mitra
"""
LLM Client - Interface for local LLM inference via Ollama

This module provides a client for interacting with Ollama, which runs
local Large Language Models (LLMs) for AI-powered security analysis,
vulnerability detection, and code fix generation.
"""

# Import JSON for parsing response payloads
import json
# Import requests for HTTP communication with Ollama server
import requests
# Import typing utilities for type hints
from typing import Dict, Any, Optional, List
# Import dataclass decorator for configuration class
from dataclasses import dataclass


@dataclass
class LLMConfig:
    """
    Configuration for LLM client
    
    Stores settings for connecting to and using the Ollama LLM server,
    including URL, model name, and inference parameters.
    """
    # Base URL for Ollama server (default local instance)
    base_url: str = "http://localhost:11434"
    # Model to use for inference (TinyLlama for 5-7x speed improvement)
    model: str = "tinyllama:1.1b"  # Optimized: smaller model for speed (was codellama:7b-instruct)
    # Temperature for sampling (0.0 = deterministic for consistency)
    temperature: float = 0.0  # Optimized: deterministic for speed
    # Maximum tokens to generate (reduced for faster inference)
    max_tokens: int = 512  # Optimized: reduced for faster inference (was 1024)
    # Request timeout in seconds
    timeout: int = 30  # Optimized: faster timeout (was 60)


class LLMClient:
    """
    Client for interacting with Ollama local LLM
    
    This class provides methods to generate text completions and chat
    responses using locally-hosted LLMs through the Ollama API. It handles
    connection checking, request formatting, and error handling.
    """
    
    def __init__(self, model: Optional[str] = None, base_url: Optional[str] = None):
        """
        Initialize LLM client
        
        Args:
            model: Optional model name to override default
            base_url: Optional Ollama server URL to override default
        """
        # Create default configuration
        self.config = LLMConfig()
        
        # Override model if provided
        if model:
            self.config.model = model
        # Override base URL if provided
        if base_url:
            self.config.base_url = base_url
        
        # Verify Ollama server is accessible
        self._check_connection()
    
    def _check_connection(self):
        """
        Verify Ollama is running and accessible
        
        Makes a test request to the Ollama API to ensure the server
        is running and responding. Raises ConnectionError if unreachable.
        """
        try:
            # Send GET request to Ollama tags endpoint
            response = requests.get(
                f"{self.config.base_url}/api/tags",  # Endpoint listing available models
                timeout=5  # 5 second timeout for connection check
            )
            # Raise exception if request failed
            response.raise_for_status()
        # Catch any request exceptions
        except requests.exceptions.RequestException as e:
            # Raise connection error with helpful message
            raise ConnectionError(
                f"Cannot connect to Ollama at {self.config.base_url}. "  # Show URL
                f"Make sure Ollama is running: 'ollama serve'"  # Show fix command
            ) from e  # Chain original exception
    
    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """
        Generate text completion using the local LLM
        
        Sends a prompt to the Ollama API and returns the generated text.
        This is used for single-turn text generation tasks like vulnerability
        detection and code analysis.
        
        Args:
            prompt: User prompt describing the task or question
            system_prompt: Optional system prompt providing context and instructions
            
        Returns:
            Generated text completion from the LLM
        """
        # Build request payload for Ollama API
        payload = {
            "model": self.config.model,  # Model to use for generation
            "prompt": prompt,  # User's input prompt
            "stream": False,  # Don't stream response (get all at once)
            "options": {  # Generation parameters
                "temperature": self.config.temperature,  # Sampling temperature
                "num_predict": self.config.max_tokens,  # Max tokens to generate
            }
        }
        
        # Add system prompt if provided
        if system_prompt:
            # System prompt provides context and instructions
            payload["system"] = system_prompt
        
        try:
            # Send POST request to generate endpoint
            response = requests.post(
                f"{self.config.base_url}/api/generate",  # Generation endpoint
                json=payload,  # Send payload as JSON
                timeout=self.config.timeout  # Request timeout
            )
            # Raise exception if request failed
            response.raise_for_status()
            
            # Parse JSON response
            result = response.json()
            # Extract and return generated text (strip whitespace)
            return result.get("response", "").strip()
        
        # Catch timeout exceptions
        except requests.exceptions.Timeout:
            # Raise timeout error with duration
            raise TimeoutError(f"LLM request timed out after {self.config.timeout}s")
        # Catch all other request exceptions
        except requests.exceptions.RequestException as e:
            # Raise runtime error with details
            raise RuntimeError(f"LLM request failed: {e}") from e
    
    def chat(self, messages: List[Dict[str, str]]) -> str:
        """
        Chat completion using the local LLM
        
        Sends a conversation history to the Ollama API for multi-turn
        chat interactions. Used for interactive debugging and explanation.
        
        Args:
            messages: List of message dicts with 'role' (user/assistant/system)
                     and 'content' (message text)
            
        Returns:
            Generated response from the LLM
        """
        # Build request payload for chat endpoint
        payload = {
            "model": self.config.model,  # Model to use for chat
            "messages": messages,  # Conversation history
            "stream": False,  # Don't stream response (get all at once)
            "options": {  # Generation parameters
                "temperature": self.config.temperature,  # Sampling temperature
                "num_predict": self.config.max_tokens,  # Max tokens to generate
            }
        }
        
        try:
            # Send POST request to chat endpoint
            response = requests.post(
                f"{self.config.base_url}/api/chat",  # Chat endpoint
                json=payload,  # Send payload as JSON
                timeout=self.config.timeout  # Request timeout
            )
            # Raise exception if request failed
            response.raise_for_status()
            
            # Parse JSON response
            result = response.json()
            # Extract message content from response (strip whitespace)
            return result.get("message", {}).get("content", "").strip()
        
        # Catch timeout exceptions
        except requests.exceptions.Timeout:
            # Raise timeout error with duration
            raise TimeoutError(f"LLM request timed out after {self.config.timeout}s")
        # Catch all other request exceptions
        except requests.exceptions.RequestException as e:
            # Raise runtime error with details
            raise RuntimeError(f"LLM request failed: {e}") from e
    
    def list_models(self) -> List[Dict[str, Any]]:
        """
        List available models in Ollama
        
        Queries the Ollama API to retrieve a list of all locally installed
        models that can be used for inference.
        
        Returns:
            List of model dictionaries with name, size, and other metadata
        """
        try:
            # Send GET request to tags endpoint
            response = requests.get(
                f"{self.config.base_url}/api/tags",  # Endpoint listing models
                timeout=5  # Short timeout for listing
            )
            # Raise exception if request failed
            response.raise_for_status()
            # Parse response and extract models list
            return response.json().get("models", [])
        # Catch any request exceptions
        except requests.exceptions.RequestException as e:
            # Raise runtime error with details
            raise RuntimeError(f"Failed to list models: {e}") from e

