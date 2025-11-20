"""
Configuration Interface - Centralized configuration management
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from pathlib import Path


class IConfigurationProvider(ABC):
    """Interface for configuration providers"""

    @abstractmethod
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value"""
        pass

    @abstractmethod
    def set(self, key: str, value: Any) -> None:
        """Set configuration value"""
        pass

    @abstractmethod
    def has(self, key: str) -> bool:
        """Check if configuration key exists"""
        pass

    @abstractmethod
    def get_all(self, prefix: str = "") -> Dict[str, Any]:
        """Get all configuration values with optional prefix"""
        pass

    @abstractmethod
    def save(self) -> None:
        """Persist configuration changes"""
        pass

    @abstractmethod
    def reload(self) -> None:
        """Reload configuration from source"""
        pass


class ConfigurationSection:
    """Represents a configuration section"""

    def __init__(self, provider: IConfigurationProvider, prefix: str = ""):
        self._provider = provider
        self._prefix = prefix

    def get(self, key: str, default: Any = None) -> Any:
        """Get value from this section"""
        full_key = f"{self._prefix}.{key}" if self._prefix else key
        return self._provider.get(full_key, default)

    def set(self, key: str, value: Any) -> None:
        """Set value in this section"""
        full_key = f"{self._prefix}.{key}" if self._prefix else key
        self._provider.set(full_key, value)

    def has(self, key: str) -> bool:
        """Check if key exists in this section"""
        full_key = f"{self._prefix}.{key}" if self._prefix else key
        return self._provider.has(full_key)


class IPluginRegistry(ABC):
    """Interface for plugin management"""

    @abstractmethod
    def register_detector(self, name: str, detector_class: type) -> None:
        """Register a detector plugin"""
        pass

    @abstractmethod
    def get_detector(self, name: str) -> Optional[type]:
        """Get registered detector class"""
        pass

    @abstractmethod
    def list_detectors(self) -> Dict[str, type]:
        """List all registered detectors"""
        pass

    @abstractmethod
    def register_analyzer(self, language: str, analyzer_class: type) -> None:
        """Register a language analyzer plugin"""
        pass

    @abstractmethod
    def get_analyzer(self, language: str) -> Optional[type]:
        """Get registered analyzer class"""
        pass

    @abstractmethod
    def list_analyzers(self) -> Dict[str, type]:
        """List all registered analyzers"""
        pass

