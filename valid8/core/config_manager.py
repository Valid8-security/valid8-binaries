"""
Configuration Manager - Centralized configuration management
"""
import os
import json
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass

from ..interfaces.config import IConfigurationProvider, ConfigurationSection, IPluginRegistry


@dataclass
class Valid8Config:
    """Valid8 configuration structure"""
    # Scanner settings
    default_scan_mode: str = "fast"
    max_file_size: int = 10 * 1024 * 1024  # 10MB
    timeout_seconds: int = 300

    # AI settings
    ai_enabled: bool = True
    ollama_host: str = "http://localhost:11434"
    default_model: str = "codellama:7b"

    # Performance settings
    max_workers: int = 4
    batch_size: int = 10

    # Enterprise settings
    enterprise_enabled: bool = False
    license_server: str = "https://api.valid8.dev"

    # GUI settings
    gui_host: str = "0.0.0.0"
    gui_port: int = 3000

    # Logging
    log_level: str = "INFO"
    log_file: Optional[str] = None


class ConfigurationManager(IConfigurationProvider):
    """Centralized configuration management"""

    def __init__(self, config_file: Optional[Path] = None):
        self.config_file = config_file or self._get_default_config_path()
        self._config = self._load_config()
        self._defaults = Valid8Config()

    def _get_default_config_path(self) -> Path:
        """Get default configuration file path"""
        config_dir = Path.home() / '.valid8'
        config_dir.mkdir(exist_ok=True)
        return config_dir / 'config.json'

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file"""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                # Return empty config if file is corrupted
                return {}
        return {}

    def _save_config(self) -> None:
        """Save configuration to file"""
        self.config_file.parent.mkdir(exist_ok=True)
        with open(self.config_file, 'w') as f:
            json.dump(self._config, f, indent=2)

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value"""
        # Check environment variable first (highest priority)
        env_key = f"VALID8_{key.upper().replace('.', '_')}"
        env_value = os.environ.get(env_key)
        if env_value is not None:
            return self._parse_env_value(env_value)

        # Check loaded config
        if key in self._config:
            return self._config[key]

        # Check defaults
        if hasattr(self._defaults, key):
            return getattr(self._defaults, key)

        return default

    def set(self, key: str, value: Any) -> None:
        """Set configuration value"""
        self._config[key] = value
        self._save_config()

    def has(self, key: str) -> bool:
        """Check if configuration key exists"""
        env_key = f"VALID8_{key.upper().replace('.', '_')}"
        if env_key in os.environ:
            return True
        return key in self._config or hasattr(self._defaults, key)

    def get_all(self, prefix: str = "") -> Dict[str, Any]:
        """Get all configuration values with optional prefix"""
        result = {}

        # Get from defaults first
        for attr_name in dir(self._defaults):
            if not attr_name.startswith('_'):
                full_key = f"{prefix}.{attr_name}" if prefix else attr_name
                result[full_key] = getattr(self._defaults, attr_name)

        # Override with loaded config
        for key, value in self._config.items():
            full_key = f"{prefix}.{key}" if prefix else key
            result[full_key] = value

        # Override with environment variables
        for env_key, env_value in os.environ.items():
            if env_key.startswith('VALID8_'):
                config_key = env_key[7:].lower().replace('_', '.')
                if not prefix or config_key.startswith(prefix):
                    display_key = f"{prefix}.{config_key}" if prefix else config_key
                    result[display_key] = self._parse_env_value(env_value)

        return result

    def save(self) -> None:
        """Persist configuration changes"""
        self._save_config()

    def reload(self) -> None:
        """Reload configuration from source"""
        self._config = self._load_config()

    def get_section(self, section_name: str) -> ConfigurationSection:
        """Get a configuration section"""
        return ConfigurationSection(self, section_name)

    def _parse_env_value(self, value: str) -> Any:
        """Parse environment variable value to appropriate type"""
        # Try boolean
        if value.lower() in ('true', 'false'):
            return value.lower() == 'true'

        # Try int
        try:
            return int(value)
        except ValueError:
            pass

        # Try float
        try:
            return float(value)
        except ValueError:
            pass

        # Return as string
        return value


class PluginRegistry(IPluginRegistry):
    """Plugin registry for detectors and analyzers"""

    def __init__(self):
        self._detectors: Dict[str, type] = {}
        self._analyzers: Dict[str, type] = {}

    def register_detector(self, name: str, detector_class: type) -> None:
        """Register a detector plugin"""
        self._detectors[name] = detector_class

    def get_detector(self, name: str) -> Optional[type]:
        """Get registered detector class"""
        return self._detectors.get(name)

    def list_detectors(self) -> Dict[str, type]:
        """List all registered detectors"""
        return self._detectors.copy()

    def register_analyzer(self, language: str, analyzer_class: type) -> None:
        """Register a language analyzer plugin"""
        self._analyzers[language] = analyzer_class

    def get_analyzer(self, language: str) -> Optional[type]:
        """Get registered analyzer class"""
        return self._analyzers.get(language)

    def list_analyzers(self) -> Dict[str, type]:
        """List all registered analyzers"""
        return self._analyzers.copy()


# Global instances
config_manager = ConfigurationManager()
plugin_registry = PluginRegistry()

