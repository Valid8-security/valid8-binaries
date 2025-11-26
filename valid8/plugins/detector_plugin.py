#!/usr/bin/env python3
"""
Copyright (c) 2025 Valid8 Security
All rights reserved.

This software is proprietary and confidential. Unauthorized copying,
modification, distribution, or use of this software, via any medium is
strictly prohibited without the express written permission of Valid8 Security.

"""

"""
Detector Plugin System - Extensible detector architecture
"""
import importlib
import pkgutil
from pathlib import Path
from typing import Dict, List, Type, Any, Optional
from abc import ABC, abstractmethod

from ..interfaces.scanner import IDetector
from ..core.config_manager import plugin_registry


class DetectorPlugin(ABC):
    """Base class for detector plugins"""

    @property
    @abstractmethod
    def name(self) -> str:
        """Plugin name"""
        pass

    @property
    @abstractmethod
    def version(self) -> str:
        """Plugin version"""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Plugin description"""
        pass

    @abstractmethod
    def get_detectors(self) -> List[Type[IDetector]]:
        """Return detector classes provided by this plugin"""
        pass

    def get_dependencies(self) -> List[str]:
        """Return required dependencies (pip packages)"""
        return []

    def is_compatible(self) -> bool:
        """Check if plugin is compatible with current environment"""
        return True


class DetectorPluginManager:
    """Manages detector plugins"""

    def __init__(self):
        self._plugins: Dict[str, DetectorPlugin] = {}
        self._detectors: Dict[str, Type[IDetector]] = {}

    def load_builtin_plugins(self) -> None:
        """Load built-in detector plugins"""
        # Load legacy detectors as a plugin
        try:
            legacy_plugin = LegacyDetectorPlugin()
            self.register_plugin(legacy_plugin)
        except Exception as e:
            print(f"Failed to load legacy detectors: {e}")

    def load_external_plugins(self, plugin_dir: Path) -> None:
        """Load external plugins from directory"""
        if not plugin_dir.exists():
            return

        for item in plugin_dir.iterdir():
            if item.is_dir() and (item / "__init__.py").exists():
                try:
                    self._load_plugin_from_path(item)
                except Exception as e:
                    print(f"Failed to load plugin {item.name}: {e}")

    def _load_plugin_from_path(self, plugin_path: Path) -> None:
        """Load plugin from filesystem path"""
        import sys
        plugin_name = plugin_path.name

        # Add to Python path
        sys.path.insert(0, str(plugin_path.parent))

        try:
            # Import plugin module
            plugin_module = importlib.import_module(plugin_name)

            # Find plugin class
            for attr_name in dir(plugin_module):
                attr = getattr(plugin_module, attr_name)
                if (isinstance(attr, type) and
                    issubclass(attr, DetectorPlugin) and
                    attr != DetectorPlugin):
                    plugin_instance = attr()
                    self.register_plugin(plugin_instance)
                    break

        except Exception as e:
            print(f"Error loading plugin {plugin_name}: {e}")
        finally:
            # Remove from Python path
            sys.path.remove(str(plugin_path.parent))

    def register_plugin(self, plugin: DetectorPlugin) -> None:
        """Register a detector plugin"""
        if not plugin.is_compatible():
            print(f"Plugin {plugin.name} is not compatible with current environment")
            return

        self._plugins[plugin.name] = plugin

        # Register detectors from this plugin
        for detector_class in plugin.get_detectors():
            detector_name = f"{plugin.name}.{detector_class.__name__}"
            self._detectors[detector_name] = detector_class

            # Also register in global plugin registry
            plugin_registry.register_detector(detector_name, detector_class)

        print(f"✅ Registered plugin: {plugin.name} v{plugin.version}")

    def get_detector(self, name: str) -> Optional[Type[IDetector]]:
        """Get detector class by name"""
        return self._detectors.get(name)

    def list_detectors(self) -> Dict[str, Type[IDetector]]:
        """List all available detectors"""
        return self._detectors.copy()

    def list_plugins(self) -> Dict[str, DetectorPlugin]:
        """List all registered plugins"""
        return self._plugins.copy()

    def create_detector_instances(self) -> List[IDetector]:
        """Create instances of all available detectors"""
        instances = []
        for detector_class in self._detectors.values():
            try:
                instance = detector_class()
                instances.append(instance)
            except Exception as e:
                print(f"Failed to create detector instance {detector_class.__name__}: {e}")

        return instances


class LegacyDetectorPlugin(DetectorPlugin):
    """Plugin that wraps existing legacy detectors"""

    @property
    def name(self) -> str:
        return "legacy"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def description(self) -> str:
        return "Legacy detector implementations"

    def get_detectors(self) -> List[Type[IDetector]]:
        """Return legacy detector classes"""
        detectors = []

        # Import legacy detectors dynamically
        legacy_detector_classes = [
            "SQLInjectionDetector",
            "XSSDetector",
            "SecretsDetector",
            "PathTraversalDetector",
            "CommandInjectionDetector",
            "DeserializationDetector",
            "WeakCryptoDetector",
            "XXEDetector",
            "SSRFDetector",
            "PermissionDetector"
        ]

        try:
            # Try to import from detectors module
            from ..detectors.base_detector import (
                SQLInjectionDetector, XSSDetector, SecretsDetector,
                PathTraversalDetector, CommandInjectionDetector,
                DeserializationDetector, WeakCryptoDetector,
                XXEDetector, SSRFDetector, PermissionDetector
            )

            detectors.extend([
                SQLInjectionDetector, XSSDetector, SecretsDetector,
                PathTraversalDetector, CommandInjectionDetector,
                DeserializationDetector, WeakCryptoDetector,
                XXEDetector, SSRFDetector, PermissionDetector
            ])

        except ImportError:
            # Fallback: create wrapper classes
            print("Legacy detectors not available, using compatibility mode")

        return detectors


# Global plugin manager instance
detector_plugin_manager = DetectorPluginManager()

# Load built-in plugins
detector_plugin_manager.load_builtin_plugins()


# Convenience functions
def get_legacy_detectors() -> List[IDetector]:
    """Get legacy detector instances (for backward compatibility)"""
    return detector_plugin_manager.create_detector_instances()


def load_detector_plugins(plugin_dir: Optional[Path] = None) -> None:
    """Load detector plugins from directory"""
    if plugin_dir:
        detector_plugin_manager.load_external_plugins(plugin_dir)

