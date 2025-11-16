#!/usr/bin/env python3
"""
Test Script for Valid8 Modular Architecture

This script demonstrates that the modular architecture works correctly
without import path issues.
"""

import sys
import os
from pathlib import Path

# Add the valid8 directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'valid8'))

def test_config_system():
    """Test configuration system"""
    print("🧪 Testing Configuration System...")

    try:
        from core.config_manager import config_manager, Valid8Config

        # Test defaults
        default_mode = config_manager.get('default_scan_mode', 'fast')
        assert default_mode == 'fast'
        print("  ✅ Default configuration loaded")

        # Test setting values
        config_manager.set('test_key', 'test_value')
        value = config_manager.get('test_key')
        assert value == 'test_value'
        print("  ✅ Configuration set/get works")

        # Test section
        scanner_config = config_manager.get_section('scanner')
        timeout = scanner_config.get('timeout_seconds', 300)
        assert timeout == 300
        print("  ✅ Configuration sections work")

        print("🎉 Configuration system working!")
        return True

    except Exception as e:
        print(f"❌ Configuration test failed: {e}")
        return False


def test_dependency_injection():
    """Test dependency injection container"""
    print("\n🧪 Testing Dependency Injection...")

    try:
        from core.dependency_container import container, ServiceLifetime
        from interfaces.scanner import IScanner

        # Test service registration
        class MockScanner(IScanner):
            def scan(self, target, **kwargs):
                return {"mock": "result"}

            def supports_mode(self, mode):
                return True

            def get_capabilities(self):
                return {"mock": True}

        container.register_service(IScanner, MockScanner, ServiceLifetime.TRANSIENT)

        # Test service resolution
        scanner1 = container.get_service(IScanner)
        scanner2 = container.get_service(IScanner)

        assert scanner1 is not None
        assert scanner2 is not None
        assert scanner1 is not scanner2  # Transient should be different instances
        print("  ✅ Service registration and resolution works")

        # Test singleton
        container.register_service(IScanner, MockScanner, ServiceLifetime.SINGLETON)
        singleton1 = container.get_service(IScanner)
        singleton2 = container.get_service(IScanner)

        assert singleton1 is singleton2  # Singleton should be same instance
        print("  ✅ Singleton lifetime works")

        print("🎉 Dependency injection working!")
        return True

    except Exception as e:
        print(f"❌ Dependency injection test failed: {e}")
        return False


def test_plugin_system():
    """Test plugin system"""
    print("\n🧪 Testing Plugin System...")

    try:
        from plugins.detector_plugin import detector_plugin_manager, DetectorPlugin
        from interfaces.scanner import IDetector

        # Test plugin registration
        class TestPlugin(DetectorPlugin):
            @property
            def name(self):
                return "test-plugin"

            @property
            def version(self):
                return "1.0.0"

            @property
            def description(self):
                return "Test plugin"

            def get_detectors(self):
                class TestDetector(IDetector):
                    @property
                    def name(self):
                        return "test-detector"

                    @property
                    def supported_languages(self):
                        return ["python"]

                    def detect(self, file_path, content, **kwargs):
                        return []

                    def get_supported_cwes(self):
                        return ["CWE-TEST"]

                return [TestDetector]

        # Register plugin
        plugin = TestPlugin()
        detector_plugin_manager.register_plugin(plugin)

        # Test plugin retrieval
        plugins = detector_plugin_manager.list_plugins()
        assert "test-plugin" in plugins
        print("  ✅ Plugin registration works")

        # Test detector retrieval
        detectors = detector_plugin_manager.list_detectors()
        assert len(detectors) > 0
        print("  ✅ Detector registration works")

        print("🎉 Plugin system working!")
        return True

    except Exception as e:
        print(f"❌ Plugin system test failed: {e}")
        return False


def test_service_layer():
    """Test service layer architecture"""
    print("\n🧪 Testing Service Layer...")

    try:
        from services.cli_service import command_registry, ICLICommand
        from services.gui_service import gui_registry, IGUIComponent

        # Test CLI command registry
        commands = command_registry.list_commands()
        assert len(commands) > 0
        assert "scan" in commands
        print("  ✅ CLI command registry works")

        # Test GUI component registry
        components = gui_registry.list_components()
        assert len(components) > 0
        print("  ✅ GUI component registry works")

        print("🎉 Service layer working!")
        return True

    except Exception as e:
        print(f"❌ Service layer test failed: {e}")
        return False


def test_utils():
    """Test utility functions"""
    print("\n🧪 Testing Utilities...")

    try:
        from utils.file_utils import get_file_language, ensure_directory
        from utils.logging_utils import logger

        # Test file utilities
        py_file = Path("test.py")
        lang = get_file_language(py_file)
        assert lang == "python"
        print("  ✅ File utilities work")

        # Test logging
        logger.info("Test log message")
        print("  ✅ Logging utilities work")

        print("🎉 Utilities working!")
        return True

    except Exception as e:
        print(f"❌ Utilities test failed: {e}")
        return False


def test_scanner_service():
    """Test scanner service"""
    print("\n🧪 Testing Scanner Service...")

    try:
        from core.scanner_service import ModularScanner
        from interfaces.scanner import IScanner

        # Create scanner
        scanner = ModularScanner()
        assert isinstance(scanner, IScanner)
        print("  ✅ Scanner implements interface")

        # Test capabilities
        caps = scanner.get_capabilities()
        assert "supported_modes" in caps
        assert "supported_languages" in caps
        print("  ✅ Scanner capabilities work")

        # Test mode support
        assert scanner.supports_mode("fast")
        assert scanner.supports_mode("hybrid")
        assert not scanner.supports_mode("invalid")
        print("  ✅ Mode support checking works")

        print("🎉 Scanner service working!")
        return True

    except Exception as e:
        print(f"❌ Scanner service test failed: {e}")
        return False


def main():
    """Run all tests"""
    print("🚀 Valid8 Modular Architecture Test Suite")
    print("=" * 50)

    tests = [
        test_config_system,
        test_dependency_injection,
        test_plugin_system,
        test_service_layer,
        test_utils,
        test_scanner_service
    ]

    passed = 0
    total = len(tests)

    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"❌ Test {test.__name__} crashed: {e}")

    print("\n" + "=" * 50)
    print(f"📊 Test Results: {passed}/{total} passed")

    if passed == total:
        print("🎉 ALL TESTS PASSED! Modular architecture is working correctly.")
        return 0
    else:
        print("❌ Some tests failed. Please check the implementation.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
