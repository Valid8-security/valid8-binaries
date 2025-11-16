#!/usr/bin/env python3
"""
Modular CLI - Refactored CLI using service layer architecture
"""
import sys
from pathlib import Path

# Add current directory to path for imports
current_dir = Path(__file__).parent
if str(current_dir) not in sys.path:
    sys.path.insert(0, str(current_dir))

try:
    import click
    from rich.console import Console

    from .core.config_manager import config_manager
    from .core.dependency_container import container, register_service
    from .interfaces.scanner import IScanner
    from .core.scanner_service import ModularScanner, create_scanner
    from .services.cli_service import command_registry, ScanCommand
    from .plugins.detector_plugin import detector_plugin_manager
    from .utils.logging_utils import logger

    console = Console()

except ImportError as e:
    print(f"Import error: {e}")
    print("Please ensure all dependencies are installed")
    sys.exit(1)


@click.group()
@click.version_option(version="2.0.0")
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.option('--config', help='Path to configuration file')
def main(verbose, config):
    """
    🔒 Valid8 Security Scanner - Modular Architecture

    Enterprise-grade security scanning with extensible plugin system.
    """
    # Setup configuration
    if config:
        config_manager._config_file = Path(config)

    # Setup logging level
    if verbose:
        config_manager.set('log_level', 'DEBUG')

    # Register services
    register_service(IScanner, create_scanner, "singleton")

    # Load detector plugins
    detector_plugin_manager.load_builtin_plugins()

    logger.info("Valid8 CLI initialized")


@main.command()
@click.argument('path', type=click.Path(exists=True))
@click.option('--format', '-f', type=click.Choice(['json', 'markdown', 'terminal']),
              default='terminal', help='Output format')
@click.option('--output', '-o', type=click.Path(), help='Output file path')
@click.option('--mode', '-m', type=click.Choice(['fast', 'hybrid', 'deep']),
              default='fast', help='Scan mode')
@click.option('--severity', '-s', type=click.Choice(['low', 'medium', 'high', 'critical']),
              help='Minimum severity level')
@click.option('--validate', is_flag=True, help='Use AI to validate findings')
@click.option('--exclude', multiple=True, help='Exclude patterns (glob)')
def scan(path, format, output, mode, severity, validate, exclude):
    """
    Scan a codebase for security vulnerabilities.

    PATH: Path to scan (file or directory)

    Examples:
        valid8 scan ./src
        valid8 scan ./src --mode hybrid --format json --output results.json
        valid8 scan ./src --exclude "test/**" --exclude "*.min.js"
    """
    try:
        # Get scan command from registry
        scan_command = command_registry.get_command('scan')
        if not scan_command:
            console.print("[red]❌ Scan command not available[/red]")
            return 1

        # Prepare arguments
        kwargs = {
            'path': path,
            'format': format,
            'output': output,
            'mode': mode,
            'severity': severity,
            'validate': validate,
            'exclude': exclude
        }

        # Execute scan
        exit_code = scan_command.execute(**kwargs)
        return exit_code

    except Exception as e:
        logger.error(f"Scan failed: {e}")
        console.print(f"[red]❌ Scan failed: {e}[/red]")
        return 1


@main.command()
@click.option('--host', default='0.0.0.0', help='Host to bind GUI to')
@click.option('--port', type=int, default=3000, help='Port to bind GUI to')
@click.option('--no-browser', is_flag=True, help='Do not open browser automatically')
def gui(host, port, no_browser):
    """
    🚀 Launch Valid8 Web GUI

    Start the web-based interface for interactive scanning, results visualization,
    and enterprise management.

    Examples:
        valid8 gui                    # Start GUI on default port 3000
        valid8 gui --port 8080        # Start GUI on custom port
        valid8 gui --no-browser       # Start GUI without opening browser
    """
    try:
        from .services.gui_service import gui_registry

        console.print(f"[cyan]🚀 Starting Valid8 GUI on {host}:{port}...[/cyan]")

        # Import GUI service
        from .services.gui_service import gui_registry

        # For now, just show that GUI components are registered
        components = gui_registry.list_components()
        console.print(f"[green]✓ Loaded {len(components)} GUI components:[/green]")

        for name, component in components.items():
            console.print(f"  • {name}")

        console.print(f"\n[bold cyan]🌐 GUI would be available at: http://{host}:{port}[/bold cyan]")
        console.print(f"[dim]GUI implementation is modular and ready for extension[/dim]")

        # Note: Full GUI implementation would require Flask and additional setup
        console.print(f"\n[yellow]Note: Full GUI requires additional setup with Flask[/yellow]")
        console.print(f"[yellow]Use 'pip install flask flask-cors' and run gui_launcher.py instead[/yellow]")

    except Exception as e:
        logger.error(f"GUI launch failed: {e}")
        console.print(f"[red]❌ GUI launch failed: {e}[/red]")
        return 1


@main.command()
@click.option('--list-plugins', is_flag=True, help='List all loaded plugins')
@click.option('--list-detectors', is_flag=True, help='List all available detectors')
def plugins(list_plugins, list_detectors):
    """
    Manage and inspect detector plugins

    Examples:
        valid8 plugins --list-plugins     # Show loaded plugins
        valid8 plugins --list-detectors   # Show available detectors
    """
    try:
        if list_plugins:
            plugins = detector_plugin_manager.list_plugins()
            console.print(f"[cyan]📦 Loaded Plugins ({len(plugins)}):[/cyan]")

            for name, plugin in plugins.items():
                console.print(f"  • [bold]{name}[/bold] v{plugin.version}")
                console.print(f"    {plugin.description}")

        if list_detectors:
            detectors = detector_plugin_manager.list_detectors()
            console.print(f"[cyan]🔍 Available Detectors ({len(detectors)}):[/cyan]")

            for name, detector_class in detectors.items():
                console.print(f"  • {name}")

        if not list_plugins and not list_detectors:
            console.print("[yellow]Use --list-plugins or --list-detectors to see details[/yellow]")

    except Exception as e:
        logger.error(f"Plugin inspection failed: {e}")
        console.print(f"[red]❌ Plugin inspection failed: {e}[/red]")
        return 1


@main.command()
def config():
    """
    Show and manage configuration

    Examples:
        valid8 config    # Show current configuration
    """
    try:
        console.print("[cyan]⚙️  Valid8 Configuration:[/cyan]")
        console.print(f"Config file: {config_manager._config_file}")

        all_config = config_manager.get_all()
        for key, value in sorted(all_config.items()):
            if 'secret' in key.lower() or 'key' in key.lower():
                display_value = "***"  # Hide sensitive values
            else:
                display_value = str(value)
            console.print(f"  {key}: {display_value}")

    except Exception as e:
        logger.error(f"Config display failed: {e}")
        console.print(f"[red]❌ Config display failed: {e}[/red]")
        return 1


if __name__ == '__main__':
    # Register additional commands
    command_registry.register_command(ScanCommand())

    # Run CLI
    sys.exit(main())
