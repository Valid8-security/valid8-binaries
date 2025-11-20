#!/usr/bin/env python3
"""
Standalone GUI Launcher for Valid8

This launcher avoids package import issues by importing GUI components directly.
"""

import sys
import os

# Add the valid8 directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'valid8'))

def main():
    """Launch the Valid8 GUI"""
    try:
        # Import GUI directly
        from gui import Valid8GUI

        # Parse command line arguments
        import argparse
        parser = argparse.ArgumentParser(description='Valid8 Web GUI')
        parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
        parser.add_argument('--port', type=int, default=3000, help='Port to bind to')
        parser.add_argument('--debug', action='store_true', help='Enable debug mode')

        args = parser.parse_args()

        # Start GUI
        gui = Valid8GUI(host=args.host, port=args.port, debug=args.debug)
        gui.start()

    except KeyboardInterrupt:
        print("\nValid8 GUI stopped")
    except Exception as e:
        print(f"Error starting GUI: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    main()

