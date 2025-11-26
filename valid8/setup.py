#!/usr/bin/env python3
"""
Copyright (c) 2025 Valid8 Security
All rights reserved.

This software is proprietary and confidential. Unauthorized copying,
modification, distribution, or use of this software, via any medium is
strictly prohibited without the express written permission of Valid8 Security.

"""

"""
Parry Setup and Installation Helper

Makes it easy to get started with Parry:
- Automatic Ollama detection and installation
- Model download with progress bars
- Graceful fallbacks if AI unavailable
- Interactive setup wizard
- Health checks
"""

import os
import sys
import subprocess
import platform
import requests
import json
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
import time


class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class SetupHelper:
    """Helper for Parry setup and configuration"""
    
    def __init__(self):
        self.ollama_installed = False
        self.ollama_running = False
        self.model_available = False
        self.recommended_model = "qwen2.5-coder:1.5b"  # Mac M3 compatible (3B/7B hang)
        self.model_size_gb = 0.99
        
    def print_banner(self):
        """Print welcome banner"""
        print(f"\n{Colors.HEADER}{Colors.BOLD}")
        print("╔═══════════════════════════════════════════════╗")
        print("║                                               ║")
        print("║         🔒 Parry Security Scanner 🔒          ║")
        print("║                                               ║")
        print("║    Privacy-First AI-Powered Security         ║")
        print("║                                               ║")
        print("╚═══════════════════════════════════════════════╝")
        print(f"{Colors.ENDC}\n")
        
    def check_ollama_installed(self) -> bool:
        """Check if Ollama is installed"""
        try:
            result = subprocess.run(
                ['ollama', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            self.ollama_installed = result.returncode == 0
            if self.ollama_installed:
                version = result.stdout.strip()
                print(f"{Colors.OKGREEN}✓{Colors.ENDC} Ollama is installed: {version}")
            return self.ollama_installed
        except (FileNotFoundError, subprocess.TimeoutExpired):
            self.ollama_installed = False
            return False
    
    def check_ollama_running(self) -> bool:
        """Check if Ollama service is running"""
        try:
            response = requests.get('http://localhost:11434/api/tags', timeout=2)
            self.ollama_running = response.status_code == 200
            if self.ollama_running:
                print(f"{Colors.OKGREEN}✓{Colors.ENDC} Ollama service is running")
            return self.ollama_running
        except:
            self.ollama_running = False
            return False
    
    def check_model_available(self, model_name: str = None) -> bool:
        """Check if model is downloaded"""
        if not model_name:
            model_name = self.recommended_model
            
        try:
            response = requests.get('http://localhost:11434/api/tags', timeout=2)
            if response.status_code == 200:
                data = response.json()
                models = [m['name'] for m in data.get('models', [])]
                self.model_available = any(model_name.split(':')[0] in m for m in models)
                if self.model_available:
                    print(f"{Colors.OKGREEN}✓{Colors.ENDC} Model '{model_name}' is available")
                return self.model_available
        except:
            pass
        
        self.model_available = False
        return False
    
    def get_install_instructions(self) -> str:
        """Get OS-specific Ollama installation instructions"""
        system = platform.system().lower()
        
        if system == 'darwin':  # macOS
            return f"""
{Colors.BOLD}To install Ollama on macOS:{Colors.ENDC}

Option 1 (Recommended): Using Homebrew
  {Colors.OKCYAN}brew install ollama{Colors.ENDC}

Option 2: Direct download
  Visit: https://ollama.ai/download
  Download and run the installer

After installation:
  {Colors.OKCYAN}ollama serve{Colors.ENDC}  (in a separate terminal)
"""
        elif system == 'linux':
            return f"""
{Colors.BOLD}To install Ollama on Linux:{Colors.ENDC}

Run this command:
  {Colors.OKCYAN}curl -fsSL https://ollama.ai/install.sh | sh{Colors.ENDC}

After installation:
  {Colors.OKCYAN}ollama serve{Colors.ENDC}  (in a separate terminal)
"""
        elif system == 'windows':
            return f"""
{Colors.BOLD}To install Ollama on Windows:{Colors.ENDC}

1. Visit: https://ollama.ai/download
2. Download the Windows installer
3. Run the installer
4. Ollama will start automatically

Or use WSL2 with Linux instructions above.
"""
        else:
            return "Visit https://ollama.ai/download for installation instructions"
    
    def start_ollama(self) -> bool:
        """Try to start Ollama service"""
        system = platform.system().lower()
        
        print(f"\n{Colors.OKBLUE}Starting Ollama service...{Colors.ENDC}")
        
        try:
            if system == 'darwin' or system == 'linux':
                # Try to start in background
                subprocess.Popen(
                    ['ollama', 'serve'],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True
                )
                # Wait a bit for service to start
                time.sleep(2)
                return self.check_ollama_running()
            else:
                print(f"{Colors.WARNING}⚠{Colors.ENDC} Please start Ollama manually")
                return False
        except Exception as e:
            print(f"{Colors.WARNING}⚠{Colors.ENDC} Could not start Ollama automatically: {e}")
            return False
    
    def download_model(self, model_name: str = None) -> bool:
        """Download AI model with progress indicator"""
        if not model_name:
            model_name = self.recommended_model
        
        print(f"\n{Colors.OKBLUE}Downloading model '{model_name}' (~{self.model_size_gb}GB)...{Colors.ENDC}")
        print(f"{Colors.WARNING}This may take 5-20 minutes depending on your connection.{Colors.ENDC}")
        print(f"You can cancel anytime with Ctrl+C and resume later.\n")
        
        try:
            # Use ollama pull with streaming output
            process = subprocess.Popen(
                ['ollama', 'pull', model_name],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            
            # Stream output
            for line in process.stdout:
                print(line.rstrip())
            
            process.wait()
            
            if process.returncode == 0:
                print(f"\n{Colors.OKGREEN}✓{Colors.ENDC} Model downloaded successfully!")
                return True
            else:
                print(f"\n{Colors.FAIL}✗{Colors.ENDC} Model download failed")
                return False
                
        except KeyboardInterrupt:
            print(f"\n\n{Colors.WARNING}⚠{Colors.ENDC} Download cancelled. You can resume later by running:")
            print(f"  {Colors.OKCYAN}ollama pull {model_name}{Colors.ENDC}\n")
            return False
        except Exception as e:
            print(f"\n{Colors.FAIL}✗{Colors.ENDC} Error downloading model: {e}")
            return False
    
    def run_interactive_setup(self) -> Dict[str, bool]:
        """Run interactive setup wizard"""
        self.print_banner()
        
        print("Welcome to Parry! Let's get you set up.\n")
        print("Parry has two modes:")
        print(f"  • {Colors.BOLD}Fast Mode{Colors.ENDC}: Pattern-based detection (works without AI)")
        print(f"  • {Colors.BOLD}Hybrid/Deep Mode{Colors.ENDC}: AI-powered detection (requires Ollama)\n")
        
        results = {
            'ollama_installed': False,
            'ollama_running': False,
            'model_available': False,
            'can_use_ai': False,
            'fast_mode_ready': True  # Always available
        }
        
        # Check Ollama installation
        print(f"{Colors.BOLD}Step 1: Checking Ollama installation...{Colors.ENDC}")
        if not self.check_ollama_installed():
            print(f"{Colors.WARNING}✗{Colors.ENDC} Ollama is not installed")
            print(self.get_install_instructions())
            
            response = input(f"\n{Colors.BOLD}Have you installed Ollama? (y/n):{Colors.ENDC} ").lower()
            if response == 'y':
                if not self.check_ollama_installed():
                    print(f"{Colors.FAIL}✗{Colors.ENDC} Still can't find Ollama. Please check installation.")
                    return results
            else:
                print(f"\n{Colors.OKGREEN}No problem!{Colors.ENDC} You can still use Parry in Fast Mode.")
                print(f"Run: {Colors.OKCYAN}parry scan /path/to/code --mode fast{Colors.ENDC}\n")
                return results
        
        results['ollama_installed'] = True
        
        # Check if Ollama is running
        print(f"\n{Colors.BOLD}Step 2: Checking Ollama service...{Colors.ENDC}")
        if not self.check_ollama_running():
            print(f"{Colors.WARNING}✗{Colors.ENDC} Ollama service is not running")
            
            response = input(f"\n{Colors.BOLD}Start Ollama now? (y/n):{Colors.ENDC} ").lower()
            if response == 'y':
                if self.start_ollama():
                    results['ollama_running'] = True
                else:
                    print(f"\n{Colors.WARNING}Please start Ollama manually:{Colors.ENDC}")
                    print(f"  {Colors.OKCYAN}ollama serve{Colors.ENDC}  (in a separate terminal)\n")
                    return results
            else:
                print(f"\n{Colors.WARNING}You'll need to start Ollama to use AI modes:{Colors.ENDC}")
                print(f"  {Colors.OKCYAN}ollama serve{Colors.ENDC}\n")
                return results
        else:
            results['ollama_running'] = True
        
        # Check model availability
        print(f"\n{Colors.BOLD}Step 3: Checking AI model...{Colors.ENDC}")
        if not self.check_model_available():
            print(f"{Colors.WARNING}✗{Colors.ENDC} Model '{self.recommended_model}' is not downloaded")
            print(f"Size: ~{self.model_size_gb}GB")
            
            response = input(f"\n{Colors.BOLD}Download model now? (y/n):{Colors.ENDC} ").lower()
            if response == 'y':
                if self.download_model():
                    results['model_available'] = True
                else:
                    print(f"\n{Colors.WARNING}You can download it later with:{Colors.ENDC}")
                    print(f"  {Colors.OKCYAN}ollama pull {self.recommended_model}{Colors.ENDC}\n")
                    return results
            else:
                print(f"\n{Colors.WARNING}You can download it later with:{Colors.ENDC}")
                print(f"  {Colors.OKCYAN}ollama pull {self.recommended_model}{Colors.ENDC}\n")
                return results
        else:
            results['model_available'] = True
        
        results['can_use_ai'] = (
            results['ollama_installed'] and 
            results['ollama_running'] and 
            results['model_available']
        )
        
        # Success message
        print(f"\n{Colors.OKGREEN}{Colors.BOLD}✓ Setup Complete!{Colors.ENDC}\n")
        
        if results['can_use_ai']:
            print(f"{Colors.BOLD}You can now use all Parry modes:{Colors.ENDC}")
            print(f"  • Fast Mode:   {Colors.OKCYAN}parry scan /path/to/code --mode fast{Colors.ENDC}")
            print(f"  • Hybrid Mode: {Colors.OKCYAN}parry scan /path/to/code --mode hybrid{Colors.ENDC}")
            print(f"  • Deep Mode:   {Colors.OKCYAN}parry scan /path/to/code --mode deep{Colors.ENDC}\n")
        else:
            print(f"{Colors.BOLD}You can use Fast Mode:{Colors.ENDC}")
            print(f"  {Colors.OKCYAN}parry scan /path/to/code --mode fast{Colors.ENDC}\n")
        
        return results
    
    def run_health_check(self) -> Dict[str, Any]:
        """Run comprehensive health check"""
        print(f"\n{Colors.BOLD}Parry Health Check{Colors.ENDC}\n")
        
        health = {
            'ollama_installed': self.check_ollama_installed(),
            'ollama_running': self.check_ollama_running(),
            'model_available': False,
            'python_version': sys.version.split()[0],
            'platform': platform.system(),
            'issues': []
        }
        
        # Check Python version
        python_version = tuple(map(int, health['python_version'].split('.')[:2]))
        if python_version < (3, 8):
            health['issues'].append(f"Python 3.8+ required (you have {health['python_version']})")
            print(f"{Colors.FAIL}✗{Colors.ENDC} Python version: {health['python_version']} (need 3.8+)")
        else:
            print(f"{Colors.OKGREEN}✓{Colors.ENDC} Python version: {health['python_version']}")
        
        # Check Ollama
        if not health['ollama_installed']:
            health['issues'].append("Ollama not installed")
            print(f"{Colors.WARNING}⚠{Colors.ENDC} Ollama: Not installed (AI modes unavailable)")
        elif not health['ollama_running']:
            health['issues'].append("Ollama not running")
            print(f"{Colors.WARNING}⚠{Colors.ENDC} Ollama: Installed but not running")
        else:
            health['model_available'] = self.check_model_available()
            if not health['model_available']:
                health['issues'].append(f"Model '{self.recommended_model}' not downloaded")
        
        # Check dependencies
        print(f"\n{Colors.BOLD}Required Dependencies:{Colors.ENDC}")
        dependencies = ['click', 'rich', 'pyyaml', 'requests']
        for dep in dependencies:
            try:
                __import__(dep)
                print(f"{Colors.OKGREEN}✓{Colors.ENDC} {dep}")
            except ImportError:
                print(f"{Colors.FAIL}✗{Colors.ENDC} {dep}")
                health['issues'].append(f"Missing dependency: {dep}")
        
        # Summary
        print(f"\n{Colors.BOLD}Summary:{Colors.ENDC}")
        if not health['issues']:
            print(f"{Colors.OKGREEN}✓ All checks passed! Parry is ready to use.{Colors.ENDC}")
        else:
            print(f"{Colors.WARNING}⚠ {len(health['issues'])} issue(s) found:{Colors.ENDC}")
            for issue in health['issues']:
                print(f"  • {issue}")
        
        # Available modes
        print(f"\n{Colors.BOLD}Available Modes:{Colors.ENDC}")
        print(f"{Colors.OKGREEN}✓{Colors.ENDC} Fast Mode (pattern-based)")
        
        if health['ollama_running'] and health['model_available']:
            print(f"{Colors.OKGREEN}✓{Colors.ENDC} Hybrid Mode (AI-powered)")
            print(f"{Colors.OKGREEN}✓{Colors.ENDC} Deep Mode (full AI)")
        else:
            print(f"{Colors.WARNING}✗{Colors.ENDC} Hybrid/Deep Mode (requires Ollama + model)")
        
        print()
        return health
    
    def create_config_file(self, config_dir: Path = None):
        """Create default configuration file"""
        if not config_dir:
            config_dir = Path.home() / '.parry'
        
        config_dir.mkdir(exist_ok=True)
        config_file = config_dir / 'config.yaml'
        
        if config_file.exists():
            print(f"{Colors.WARNING}⚠{Colors.ENDC} Config file already exists: {config_file}")
            return
        
        config_content = """# Parry Configuration File

scanner:
  # Default scanning mode: fast, deep, or hybrid
  default_mode: hybrid
  
  # Enable AI validation to reduce false positives
  enable_validation: true
  
  # Number of concurrent threads for scanning
  max_threads: 4
  
  # Exclude patterns (glob format)
  exclude_patterns:
    - "node_modules/**"
    - "venv/**"
    - ".git/**"
    - "*.test.js"
    - "*.spec.py"

llm:
  # AI model to use (qwen2.5-coder:1.5b - Mac M3 compatible)
  model: qwen2.5-coder:1.5b
  
  # Ollama API endpoint
  endpoint: http://localhost:11434
  
  # Model parameters
  temperature: 0.1
  max_tokens: 2000
  
  # Cache AI responses
  enable_cache: true

reporting:
  # Default output format: json, markdown, or terminal
  default_format: json
  
  # Include AI-generated fixes in output
  include_fixes: true
  
  # Minimum confidence threshold (0.0 to 1.0)
  min_confidence: 0.6
  
  # Show detailed context in reports
  show_context: true

sca:
  # Enable Software Composition Analysis
  enabled: true
  
  # Check license compliance
  check_licenses: true
  
  # Severity threshold for dependency alerts
  min_severity: medium

cache:
  # Enable incremental scanning
  enabled: true
  
  # Cache TTL in days
  ttl_days: 7
  
  # Maximum cache size in MB
  max_size_mb: 1000

# Framework-specific rules
frameworks:
  django:
    check_csrf: true
    check_debug_mode: true
  
  flask:
    check_debug_mode: true
    check_secret_key: true
  
  spring:
    check_authorization: true
    check_sql_injection: true
"""
        
        config_file.write_text(config_content)
        print(f"{Colors.OKGREEN}✓{Colors.ENDC} Created config file: {config_file}")
        print(f"  You can edit this file to customize Parry's behavior.\n")


def run_setup_wizard():
    """Run the interactive setup wizard"""
    helper = SetupHelper()
    return helper.run_interactive_setup()


def run_doctor():
    """Run health check (parry doctor command)"""
    helper = SetupHelper()
    return helper.run_health_check()


def create_config():
    """Create default configuration file"""
    helper = SetupHelper()
    helper.create_config_file()


if __name__ == '__main__':
    # Run setup wizard if executed directly
    helper = SetupHelper()
    helper.run_interactive_setup()

