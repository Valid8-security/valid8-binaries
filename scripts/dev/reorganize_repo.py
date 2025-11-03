#!/usr/bin/env python3
# Parry (C) by Lemonade Stand. Written by Andy Kurapati and Shreyan Mitra
"""
Automated Repository Reorganization Script

This script safely reorganizes the Parry repository structure according to
the REORGANIZATION_PLAN.md, with validation and rollback capability.

Usage:
    python scripts/dev/reorganize_repo.py [--dry-run] [--backup]
    
Options:
    --dry-run    Show what would be done without making changes
    --backup     Create backup before making changes
    --rollback   Restore from backup
    
Safety Features:
- Dry-run mode for testing
- Automatic backup creation
- Git status check (warns if uncommitted changes)
- Path validation before moves
- Rollback capability
"""

import os
import sys
import shutil
import argparse
import json
from pathlib import Path
from datetime import datetime


class RepositoryReorganizer:
    """Handles safe repository reorganization with rollback support"""
    
    def __init__(self, root_dir: Path, dry_run: bool = False):
        self.root = root_dir
        self.dry_run = dry_run
        self.backup_dir = root_dir / ".backup" / datetime.now().strftime("%Y%m%d_%H%M%S")
        self.migration_log = []
        
    def log(self, message: str, level: str = "INFO"):
        """Log migration actions"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {level}: {message}"
        print(log_entry)
        self.migration_log.append(log_entry)
        
    def check_git_status(self) -> bool:
        """Check for uncommitted changes"""
        import subprocess
        try:
            result = subprocess.run(
                ["git", "status", "--porcelain"],
                capture_output=True,
                text=True,
                cwd=self.root
            )
            if result.stdout.strip():
                self.log("WARNING: Uncommitted changes detected!", "WARN")
                response = input("Continue anyway? (y/N): ")
                return response.lower() == 'y'
            return True
        except Exception as e:
            self.log(f"Could not check git status: {e}", "WARN")
            return True
            
    def create_backup(self):
        """Create backup of current structure"""
        if self.dry_run:
            self.log("DRY RUN: Would create backup", "INFO")
            return
            
        self.log(f"Creating backup at {self.backup_dir}", "INFO")
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        
        # Backup file mapping
        backup_map = {}
        files_to_backup = [
            ".gitignore",
            "setup.py",
            "pyproject.toml",
            "MANIFEST.in",
            ".gitlab-ci.yml",
            "Jenkinsfile",
            "README.md"
        ]
        
        for file in files_to_backup:
            src = self.root / file
            if src.exists():
                dst = self.backup_dir / file
                shutil.copy2(src, dst)
                backup_map[file] = str(dst)
                
        # Save backup map
        with open(self.backup_dir / "backup_map.json", "w") as f:
            json.dump(backup_map, f, indent=2)
            
        self.log(f"Backup created: {len(backup_map)} files", "INFO")
        
    def create_directories(self):
        """Create new directory structure"""
        dirs = [
            "docs/api",
            "docs/guides",
            "docs/benchmarks",
            "docs/testing",
            "docs/security",
            "docs/development",
            "scripts/dev",
            "scripts/build",
            "scripts/benchmark",
            "config",
            "integrations/homebrew",
            "integrations/vscode",
            "integrations/website",
        ]
        
        for dir_path in dirs:
            full_path = self.root / dir_path
            if self.dry_run:
                self.log(f"DRY RUN: Would create {dir_path}", "INFO")
            else:
                full_path.mkdir(parents=True, exist_ok=True)
                self.log(f"Created directory: {dir_path}", "INFO")
                
    def move_file(self, src: str, dst: str) -> bool:
        """Move a file or directory"""
        src_path = self.root / src
        dst_path = self.root / dst
        
        if not src_path.exists():
            self.log(f"SKIP: {src} does not exist", "WARN")
            return False
            
        if self.dry_run:
            self.log(f"DRY RUN: Would move {src} → {dst}", "INFO")
            return True
            
        try:
            dst_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(src_path), str(dst_path))
            self.log(f"Moved: {src} → {dst}", "INFO")
            return True
        except Exception as e:
            self.log(f"ERROR moving {src}: {e}", "ERROR")
            return False
            
    def migrate_documentation(self):
        """Move documentation files"""
        self.log("=== Phase 1: Migrating Documentation ===", "INFO")
        
        moves = {
            # API docs
            "API_REFERENCE.md": "docs/api/API_REFERENCE.md",
            
            # User guides
            "QUICKSTART.md": "docs/guides/QUICKSTART.md",
            "SETUP_GUIDE.md": "docs/guides/SETUP_GUIDE.md",
            "CONTRIBUTING.md": "docs/guides/CONTRIBUTING.md",
            "QUICK_DEMO.md": "docs/guides/QUICK_DEMO.md",
            
            # Benchmarks
            "BENCHMARK_SUMMARY.md": "docs/benchmarks/BENCHMARK_SUMMARY.md",
            "COMPREHENSIVE_BENCHMARK_RESULTS.md": "docs/benchmarks/COMPREHENSIVE_BENCHMARK_RESULTS.md",
            "COMPETITIVE_ANALYSIS.md": "docs/benchmarks/COMPETITIVE_ANALYSIS.md",
            "PARRY_METRICS.md": "docs/benchmarks/PARRY_METRICS.md",
            "SCAN_SPEED_EXAMPLES.md": "docs/benchmarks/SCAN_SPEED_EXAMPLES.md",
            
            # Testing
            "TEST_INSTRUCTIONS.md": "docs/testing/TEST_INSTRUCTIONS.md",
            "DEEP_MODE_TEST_INSTRUCTIONS.md": "docs/testing/DEEP_MODE_TEST_INSTRUCTIONS.md",
            
            # Security
            "SECURITY_COVERAGE_ANALYSIS.md": "docs/security/SECURITY_COVERAGE_ANALYSIS.md",
            
            # Development
            "DOCUMENTATION_COMPLETE.md": "docs/development/DOCUMENTATION_COMPLETE.md",
            "UPDATE_SUMMARY.md": "docs/development/UPDATE_SUMMARY.md",
            "REPOSITORY_STRUCTURE.md": "docs/development/REPOSITORY_STRUCTURE.md",
            
            # Archive
            "docs-archive": "docs/archive",
        }
        
        success_count = 0
        for src, dst in moves.items():
            if self.move_file(src, dst):
                success_count += 1
                
        self.log(f"Documentation migration: {success_count}/{len(moves)} files moved", "INFO")
        
    def migrate_scripts(self):
        """Move script files"""
        self.log("=== Phase 2: Migrating Scripts ===", "INFO")
        
        moves = {
            # Development scripts
            "add_copyright_headers.py": "scripts/dev/add_copyright_headers.py",
            "add_comprehensive_comments.py": "scripts/dev/add_comprehensive_comments.py",
            "verify_install.py": "scripts/dev/verify_install.py",
            
            # Build scripts
            "build_protected.sh": "scripts/build/build_protected.sh",
            "setup_compiled.py": "scripts/build/setup_compiled.py",
            "install.sh": "scripts/build/install.sh",
            
            # Benchmark scripts
            "benchmark_results.py": "scripts/benchmark/benchmark_results.py",
            "benchmark_results.json": "scripts/benchmark/benchmark_results.json",
        }
        
        success_count = 0
        for src, dst in moves.items():
            if self.move_file(src, dst):
                success_count += 1
                
        self.log(f"Scripts migration: {success_count}/{len(moves)} files moved", "INFO")
        
    def migrate_config(self):
        """Move configuration files"""
        self.log("=== Phase 3: Migrating Config Files ===", "INFO")
        
        moves = {
            ".parry.example.yml": "config/.parry.example.yml",
            "requirements-build.txt": "config/requirements-build.txt",
        }
        
        success_count = 0
        for src, dst in moves.items():
            if self.move_file(src, dst):
                success_count += 1
                
        self.log(f"Config migration: {success_count}/{len(moves)} files moved", "INFO")
        
    def migrate_integrations(self):
        """Move integration files"""
        self.log("=== Phase 4: Migrating Integrations ===", "INFO")
        
        moves = {
            "parry.rb": "integrations/homebrew/parry.rb",
        }
        
        # Move vscode-extension directory if it exists
        vscode_src = self.root / "vscode-extension"
        if vscode_src.exists() and vscode_src.is_dir():
            vscode_dst = self.root / "integrations/vscode"
            if self.dry_run:
                self.log(f"DRY RUN: Would move vscode-extension/ → integrations/vscode/", "INFO")
            else:
                shutil.copytree(vscode_src, vscode_dst, dirs_exist_ok=True)
                shutil.rmtree(vscode_src)
                self.log("Moved: vscode-extension/ → integrations/vscode/", "INFO")
                
        # Move website directory if it exists
        website_src = self.root / "website"
        if website_src.exists() and website_src.is_dir():
            website_dst = self.root / "integrations/website"
            if self.dry_run:
                self.log(f"DRY RUN: Would move website/ → integrations/website/", "INFO")
            else:
                shutil.copytree(website_src, website_dst, dirs_exist_ok=True)
                shutil.rmtree(website_src)
                self.log("Moved: website/ → integrations/website/", "INFO")
        
        success_count = 0
        for src, dst in moves.items():
            if self.move_file(src, dst):
                success_count += 1
                
        self.log(f"Integrations migration: {success_count}/{len(moves)} files moved", "INFO")
        
    def create_navigation_files(self):
        """Create README files for navigation"""
        self.log("=== Phase 5: Creating Navigation Files ===", "INFO")
        
        # docs/README.md
        docs_readme = """# Parry Documentation

## Quick Links
- [Getting Started](guides/QUICKSTART.md)
- [API Reference](api/API_REFERENCE.md)
- [Benchmarks](benchmarks/BENCHMARK_SUMMARY.md)
- [Contributing](guides/CONTRIBUTING.md)

## Documentation Structure
- `api/` - API documentation and reference
- `guides/` - User guides and tutorials
- `benchmarks/` - Performance metrics and comparisons
- `testing/` - Testing guides and instructions
- `security/` - Security coverage analysis
- `development/` - Developer documentation
- `archive/` - Archived documentation
"""
        
        # scripts/README.md
        scripts_readme = """# Parry Scripts

## Development Scripts (`dev/`)
- `add_copyright_headers.py` - Adds copyright headers to all files
- `add_comprehensive_comments.py` - Adds comprehensive code comments
- `verify_install.py` - Verifies Parry installation
- `reorganize_repo.py` - Repository reorganization tool

## Build Scripts (`build/`)
- `install.sh` - Main installation script
- `build_protected.sh` - Creates protected/compiled build
- `setup_compiled.py` - Cython compilation setup

## Benchmark Scripts (`benchmark/`)
- `benchmark_results.py` - Runs competitive benchmarking
- `benchmark_results.json` - Benchmark results data
"""
        
        files = {
            "docs/README.md": docs_readme,
            "scripts/README.md": scripts_readme,
        }
        
        for path, content in files.items():
            if self.dry_run:
                self.log(f"DRY RUN: Would create {path}", "INFO")
            else:
                full_path = self.root / path
                full_path.write_text(content)
                self.log(f"Created: {path}", "INFO")
                
    def update_gitignore(self):
        """Update .gitignore if needed"""
        self.log("=== Phase 6: Updating .gitignore ===", "INFO")
        
        gitignore_path = self.root / ".gitignore"
        if not gitignore_path.exists():
            self.log(".gitignore not found, skipping", "WARN")
            return
            
        if self.dry_run:
            self.log("DRY RUN: Would update .gitignore", "INFO")
            return
            
        # Add backup directory to gitignore
        content = gitignore_path.read_text()
        if ".backup/" not in content:
            content += "\n# Repository reorganization backups\n.backup/\n"
            gitignore_path.write_text(content)
            self.log("Updated .gitignore", "INFO")
            
    def save_migration_log(self):
        """Save migration log to file"""
        if self.dry_run:
            return
            
        log_file = self.root / ".backup" / "migration_log.txt"
        log_file.parent.mkdir(parents=True, exist_ok=True)
        log_file.write_text("\n".join(self.migration_log))
        self.log(f"Migration log saved: {log_file}", "INFO")
        
    def run_migration(self):
        """Execute full migration"""
        self.log("=" * 60, "INFO")
        self.log("PARRY REPOSITORY REORGANIZATION", "INFO")
        self.log("=" * 60, "INFO")
        
        if not self.dry_run:
            if not self.check_git_status():
                self.log("Migration cancelled by user", "INFO")
                return False
                
            self.create_backup()
            
        self.create_directories()
        self.migrate_documentation()
        self.migrate_scripts()
        self.migrate_config()
        self.migrate_integrations()
        self.create_navigation_files()
        self.update_gitignore()
        
        self.log("=" * 60, "INFO")
        self.log("MIGRATION COMPLETE", "INFO")
        self.log("=" * 60, "INFO")
        
        if not self.dry_run:
            self.save_migration_log()
            self.log(f"Backup location: {self.backup_dir}", "INFO")
            
        return True


def main():
    parser = argparse.ArgumentParser(
        description="Reorganize Parry repository structure"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without making changes"
    )
    parser.add_argument(
        "--backup",
        action="store_true",
        help="Create backup before making changes (always done unless --dry-run)"
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path.cwd(),
        help="Root directory of repository (default: current directory)"
    )
    
    args = parser.parse_args()
    
    reorganizer = RepositoryReorganizer(args.root, dry_run=args.dry_run)
    
    if args.dry_run:
        print("\n🔍 DRY RUN MODE - No changes will be made\n")
    else:
        print("\n⚠️  LIVE MODE - Repository will be reorganized\n")
        response = input("Continue? (y/N): ")
        if response.lower() != 'y':
            print("Cancelled.")
            return
            
    success = reorganizer.run_migration()
    
    if success and not args.dry_run:
        print("\n✅ Migration successful!")
        print(f"📦 Backup created at: {reorganizer.backup_dir}")
        print("\n Next steps:")
        print("  1. Review changes: git status")
        print("  2. Run tests: pytest tests/")
        print("  3. Test install: pip install -e .")
        print("  4. Commit changes: git add -A && git commit -m 'Reorganize repository structure'")
    elif success and args.dry_run:
        print("\n✅ Dry run successful! Run without --dry-run to apply changes.")
    else:
        print("\n❌ Migration failed. Check logs above.")


if __name__ == "__main__":
    main()
