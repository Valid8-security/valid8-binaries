#!/usr/bin/env python3
"""
Script to organize and declutter the repository structure
"""
import os
import shutil
from pathlib import Path

def organize_repository():
    """Organize repository by moving files to appropriate directories"""
    project_root = Path(__file__).parent.parent
    
    # Create organization directories
    docs_dir = project_root / 'docs'
    archive_dir = project_root / 'archive'
    scripts_dir = project_root / 'scripts'
    
    docs_dir.mkdir(exist_ok=True)
    archive_dir.mkdir(exist_ok=True)
    
    # Files to move to docs/
    docs_files = [
        '*.md',  # All markdown files (except README.md)
        'DEPLOYMENT*.md',
        'FIX_*.md',
        'GUIDE*.md',
        'SETUP*.md',
        'INSTALLATION*.md',
        'CODE_SIGNING*.md',
        'STRIPE*.md',
        'QUICK*.md',
        'FREE*.md',
        'SYSTEM_PROMPT*.md',
        'RESEARCH_PAPERS.md',
    ]
    
    # Files to archive (old/unused)
    archive_patterns = [
        '*.backup',
        '*.broken',
        '*.old',
        '*_test_results.json',
        'component_test_results.json',
    ]
    
    # Keep in root
    keep_in_root = [
        'README.md',
        'LICENSE',
        'PROPRIETARY_LICENSE.md',
        'CONTRIBUTING.md',
        'requirements.txt',
        'setup.py',
        'pyproject.toml',
        'package.json',
        'vercel.json',
        '.vercelignore',
    ]
    
    print("📁 Organizing repository...")
    
    # Move documentation files
    moved_count = 0
    for pattern in docs_files:
        for file in project_root.glob(pattern):
            if file.name in keep_in_root:
                continue
            if file.is_file() and file.suffix == '.md':
                try:
                    dest = docs_dir / file.name
                    if not dest.exists():
                        shutil.move(str(file), str(dest))
                        print(f"  📄 Moved {file.name} → docs/")
                        moved_count += 1
                except Exception as e:
                    print(f"  ⚠️  Could not move {file.name}: {e}")
    
    print(f"\n✅ Moved {moved_count} documentation files to docs/")
    print("\n💡 Recommendation: Review docs/ and organize further if needed")

if __name__ == '__main__':
    organize_repository()




