#!/usr/bin/env python3
"""
Script to add copyright headers to all Python source files
"""
import os
import re
from pathlib import Path

COPYRIGHT_HEADER = """Copyright (c) 2025 Valid8 Security
All rights reserved.

This software is proprietary and confidential. Unauthorized copying,
modification, distribution, or use of this software, via any medium is
strictly prohibited without the express written permission of Valid8 Security.
"""

def get_copyright_block(file_path: str) -> str:
    """Generate copyright block for a file"""
    return f"""#!/usr/bin/env python3
\"\"\"
{COPYRIGHT_HEADER}
\"\"\"

"""

def has_copyright_header(content: str) -> bool:
    """Check if file already has copyright header"""
    return "Copyright (c) 2025 Valid8 Security" in content or "Copyright (c) 2025 Parry Security" in content

def add_copyright_to_file(file_path: Path) -> bool:
    """Add copyright header to a Python file"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Skip if already has copyright
        if has_copyright_header(content):
            return False
        
        # Check if file starts with shebang
        has_shebang = content.startswith('#!/usr/bin/env python')
        
        # Check if file starts with docstring
        has_docstring = content.strip().startswith('"""') or content.strip().startswith("'''")
        
        # Generate new content
        if has_shebang:
            # File has shebang, add copyright after it
            lines = content.split('\n')
            new_content = lines[0] + '\n'
            new_content += get_copyright_block(str(file_path)).split('\n', 1)[1]  # Skip shebang from template
            new_content += '\n'.join(lines[1:])
        elif has_docstring:
            # File has docstring, add copyright before it
            new_content = get_copyright_block(str(file_path))
            new_content += content
        else:
            # No shebang or docstring, add both
            new_content = get_copyright_block(str(file_path))
            new_content += content
        
        # Write back
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(new_content)
        
        return True
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return False

def main():
    """Add copyright headers to all Python files"""
    project_root = Path(__file__).parent.parent
    valid8_dir = project_root / 'valid8'
    
    # Directories to process
    dirs_to_process = [
        valid8_dir,
        project_root / 'api',
        project_root / 'scripts',
    ]
    
    # Exclude patterns
    exclude_patterns = [
        '__pycache__',
        '.git',
        'venv',
        '.venv',
        'node_modules',
        'dist',
        'build',
        '.test_venv',
    ]
    
    files_processed = 0
    files_skipped = 0
    
    for directory in dirs_to_process:
        if not directory.exists():
            continue
        
        for py_file in directory.rglob('*.py'):
            # Skip excluded paths
            if any(exclude in str(py_file) for exclude in exclude_patterns):
                continue
            
            if add_copyright_to_file(py_file):
                print(f"✅ Added copyright to: {py_file.relative_to(project_root)}")
                files_processed += 1
            else:
                files_skipped += 1
    
    print(f"\n📊 Summary:")
    print(f"   Files processed: {files_processed}")
    print(f"   Files skipped (already have copyright): {files_skipped}")

if __name__ == '__main__':
    main()




