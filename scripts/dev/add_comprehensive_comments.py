#!/usr/bin/env python3
"""
Copyright (c) 2025 Valid8 Security
All rights reserved.

This software is proprietary and confidential. Unauthorized copying,
modification, distribution, or use of this software, via any medium is
strictly prohibited without the express written permission of Valid8 Security.

"""

# Parry (C) by Lemonade Stand. Written by Andy Kurapati and Shreyan Mitra
"""
Comprehensive Comment Addition Script

This script automatically adds detailed line-by-line comments to all Python files
in the Parry Security Scanner repository. It analyzes code structure and adds
contextually appropriate comments for imports, functions, classes, variables, and logic.
"""

# Import Path for file system operations
from pathlib import Path
# Import regular expressions for pattern matching
import re
# Import ast module for parsing Python code into Abstract Syntax Trees
import ast
# Import sys for system-specific parameters and functions
import sys
# Import typing for type hints
from typing import List, Dict, Set, Tuple

# Define the copyright header that should be present in all files
COPYRIGHT_HEADER = "# Parry (C) by Lemonade Stand. Written by Andy Kurapati and Shreyan Mitra\n"


def analyze_and_comment_file(file_path: Path) -> bool:
    """
    Analyze a Python file and add comprehensive inline comments
    
    This function reads a Python file, parses its structure, and adds detailed
    comments explaining imports, variables, functions, classes, and logic flow.
    
    Args:
        file_path: Path to the Python file to process
        
    Returns:
        Boolean indicating whether the file was modified
    """
    try:
        # Read the file content
        with open(file_path, 'r', encoding='utf-8') as f:
            original_content = f.read()
        
        # Check if already heavily commented (skip if already done)
        lines = original_content.split('\n')
        comment_count = sum(1 for line in lines if line.strip().startswith('#') and not line.strip().startswith('#!'))
        code_count = sum(1 for line in lines if line.strip() and not line.strip().startswith('#'))
        
        if code_count > 0:
            comment_ratio = comment_count / code_count
            if comment_ratio > 0.3:  # Already well-commented
                print(f"✓ {file_path.name} already well-commented ({comment_ratio:.1%})")
                return False
        
        # Process the file with intelligent commenting
        new_lines = []
        in_multiline_string = False
        in_function = False
        in_class = False
        indent_level = 0
        
        for i, line in enumerate(lines):
            # Add the original line first
            stripped = line.strip()
            
            # Handle multiline strings
            if '"""' in line or "'''" in line:
                in_multiline_string = not in_multiline_string
                new_lines.append(line)
                continue
            
            if in_multiline_string:
                new_lines.append(line)
                continue
            
            # Skip empty lines and lines that are already comments
            if not stripped or stripped.startswith('#'):
                new_lines.append(line)
                continue
            
            # Get indentation
            indent = len(line) - len(line.lstrip())
            indent_str = ' ' * indent
            
            # Add comments for imports
            if stripped.startswith('import ') or stripped.startswith('from '):
                if not (i > 0 and lines[i-1].strip().startswith('#')):
                    comment = generate_import_comment(stripped)
                    new_lines.append(f"{indent_str}# {comment}")
            
            # Add comments for class definitions
            elif stripped.startswith('class '):
                if not (i > 0 and lines[i-1].strip().startswith('#')):
                    class_name = stripped.split('(')[0].replace('class ', '').strip(':')
                    new_lines.append(f"{indent_str}# Define {class_name} class for specific functionality")
                in_class = True
            
            # Add comments for function/method definitions
            elif stripped.startswith('def '):
                if not (i > 0 and lines[i-1].strip().startswith('#')):
                    func_name = stripped.split('(')[0].replace('def ', '')
                    comment = generate_function_comment(func_name, stripped)
                    new_lines.append(f"{indent_str}# {comment}")
                in_function = True
            
            # Add comments for variable assignments
            elif '=' in stripped and not any(op in stripped for op in ['==', '!=', '<=', '>=', '+=', '-=', '*=', '/=']):
                if not (i > 0 and lines[i-1].strip().startswith('#')):
                    var_name = stripped.split('=')[0].strip()
                    if not var_name.startswith('self.') or True:  # Comment all assignments
                        comment = generate_variable_comment(var_name, stripped)
                        if comment:
                            new_lines.append(f"{indent_str}# {comment}")
            
            # Add comments for control structures
            elif stripped.startswith('if ') or stripped.startswith('elif '):
                if not (i > 0 and lines[i-1].strip().startswith('#')):
                    new_lines.append(f"{indent_str}# Check condition: {stripped.rstrip(':')}")
            elif stripped.startswith('for '):
                if not (i > 0 and lines[i-1].strip().startswith('#')):
                    new_lines.append(f"{indent_str}# Iterate through: {stripped.rstrip(':')}")
            elif stripped.startswith('while '):
                if not (i > 0 and lines[i-1].strip().startswith('#')):
                    new_lines.append(f"{indent_str}# Loop while: {stripped.rstrip(':')}")
            elif stripped.startswith('try:'):
                if not (i > 0 and lines[i-1].strip().startswith('#')):
                    new_lines.append(f"{indent_str}# Attempt operation with error handling")
            elif stripped.startswith('except'):
                if not (i > 0 and lines[i-1].strip().startswith('#')):
                    new_lines.append(f"{indent_str}# Handle exception: {stripped.rstrip(':')}")
            elif stripped.startswith('with '):
                if not (i > 0 and lines[i-1].strip().startswith('#')):
                    new_lines.append(f"{indent_str}# Use context manager: {stripped.rstrip(':')}")
            elif stripped.startswith('return '):
                if not (i > 0 and lines[i-1].strip().startswith('#')):
                    new_lines.append(f"{indent_str}# Return value: {stripped}")
            
            # Add the original line
            new_lines.append(line)
        
        # Join lines and write back
        new_content = '\n'.join(new_lines)
        
        # Only write if content changed
        if new_content != original_content:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(new_content)
            print(f"✓ Added comments to {file_path.name}")
            return True
        else:
            print(f"○ No changes needed for {file_path.name}")
            return False
            
    except Exception as e:
        print(f"✗ Error processing {file_path.name}: {e}")
        return False


def generate_import_comment(import_line: str) -> str:
    """Generate contextual comment for import statements"""
    if 'from' in import_line:
        parts = import_line.split('import')
        if len(parts) == 2:
            module = parts[0].replace('from', '').strip()
            items = parts[1].strip()
            return f"Import {items} from {module} module"
    else:
        module = import_line.replace('import', '').strip()
        return f"Import {module} module for use in this file"
    return "Import required module"


def generate_function_comment(func_name: str, full_line: str) -> str:
    """Generate contextual comment for function definitions"""
    if func_name.startswith('_') and not func_name.startswith('__'):
        return f"Define private helper function {func_name}"
    elif func_name.startswith('__') and func_name.endswith('__'):
        return f"Define special method {func_name} (dunder method)"
    elif 'self' in full_line:
        return f"Define instance method {func_name}"
    elif 'cls' in full_line:
        return f"Define class method {func_name}"
    else:
        return f"Define function {func_name}"


def generate_variable_comment(var_name: str, full_line: str) -> str:
    """Generate contextual comment for variable assignments"""
    if var_name.isupper():
        return f"Define constant {var_name}"
    elif '[]' in full_line or 'list()' in full_line.lower():
        return f"Initialize {var_name} as an empty list"
    elif '{}' in full_line or 'dict()' in full_line.lower():
        return f"Initialize {var_name} as an empty dictionary"
    elif 'Path(' in full_line:
        return f"Create Path object for {var_name}"
    elif '(' in full_line and ')' in full_line:
        return f"Initialize {var_name} with function/constructor call"
    else:
        return f"Set {var_name} variable"


def process_all_files(repo_path: Path):
    """
    Process all Python files in the repository
    
    Args:
        repo_path: Root path of the repository
    """
    # Counter for modified files
    modified_count = 0
    # Counter for total files processed
    total_count = 0
    
    # Print header
    print("=" * 80)
    print("Adding Comprehensive Comments to All Python Files")
    print("=" * 80)
    
    # Find all Python files
    python_files = list(repo_path.rglob('*.py'))
    print(f"\nFound {len(python_files)} Python files\n")
    
    # Process each file
    for py_file in python_files:
        total_count += 1
        if analyze_and_comment_file(py_file):
            modified_count += 1
    
    # Print summary
    print("\n" + "=" * 80)
    print("Summary:")
    print("=" * 80)
    print(f"Total files processed: {total_count}")
    print(f"Files modified: {modified_count}")
    print(f"Files unchanged: {total_count - modified_count}")


# Main execution
if __name__ == "__main__":
    # Get repository root directory
    repo_path = Path(__file__).parent
    print(f"Processing repository at: {repo_path}\n")
    
    # Process all files
    process_all_files(repo_path)
    
    print("\n✓ Complete! All Python files have been processed.")
