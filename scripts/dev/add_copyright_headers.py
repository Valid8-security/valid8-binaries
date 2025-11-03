# Parry (C) by Lemonade Stand. Written by Andy Kurapati and Shreyan Mitra
"""
Copyright Header Addition Script

This script automatically adds copyright headers to all Python and JavaScript files
in the Parry Security Scanner repository. It processes each file, checks if it already
has the copyright header, and adds it if missing.
"""

# Import Path for file system operations
from pathlib import Path
# Import regular expressions for pattern matching
import re
# Import sys for system-specific parameters and functions
import sys

# Define the copyright header that will be added to all Python files
COPYRIGHT_HEADER_PYTHON = "# Parry (C) by Lemonade Stand. Written by Andy Kurapati and Shreyan Mitra\n"

# Define the copyright header that will be added to all JavaScript files
COPYRIGHT_HEADER_JS = "// Parry (C) by Lemonade Stand. Written by Andy Kurapati and Shreyan Mitra\n"


def has_copyright_header(content, language):
    """
    Check if the file already contains the copyright header
    
    Args:
        content: The complete file content as a string
        language: The programming language ('python' or 'javascript')
    
    Returns:
        Boolean indicating whether the copyright header is already present
    """
    # Check for the presence of the copyright text in the file content
    return "Parry (C) by Lemonade Stand" in content


def add_copyright_to_python_file(file_path):
    """
    Add copyright header to a Python file if it doesn't already have one
    
    Args:
        file_path: Path object pointing to the Python file to process
    
    Returns:
        Boolean indicating whether the file was modified
    """
    # Read the entire file content into memory
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Check if the copyright header already exists
    if has_copyright_header(content, 'python'):
        # Print a message indicating the file already has the header
        print(f"✓ {file_path} already has copyright header")
        # Return False to indicate no modification was made
        return False
    
    # Check if file starts with a shebang line (#!/usr/bin/env python3)
    if content.startswith('#!'):
        # Find the end of the first line (the shebang line)
        first_newline = content.find('\n')
        # Extract the shebang line including the newline
        shebang = content[:first_newline + 1]
        # Extract the rest of the content after the shebang
        rest = content[first_newline + 1:]
        # Construct new content: shebang + copyright + rest
        new_content = shebang + COPYRIGHT_HEADER_PYTHON + rest
    else:
        # If no shebang, simply prepend the copyright header
        new_content = COPYRIGHT_HEADER_PYTHON + content
    
    # Write the modified content back to the file
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(new_content)
    
    # Print success message showing which file was updated
    print(f"✓ Added copyright to {file_path}")
    # Return True to indicate the file was modified
    return True


def add_copyright_to_js_file(file_path):
    """
    Add copyright header to a JavaScript file if it doesn't already have one
    
    Args:
        file_path: Path object pointing to the JavaScript file to process
    
    Returns:
        Boolean indicating whether the file was modified
    """
    # Read the entire file content into memory
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Check if the copyright header already exists
    if has_copyright_header(content, 'javascript'):
        # Print a message indicating the file already has the header
        print(f"✓ {file_path} already has copyright header")
        # Return False to indicate no modification was made
        return False
    
    # Simply prepend the copyright header to the content
    new_content = COPYRIGHT_HEADER_JS + content
    
    # Write the modified content back to the file
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(new_content)
    
    # Print success message showing which file was updated
    print(f"✓ Added copyright to {file_path}")
    # Return True to indicate the file was modified
    return True


def process_repository(repo_path):
    """
    Process all Python and JavaScript files in the repository
    
    Args:
        repo_path: Path object pointing to the root of the repository
    """
    # Initialize counter for modified Python files
    python_modified = 0
    # Initialize counter for modified JavaScript files
    js_modified = 0
    
    # Print header message indicating the start of processing
    print("=" * 80)
    print("Processing Python files...")
    print("=" * 80)
    
    # Find all Python files recursively using glob pattern
    for py_file in repo_path.rglob('*.py'):
        # Process each Python file and add copyright if needed
        if add_copyright_to_python_file(py_file):
            # Increment counter if file was modified
            python_modified += 1
    
    # Print header message for JavaScript file processing
    print("\n" + "=" * 80)
    print("Processing JavaScript files...")
    print("=" * 80)
    
    # Find all JavaScript files recursively using glob pattern
    for js_file in repo_path.rglob('*.js'):
        # Process each JavaScript file and add copyright if needed
        if add_copyright_to_js_file(js_file):
            # Increment counter if file was modified
            js_modified += 1
    
    # Print summary statistics showing how many files were modified
    print("\n" + "=" * 80)
    print("Summary:")
    print("=" * 80)
    # Display count of Python files modified
    print(f"Python files modified: {python_modified}")
    # Display count of JavaScript files modified
    print(f"JavaScript files modified: {js_modified}")
    # Display total count of all files modified
    print(f"Total files modified: {python_modified + js_modified}")


# Main execution block that runs when script is executed directly
if __name__ == "__main__":
    # Get the current directory where the script is located
    repo_path = Path(__file__).parent
    # Print message indicating which directory will be processed
    print(f"Processing repository at: {repo_path}")
    # Call the main processing function to add copyright headers
    process_repository(repo_path)
    # Print completion message
    print("\nDone!")
