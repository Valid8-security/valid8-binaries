# Parry (C) by Lemonade Stand. Written by Andy Kurapati and Shreyan Mitra
"""
Setup script for Parry Security Scanner (development/standard build)
This file configures the package for installation via pip and distribution via PyPI.
It defines dependencies, metadata, and entry points for the command-line interface.
"""
# Import Path for file system path manipulation
from pathlib import Path
# Import setup function and find_packages utility from setuptools for package configuration
from setuptools import setup, find_packages

# Read requirements from the requirements.txt file
def read_requirements():
    """
    Read requirements from requirements.txt file
    
    Returns:
        List of requirement strings for package dependencies
    """
    # Create a Path object pointing to the requirements.txt file
    req_file = Path('requirements.txt')
    # Check if the requirements file exists in the current directory
    if req_file.exists():
        # Read the file contents, split into lines, filter out empty lines and comments
        return [line.strip() for line in req_file.read_text().splitlines() 
                if line.strip() and not line.startswith('#')]
    # Return empty list if requirements file doesn't exist
    return []

# Read README file for use as the long description in package metadata
def read_readme():
    """
    Read README.md file for long description
    
    Returns:
        String containing the README content for PyPI display
    """
    # Create a Path object pointing to the README.md file
    readme_file = Path('README.md')
    # Check if the README file exists
    if readme_file.exists():
        # Read and return the entire README content
        return readme_file.read_text()
    # Return a default description if README doesn't exist
    return "Parry Security Scanner - Privacy-first AI-powered security scanning"

# Call setup function to configure the package
setup(
    # Package name as it will appear on PyPI
    name='parry-scanner',
    # Version number following semantic versioning (MAJOR.MINOR.PATCH)
    version='0.7.0',
    # Short one-line description of the package
    description='Privacy-first AI-powered security scanner with 90.9% recall',
    # Long description from README for detailed PyPI page
    long_description=read_readme(),
    # Specify that long description is in Markdown format
    long_description_content_type='text/markdown',
    # Author name for package metadata
    author='Parry Security',
    # Contact email for package maintainers
    author_email='security@parry.dev',
    # Project homepage URL
    url='https://github.com/parry/parry',
    # Automatically find all packages in the directory, excluding test and build artifacts
    packages=find_packages(exclude=['tests', 'tests.*', 'venv', '*.egg-info']),
    # List of dependencies required to run the package
    install_requires=read_requirements(),
    # Define command-line scripts that will be installed
    entry_points={
        'console_scripts': [
            # Creates 'parry' command that calls the main() function in cli.py
            'parry=parry.cli:main',
        ],
    },
    # PyPI classifiers for categorizing the package
    classifiers=[
        # Development status indicating beta release
        'Development Status :: 4 - Beta',
        # Target audience: software developers
        'Intended Audience :: Developers',
        # Target audience: system administrators
        'Intended Audience :: System Administrators',
        # Category: security tools
        'Topic :: Security',
        # Category: code quality assurance
        'Topic :: Software Development :: Quality Assurance',
        # Category: testing tools
        'Topic :: Software Development :: Testing',
        # License type: MIT open source license
        'License :: OSI Approved :: MIT License',
        # Programming language: Python 3
        'Programming Language :: Python :: 3',
        # Supported Python version: 3.8
        'Programming Language :: Python :: 3.8',
        # Supported Python version: 3.9
        'Programming Language :: Python :: 3.9',
        # Supported Python version: 3.10
        'Programming Language :: Python :: 3.10',
        # Supported Python version: 3.11
        'Programming Language :: Python :: 3.11',
        # Supported Python version: 3.12
        'Programming Language :: Python :: 3.12',
        # Supported Python version: 3.13
        'Programming Language :: Python :: 3.13',
        # Works on any operating system
        'Operating System :: OS Independent',
    ],
    # Minimum Python version required to run the package
    python_requires='>=3.8',
    # Include non-Python files specified in MANIFEST.in
    include_package_data=True,
    # Don't create a zip archive, install as regular files
    zip_safe=False,
    # Keywords for PyPI search functionality
    keywords='security scanning vulnerability detection static analysis sast ai llm',
    # Additional project URLs for documentation and issue tracking
    project_urls={
        # Link to documentation website
        'Documentation': 'https://parry.dev/docs',
        # Link to source code repository
        'Source': 'https://github.com/parry/parry',
        # Link to issue tracker
        'Tracker': 'https://github.com/parry/parry/issues',
    },
)

