"""
Setup script for Parry Security Scanner (development/standard build)
"""
from pathlib import Path
from setuptools import setup, find_packages

# Read requirements
def read_requirements():
    """Read requirements from file"""
    req_file = Path('requirements.txt')
    if req_file.exists():
        return [line.strip() for line in req_file.read_text().splitlines() 
                if line.strip() and not line.startswith('#')]
    return []

# Read README
def read_readme():
    """Read README for long description"""
    readme_file = Path('README.md')
    if readme_file.exists():
        return readme_file.read_text()
    return "Parry Security Scanner - Privacy-first AI-powered security scanning"

setup(
    name='parry-scanner',
    version='0.7.0',
    description='Privacy-first AI-powered security scanner with 90.9% recall',
    long_description=read_readme(),
    long_description_content_type='text/markdown',
    author='Parry Security',
    author_email='security@parry.dev',
    url='https://github.com/parry/parry',
    packages=find_packages(exclude=['tests', 'tests.*', 'venv', '*.egg-info']),
    install_requires=read_requirements(),
    entry_points={
        'console_scripts': [
            'parry=parry.cli:main',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Topic :: Security',
        'Topic :: Software Development :: Quality Assurance',
        'Topic :: Software Development :: Testing',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Programming Language :: Python :: 3.13',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.8',
    include_package_data=True,
    zip_safe=False,
    keywords='security scanning vulnerability detection static analysis sast ai llm',
    project_urls={
        'Documentation': 'https://parry.dev/docs',
        'Source': 'https://github.com/parry/parry',
        'Tracker': 'https://github.com/parry/parry/issues',
    },
)

