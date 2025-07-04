#!/usr/bin/env python3
"""
FuzzMaster Setup Configuration
Installation script for FuzzMaster fuzzing tool
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
readme_path = Path(__file__).parent / "README.md"
long_description = readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""

# Read requirements
requirements_path = Path(__file__).parent / "requirements.txt"
requirements = []
if requirements_path.exists():
    with open(requirements_path, 'r') as f:
        requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]

setup(
    name="fuzzmaster",
    version="1.0.0",
    author="FuzzMaster Team",
    author_email="info@fuzzmaster.com",
    description="Advanced Web Fuzzing Automation Tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/fuzzmaster/fuzzmaster",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Software Development :: Testing",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=6.0",
            "pytest-cov>=2.0",
            "black>=21.0",
            "flake8>=3.8",
            "mypy>=0.800",
        ],
        "full": [
            "matplotlib>=3.3",
            "pandas>=1.3",
            "numpy>=1.20",
            "scikit-learn>=1.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "fuzzmaster=fuzzmaster.main:main",
            "fuzzmaster-cli=fuzzmaster.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "fuzzmaster": [
            "wordlists/*.txt",
            "profiles/*.yaml",
            "templates/*.html",
            "templates/*.txt",
            "config.yaml",
        ],
    },
    zip_safe=False,
    keywords="fuzzing, web security, penetration testing, security testing, web application security",
    project_urls={
        "Bug Reports": "https://github.com/fuzzmaster/fuzzmaster/issues",
        "Source": "https://github.com/fuzzmaster/fuzzmaster",
        "Documentation": "https://fuzzmaster.readthedocs.io/",
    },
)
