#!/usr/bin/env python3
"""
Setup script for Zscaler Bulk URL Uploader
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
readme_path = Path(__file__).parent / "README.md"
long_description = readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""

# Read requirements
requirements_path = Path(__file__).parent / "requirements.txt"
requirements = []
if requirements_path.exists():
    with open(requirements_path) as f:
        requirements = [
            line.strip() 
            for line in f 
            if line.strip() and not line.startswith('#') and not line.startswith('pytest')
        ]

setup(
    name="zscaler-bulk-url-uploader",
    version="1.0.0",
    author="GitHub Community",
    author_email="your-email@example.com",
    description="Bulk upload URLs to Zscaler Internet Access custom URL categories",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/dunwright/zscaler-bulk-url-uploader",
    project_urls={
        "Bug Tracker": "https://github.com/dunwright/zscaler-bulk-url-uploader/issues",
        "Documentation": "https://dunwright.github.io/zscaler-bulk-url-uploader/",
        "Source Code": "https://github.com/dunwright/zscaler-bulk-url-uploader",
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
        "Topic :: Utilities",
    ],
    packages=find_packages(),
    python_requires=">=3.7",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=22.0.0",
            "flake8>=5.0.0",
            "mypy>=1.0.0",
            "pre-commit>=3.0.0",
        ],
        "docs": [
            "sphinx>=5.0.0",
            "sphinx-rtd-theme>=1.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "zscaler-uploader=zscaler_bulk_uploader:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["*.yaml", "*.yml", "*.md", "*.txt"],
    },
    keywords=[
        "zscaler",
        "url",
        "bulk",
        "upload",
        "security",
        "api",
        "automation",
        "zia",
        "internet-access",
    ],
    zip_safe=False,
)
