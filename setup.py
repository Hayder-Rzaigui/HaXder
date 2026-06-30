from setuptools import setup, find_packages

setup(
    name="haxder",
    version="0.3.0",
    author="Hayder Rzaigui",
    description="A modular and extensible Passive Subdomain Enumeration & DNS Validation Tool",
    long_description=open("README.md").read() if open("README.md") else "",
    long_description_content_type="text/markdown",
    packages=find_packages(),
    install_requires=[
        "aiohttp>=3.8.0",
        "aiodns>=3.0.0",
        "rich>=13.0.0",
        "tenacity>=8.2.0",
        "PyYAML>=6.0",
        "beautifulsoup4>=4.12.0",
        "lxml>=4.9.0",
    ],
    entry_points={
        "console_scripts": [
            "haxder=haxder.cli:main",
        ],
    },
    python_requires=">=3.8",
)
