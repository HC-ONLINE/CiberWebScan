"""
CiberWebScan: initialization module.
Defines package-level metadata.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("ciberwebscan")
except PackageNotFoundError:
    __version__ = "2.14.0"
__author__ = "Andrés Henríquez (a.k.a. HC-ONLINE)"
__email__ = "henriquezandres856@gmail.com"
__description__ = "Hybrid tool for passive reconnaissance and attack surface analysis in web applications. It combines advanced scraping, technology fingerprinting, security assessment, and reporting into a single CLI solution. Designed for ethical, educational, and auditing purposes. This software MUST NOT be used on third-party systems."
__license__ = "Apache License 2.0"
__url__ = "https://github.com/HC-ONLINE/CiberWebScan"

__all__ = [
    "__version__",
    "__author__",
    "__email__",
    "__description__",
    "__license__",
    "__url__",
]
