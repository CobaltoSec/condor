"""Condor — Agentic AI security testing framework (OWASP ASI Top 10)."""
from importlib.metadata import version, PackageNotFoundError

try:
    __version__ = version("cobaltosec-condor")
except PackageNotFoundError:
    __version__ = "0.1.0"

__all__ = ["__version__"]
