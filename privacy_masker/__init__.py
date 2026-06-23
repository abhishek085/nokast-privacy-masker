"""Privacy Hook (nokast-privacy-masker): a privacy-first CLI for builders.

Scans text and clipboard content for sensitive data (emails, API keys, passwords,
phone numbers, SSNs, credit cards and custom keywords) and replaces it with safe
placeholder tokens before you paste into an AI tool. Fully local; nothing leaves
your machine.
"""

from .config import Config
from .masker import MaskResult, Masker

__version__ = "0.1.0"

__all__ = ["Config", "Masker", "MaskResult", "__version__"]
