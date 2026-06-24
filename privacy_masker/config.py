"""User configuration for the privacy masker.

The config is a small JSON file stored under the platform config directory
(``~/Library/Application Support/nokast-privacy-masker`` on macOS). It controls
which categories are active, the replacement token used for each category, and
the custom keyword list.

Everything has a sane default, so a missing or partial config file still works.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

from . import patterns

APP_NAME = "nokast-privacy-masker"

# Default replacement token per category. Labelled tokens (rather than a bare
# "XXX") let the AI on the other end still understand the *shape* of the text --
# it knows an email used to be there without seeing the address.
DEFAULT_REPLACEMENTS: dict[str, str] = {
    patterns.EMAIL: "[EMAIL]",
    patterns.SECRET: "[SECRET]",
    patterns.PHONE: "[PHONE]",
    patterns.SSN: "[SSN]",
    patterns.CREDIT_CARD: "[CARD]",
    patterns.IP: "[IP]",
    patterns.KEYWORD: "[REDACTED]",
    patterns.PERSON: "[NAME]",
    patterns.LOCATION: "[LOCATION]",
    patterns.ORG: "[ORG]",
    patterns.DATE: "[DATE]",
}


def default_config_dir() -> Path:
    """Return the directory where the config file lives, honouring overrides."""

    override = os.environ.get("PRIVACY_MASKER_CONFIG_DIR")
    if override:
        return Path(override).expanduser()
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / APP_NAME
    # Linux / other: respect XDG.
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg).expanduser() if xdg else Path.home() / ".config"
    return base / APP_NAME


@dataclass
class Config:
    """Runtime configuration for the masker."""

    enabled_categories: set[str] = field(
        default_factory=lambda: set(patterns.DEFAULT_ENABLED)
    )
    replacements: dict[str, str] = field(
        default_factory=lambda: dict(DEFAULT_REPLACEMENTS)
    )
    keywords: list[str] = field(default_factory=list)

    # -- serialisation ----------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "enabled_categories": sorted(self.enabled_categories),
            "replacements": self.replacements,
            "keywords": self.keywords,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Config":
        cfg = cls()
        if isinstance(data.get("enabled_categories"), list):
            cfg.enabled_categories = {
                c for c in data["enabled_categories"] if c in patterns.ALL_CATEGORIES
            }
        if isinstance(data.get("replacements"), dict):
            # Start from defaults so a partial map still covers every category.
            merged = dict(DEFAULT_REPLACEMENTS)
            merged.update({k: str(v) for k, v in data["replacements"].items()})
            cfg.replacements = merged
        if isinstance(data.get("keywords"), list):
            cfg.keywords = [str(k) for k in data["keywords"] if str(k).strip()]
        return cfg

    # -- persistence ------------------------------------------------------

    @classmethod
    def path(cls) -> Path:
        return default_config_dir() / "config.json"

    @classmethod
    def load(cls) -> "Config":
        """Load config from disk, falling back to defaults on any problem."""

        path = cls.path()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return cls()
        if not isinstance(data, dict):
            return cls()
        return cls.from_dict(data)

    def save(self) -> Path:
        """Persist config to disk, creating the directory if needed."""

        path = self.path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.to_dict(), indent=2) + "\n", encoding="utf-8"
        )
        return path
