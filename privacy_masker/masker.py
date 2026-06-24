"""The masking engine: turn sensitive text into a safe-to-paste version.

This is the heart of the tool and is deliberately free of any OS / clipboard /
hotkey concerns so it can be unit-tested in isolation and reused from a CLI, a
menu-bar app, or anywhere else.

Usage::

    from privacy_masker.config import Config
    from privacy_masker.masker import Masker

    masker = Masker(Config.load())
    result = masker.mask("email me at jane@corp.com")
    print(result.text)      # "email me at [EMAIL]"
    print(result.summary()) # "1 email"
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable

from . import detectors, patterns
from .config import Config
from .detectors import NerUnavailable, PresidioNerDetector
from .patterns import Finding, Pattern


# Human-readable singular/plural labels for findings reports.
_CATEGORY_LABELS = {
    patterns.EMAIL: ("email", "emails"),
    patterns.SECRET: ("secret", "secrets"),
    patterns.PHONE: ("phone number", "phone numbers"),
    patterns.SSN: ("SSN", "SSNs"),
    patterns.CREDIT_CARD: ("card number", "card numbers"),
    patterns.IP: ("IP address", "IP addresses"),
    patterns.KEYWORD: ("keyword", "keywords"),
    patterns.PERSON: ("name", "names"),
    patterns.LOCATION: ("location", "locations"),
    patterns.ORG: ("organisation", "organisations"),
    patterns.DATE: ("date", "dates"),
}


@dataclass
class MaskResult:
    """The outcome of masking a piece of text."""

    text: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(self.findings)

    def counts(self) -> dict[str, int]:
        """Number of redactions per category."""

        return dict(Counter(f.category for f in self.findings))

    def summary(self) -> str:
        """A short human-readable summary, e.g. ``2 emails, 1 secret``.

        Returns an empty string when nothing was redacted.
        """

        counts = self.counts()
        if not counts:
            return ""
        parts = []
        for category, count in counts.items():
            singular, plural = _CATEGORY_LABELS.get(category, (category, category))
            parts.append(f"{count} {singular if count == 1 else plural}")
        return ", ".join(parts)


class Masker:
    """Applies the active patterns and keywords to text."""

    def __init__(self, config: Config | None = None):
        self.config = config or Config()
        self._compile()

    def _compile(self) -> None:
        """Collect the active detectors for the current config.

        Sets ``self._detectors`` (regex patterns + custom keywords + an optional
        Presidio NER detector) and ``self.ner_status`` -- one of ``"off"`` (no NER
        categories enabled), ``"active"``, or a ``NerUnavailable.reason``
        (``"no_presidio"`` / ``"no_model"``) so the CLI can guide the user.
        """

        active: list = []
        # Iterate in a fixed category order so collection (and thus tie-breaking
        # between equal spans) is deterministic regardless of set ordering.
        for category in patterns.ALL_CATEGORIES:
            if category in self.config.enabled_categories:
                active.extend(patterns.BUILTIN_PATTERNS.get(category, []))
        # Custom keywords (only if the keyword category is enabled).
        if patterns.KEYWORD in self.config.enabled_categories:
            for keyword in self.config.keywords:
                if keyword.strip():
                    active.append(patterns.keyword_pattern(keyword))

        # Optional NER detector for contextual PII (names, places, ...).
        self.ner_status = "off"
        enabled_ner = self.config.enabled_categories & set(patterns.NER_CATEGORIES)
        if enabled_ner:
            try:
                active.append(PresidioNerDetector(enabled_ner))
                self.ner_status = "active"
            except NerUnavailable as exc:
                # Regex masking still works; record why NER is inert.
                self.ner_status = exc.reason
                self.ner_message = str(exc)

        self._detectors = active

    def _replacement(self, category: str) -> str:
        return self.config.replacements.get(
            category, patterns.KEYWORD
        )

    def _collect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for detector in self._detectors:
            findings.extend(detector.finditer(text))
        return findings

    # When two findings cover the exact same span, the more sensitive label
    # wins (lower number = higher priority).
    _PRIORITY = {
        patterns.SECRET: 0,
        patterns.CREDIT_CARD: 1,
        patterns.SSN: 2,
        patterns.KEYWORD: 3,
        patterns.EMAIL: 4,
        patterns.IP: 5,
        patterns.PHONE: 6,
        # NER (contextual) findings yield to structured regex matches on a tie.
        patterns.PERSON: 7,
        patterns.LOCATION: 8,
        patterns.ORG: 9,
        patterns.DATE: 10,
    }

    @classmethod
    def _resolve_overlaps(cls, findings: Iterable[Finding]) -> list[Finding]:
        """Drop overlapping findings, keeping the earliest then longest.

        When two detectors match overlapping spans (e.g. an email inside a
        ``secret = jane@corp.com`` assignment), redacting both would corrupt the
        output. We sort by start position, then by *longest* span, then by
        category priority, and greedily keep non-overlapping findings.
        """

        ordered = sorted(
            findings,
            key=lambda f: (f.start, -(f.end - f.start), cls._PRIORITY.get(f.category, 99)),
        )
        kept: list[Finding] = []
        last_end = -1
        for finding in ordered:
            if finding.start >= last_end:
                kept.append(finding)
                last_end = finding.end
        return kept

    def find(self, text: str) -> list[Finding]:
        """Return the resolved, non-overlapping sensitive spans in ``text``.

        This is the detection half of :meth:`mask`, exposed so other consumers
        (e.g. the reversible vault) can reuse the exact same detectors and
        overlap resolution without committing to a particular replacement.
        Findings come back in ascending, non-overlapping order.
        """

        if not text:
            return []
        return self._resolve_overlaps(self._collect(text))

    def mask(self, text: str) -> MaskResult:
        """Return a :class:`MaskResult` with sensitive spans replaced."""

        findings = self.find(text)
        if not findings:
            return MaskResult(text=text, findings=[])

        # Rebuild the string, splicing in replacement tokens. Findings are in
        # ascending, non-overlapping order after resolution.
        pieces: list[str] = []
        cursor = 0
        for finding in findings:
            pieces.append(text[cursor:finding.start])
            pieces.append(self._replacement(finding.category))
            cursor = finding.end
        pieces.append(text[cursor:])

        return MaskResult(text="".join(pieces), findings=findings)
