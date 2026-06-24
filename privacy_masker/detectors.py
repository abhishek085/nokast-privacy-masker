"""Pluggable detectors beyond regex.

The masking engine doesn't care *how* a sensitive span is found -- only that it
gets :class:`~privacy_masker.patterns.Finding` objects with character offsets. A
:class:`Pattern` (regex) is one detector; this module adds an NER-based detector
that catches contextual PII -- names, places, organisations, dates -- which have
no fixed shape and so can't be matched by regex alone.

The NER detector is backed by **Microsoft Presidio** (open source, MIT), which
wraps a spaCy model with context-aware scoring. Presidio can recognise many more
entity types itself, but here we deliberately restrict it to the *contextual*
categories (person/location/org/date) and let our own regex handle the
structured ones (email, secrets, phone, SSN, card, IP) -- one detector per job.

Everything runs **fully locally**. It is an optional dependency: install with
``pip install 'nokast-privacy-masker[ner]'`` and download a model with
``python -m spacy download en_core_web_sm``. When Presidio or the model is
missing, the rest of the masker keeps working and reports the NER status so the
CLI can nudge the user.
"""

from __future__ import annotations

from typing import Iterable, Protocol, runtime_checkable

from . import patterns
from .patterns import Finding


@runtime_checkable
class Detector(Protocol):
    """Anything that can find sensitive spans in text.

    Both :class:`~privacy_masker.patterns.Pattern` and :class:`PresidioNerDetector`
    satisfy this -- the engine treats them uniformly.
    """

    def finditer(self, text: str) -> Iterable[Finding]:  # pragma: no cover - protocol
        ...


# Map Presidio entity types to our categories (and back, to request only what we
# need from the analyzer).
PRESIDIO_ENTITY_MAP = {
    "PERSON": patterns.PERSON,
    "LOCATION": patterns.LOCATION,
    "ORGANIZATION": patterns.ORG,
    "DATE_TIME": patterns.DATE,
}
CATEGORY_TO_PRESIDIO = {v: k for k, v in PRESIDIO_ENTITY_MAP.items()}

DEFAULT_MODEL = "en_core_web_sm"
# Presidio scores 0-1; drop low-confidence matches to limit false positives.
DEFAULT_MIN_SCORE = 0.4


class NerUnavailable(Exception):
    """Raised when an NER detector cannot be constructed.

    ``reason`` is a stable machine-readable token (``"no_presidio"`` or
    ``"no_model"``) the CLI can turn into an actionable hint.
    """

    def __init__(self, reason: str, message: str):
        super().__init__(message)
        self.reason = reason


# Presidio's AnalyzerEngine is expensive to build (loads the model), so cache it
# by model name across Masker rebuilds (e.g. when the user toggles a category).
_ANALYZER_CACHE: dict = {}


def load_analyzer(model_name: str = DEFAULT_MODEL):
    """Build (and cache) a Presidio AnalyzerEngine bound to ``model_name``.

    Raises :class:`NerUnavailable` if Presidio isn't installed or the spaCy model
    can't be loaded.
    """

    if model_name in _ANALYZER_CACHE:
        return _ANALYZER_CACHE[model_name]
    try:
        from presidio_analyzer import AnalyzerEngine
        from presidio_analyzer.nlp_engine import NlpEngineProvider
    except ImportError as exc:
        raise NerUnavailable(
            "no_presidio",
            "Presidio is not installed. Install with: pip install "
            "'nokast-privacy-masker[ner]'",
        ) from exc

    try:
        provider = NlpEngineProvider(
            nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": model_name}],
            }
        )
        nlp_engine = provider.create_engine()
    except OSError as exc:
        raise NerUnavailable(
            "no_model",
            f"spaCy model {model_name!r} is not installed. Download it with: "
            f"python -m spacy download {model_name}",
        ) from exc

    analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])
    _ANALYZER_CACHE[model_name] = analyzer
    return analyzer


class PresidioNerDetector:
    """Detect contextual PII (names, locations, orgs, dates) via Presidio."""

    def __init__(
        self,
        enabled_categories: Iterable[str],
        model_name: str = DEFAULT_MODEL,
        min_score: float = DEFAULT_MIN_SCORE,
    ):
        self._enabled = {c for c in enabled_categories if c in patterns.NER_CATEGORIES}
        # Only ask Presidio for the entity types we actually map and enabled.
        self._entities = [
            CATEGORY_TO_PRESIDIO[c] for c in self._enabled if c in CATEGORY_TO_PRESIDIO
        ]
        self._min_score = min_score
        self._analyzer = load_analyzer(model_name)

    def finditer(self, text: str) -> Iterable[Finding]:
        if not text or not self._entities:
            return
        results = self._analyzer.analyze(
            text=text, entities=self._entities, language="en"
        )
        for r in results:
            if r.score < self._min_score:
                continue
            category = PRESIDIO_ENTITY_MAP.get(r.entity_type)
            if category is not None and category in self._enabled:
                yield Finding(
                    start=r.start,
                    end=r.end,
                    category=category,
                    text=text[r.start:r.end],
                )
