"""Pluggable detectors beyond regex.

The masking engine doesn't care *how* a sensitive span is found -- only that it
gets :class:`~privacy_masker.patterns.Finding` objects with character offsets. A
:class:`Pattern` (regex) is one detector; this module adds an NER-based detector
that catches contextual PII -- names, places, organisations, dates -- which have
no fixed shape and so can't be matched by regex alone.

The NER detector uses spaCy, an open-source NLP library, and runs **fully
locally**. It is an optional dependency: install with ``pip install
'nokast-privacy-masker[ner]'`` and download a model with
``python -m spacy download en_core_web_sm``. When spaCy or the model is missing,
the rest of the masker keeps working and reports the NER status so the CLI can
nudge the user.
"""

from __future__ import annotations

from typing import Iterable, Protocol, runtime_checkable

from . import patterns
from .patterns import Finding


@runtime_checkable
class Detector(Protocol):
    """Anything that can find sensitive spans in text.

    Both :class:`~privacy_masker.patterns.Pattern` and :class:`SpacyNerDetector`
    satisfy this -- the engine treats them uniformly.
    """

    def finditer(self, text: str) -> Iterable[Finding]:  # pragma: no cover - protocol
        ...


# Map spaCy entity labels (from en_core_web_* models) to our categories.
# GPE = geo-political entity (countries/cities/states); LOC = non-GPE locations;
# FAC = facilities / addresses-ish; we fold those into a single LOCATION bucket.
SPACY_LABEL_MAP = {
    "PERSON": patterns.PERSON,
    "GPE": patterns.LOCATION,
    "LOC": patterns.LOCATION,
    "FAC": patterns.LOCATION,
    "ORG": patterns.ORG,
    "DATE": patterns.DATE,
}

DEFAULT_MODEL = "en_core_web_sm"


class NerUnavailable(Exception):
    """Raised when an NER detector cannot be constructed.

    ``reason`` is a stable machine-readable token (``"no_spacy"`` or
    ``"no_model"``) the CLI can turn into an actionable hint.
    """

    def __init__(self, reason: str, message: str):
        super().__init__(message)
        self.reason = reason


# spaCy models are expensive to load (~1s), so cache by model name across Masker
# rebuilds (e.g. when the user toggles a category).
_MODEL_CACHE: dict = {}


def load_model(model_name: str = DEFAULT_MODEL):
    """Load (and cache) a spaCy model, raising :class:`NerUnavailable` on failure."""

    if model_name in _MODEL_CACHE:
        return _MODEL_CACHE[model_name]
    try:
        import spacy
    except ImportError as exc:
        raise NerUnavailable(
            "no_spacy",
            "spaCy is not installed. Install with: pip install "
            "'nokast-privacy-masker[ner]'",
        ) from exc
    try:
        nlp = spacy.load(model_name, disable=["lemmatizer", "tagger", "parser"])
    except OSError as exc:
        raise NerUnavailable(
            "no_model",
            f"spaCy model {model_name!r} is not installed. Download it with: "
            f"python -m spacy download {model_name}",
        ) from exc
    _MODEL_CACHE[model_name] = nlp
    return nlp


class SpacyNerDetector:
    """Detect contextual PII (names, locations, orgs, dates) via spaCy NER."""

    def __init__(self, enabled_categories: Iterable[str], model_name: str = DEFAULT_MODEL):
        # Only the NER categories the user actually enabled.
        self._enabled = {c for c in enabled_categories if c in patterns.NER_CATEGORIES}
        self._nlp = load_model(model_name)

    def finditer(self, text: str) -> Iterable[Finding]:
        if not text or not self._enabled:
            return
        doc = self._nlp(text)
        for ent in doc.ents:
            category = SPACY_LABEL_MAP.get(ent.label_)
            if category is not None and category in self._enabled:
                yield Finding(
                    start=ent.start_char,
                    end=ent.end_char,
                    category=category,
                    text=ent.text,
                )
