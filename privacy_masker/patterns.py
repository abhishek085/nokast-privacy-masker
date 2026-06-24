"""Sensitive-data pattern definitions for the privacy masker.

Each :class:`Pattern` knows how to find a kind of sensitive data in a block of
text via a regular expression. Patterns are one kind of *detector*: anything that
yields :class:`Finding` spans plugs into the same masking pipeline (see
:mod:`privacy_masker.detectors` for the NER-based detector).

Patterns are split by *category* (email, secret, phone, ...) so users can toggle
categories on and off, and so findings can be reported back ("redacted 2 emails").

Adding a new regex detector is just a matter of appending a ``Pattern`` to one of
the category lists below.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Iterator, Optional

# Category identifiers. These double as the keys used in the config file to
# enable/disable a whole category and to look up replacement tokens.

# -- regex-detectable categories (fixed shape) --
EMAIL = "email"
SECRET = "secret"
PHONE = "phone"
SSN = "ssn"
CREDIT_CARD = "credit_card"
IP = "ip"
# -- user-supplied dictionary --
KEYWORD = "keyword"
# -- NER-detected categories (contextual; need the [ner] extra) --
PERSON = "person"
LOCATION = "location"
ORG = "org"
DATE = "date"

# Categories that have built-in regex patterns.
REGEX_CATEGORIES = (EMAIL, SECRET, PHONE, SSN, CREDIT_CARD, IP)
# Categories resolved by the spaCy NER detector.
NER_CATEGORIES = (PERSON, LOCATION, ORG, DATE)

ALL_CATEGORIES = REGEX_CATEGORIES + (KEYWORD,) + NER_CATEGORIES

# What's on out of the box. NER person/location are high-value, low-noise PII so
# they're enabled by default (they simply do nothing until the [ner] extra and a
# model are installed). ORG and DATE are off by default -- redacting every company
# name or date tends to over-redact ordinary prose.
DEFAULT_ENABLED = REGEX_CATEGORIES + (KEYWORD, PERSON, LOCATION)


@dataclass(frozen=True)
class Finding:
    """A single span of text that should be redacted.

    ``start``/``end`` are indices into the *original* text. ``category`` is one
    of the constants above and is used both for reporting and to pick the
    replacement token.
    """

    start: int
    end: int
    category: str
    text: str


@dataclass(frozen=True)
class Pattern:
    """A regex-based detector for one kind of sensitive data.

    Parameters
    ----------
    category:
        Which category this detector belongs to (see constants above).
    regex:
        Compiled regular expression to scan with.
    group:
        Which capture group holds the *value* to redact. Defaults to ``0`` (the
        whole match). For assignment-style rules like ``password: hunter2`` we
        only want to redact the value, so the rule captures the value in a named
        group and points ``group`` at it -- the ``password:`` prefix is kept.
    validate:
        Optional predicate run on the matched value. If it returns ``False`` the
        match is discarded. Used, e.g., to Luhn-check credit-card candidates so
        we don't redact every 16-digit number.
    """

    category: str
    regex: re.Pattern
    group: int | str = 0
    validate: Optional[Callable[[str], bool]] = None

    def finditer(self, text: str) -> Iterator[Finding]:
        for match in self.regex.finditer(text):
            value = match.group(self.group)
            if value is None:
                continue
            if self.validate is not None and not self.validate(value):
                continue
            start, end = match.span(self.group)
            yield Finding(start=start, end=end, category=self.category, text=value)


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

def luhn_valid(candidate: str) -> bool:
    """Return ``True`` if ``candidate`` passes the Luhn checksum.

    Credit-card numbers satisfy Luhn; most random 16-digit strings do not, so
    this dramatically cuts false positives. Non-digit characters (spaces,
    dashes) are ignored.
    """

    digits = [int(c) for c in candidate if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, digit in enumerate(digits):
        if i % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------

# Email addresses: alice.smith+tag@sub.example.co.uk
_EMAIL = Pattern(
    category=EMAIL,
    regex=re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
)

# Secrets, API keys and tokens. Ordered roughly from most-specific to most
# generic; the masker resolves overlaps so the order here is not critical, but
# specific vendor formats are clearer in reports.
_SECRET_PATTERNS = [
    # PEM private key blocks (multi-line).
    Pattern(
        category=SECRET,
        regex=re.compile(
            r"-----BEGIN[A-Z ]*PRIVATE KEY-----.*?-----END[A-Z ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
    ),
    # OpenAI / Anthropic style keys: sk-..., sk-proj-..., sk-ant-...
    Pattern(category=SECRET, regex=re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_\-]{16,}\b")),
    # AWS access key id.
    Pattern(category=SECRET, regex=re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    # Google API key.
    Pattern(category=SECRET, regex=re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    # GitHub tokens (personal, OAuth, server, refresh, fine-grained).
    Pattern(category=SECRET, regex=re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    Pattern(category=SECRET, regex=re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    # Slack tokens.
    Pattern(category=SECRET, regex=re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b")),
    # Stripe keys + webhook signing secret.
    Pattern(category=SECRET, regex=re.compile(r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    Pattern(category=SECRET, regex=re.compile(r"\bwhsec_[A-Za-z0-9]{32,}\b")),
    # GitLab personal access token.
    Pattern(category=SECRET, regex=re.compile(r"\bglpat-[A-Za-z0-9_\-]{20}\b")),
    # Google OAuth client secret.
    Pattern(category=SECRET, regex=re.compile(r"\bGOCSPX-[A-Za-z0-9_\-]{28}\b")),
    # SendGrid API key.
    Pattern(category=SECRET, regex=re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b")),
    # Twilio account SID and API key.
    Pattern(category=SECRET, regex=re.compile(r"\b(?:AC|SK)[a-f0-9]{32}\b")),
    # npm / PyPI / Hugging Face / DigitalOcean tokens.
    Pattern(category=SECRET, regex=re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    Pattern(category=SECRET, regex=re.compile(r"\bpypi-[A-Za-z0-9_\-]{16,}\b")),
    Pattern(category=SECRET, regex=re.compile(r"\bhf_[A-Za-z0-9]{34,}\b")),
    Pattern(category=SECRET, regex=re.compile(r"\bdop_v1_[a-f0-9]{64}\b")),
    # Telegram bot token.
    Pattern(category=SECRET, regex=re.compile(r"\b\d{8,10}:[A-Za-z0-9_\-]{35}\b")),
    # JSON Web Tokens.
    Pattern(
        category=SECRET,
        regex=re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"),
    ),
    # Credentials embedded in a connection string / URL: redact just the
    # password. Common in .env files: postgres://user:s3cr3t@host/db
    Pattern(
        category=SECRET,
        regex=re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:/@]*:(?P<value>[^\s:/@]+)@"),
        group="value",
    ),
    # "Authorization: Bearer <token>" -- redact just the token.
    Pattern(
        category=SECRET,
        regex=re.compile(r"\bBearer\s+(?P<value>[A-Za-z0-9._\-]{8,})", re.IGNORECASE),
        group="value",
    ),
    # Generic assignment of a secret-ish key: password = hunter2, API_KEY: abc123,
    # DJANGO_SECRET_KEY="...". Only the value is redacted so the key name stays
    # readable. The key may be prefixed (e.g. STRIPE_SECRET_KEY) -- we anchor on
    # the secret-ish suffix. Covers most .env style declarations.
    Pattern(
        category=SECRET,
        regex=re.compile(
            r"(?i)(?:^|[^A-Za-z0-9])"                       # start or non-word before
            r"[A-Z0-9_]*?"                                  # optional prefix (DJANGO_, STRIPE_)
            r"(?:passwd|password|passphrase|pwd|"
            r"secret[_\-]?key|secret|"
            r"api[_\-]?key|apikey|access[_\-]?key|"
            r"access[_\-]?token|refresh[_\-]?token|id[_\-]?token|auth[_\-]?token|"
            r"private[_\-]?key|encryption[_\-]?key|"
            r"client[_\-]?secret|signing[_\-]?secret|webhook[_\-]?secret|"
            r"account[_\-]?sid|credentials?|token|auth|dsn)"
            r"\s*[:=]\s*"
            r"(?P<value>(?:\"[^\"]+\"|'[^']+'|\S+))",
        ),
        group="value",
    ),
]

# Phone numbers. Requires at least a 3-3-4 grouping with optional country code
# and common separators. The leading/trailing boundaries avoid eating digits out
# of longer numbers.
_PHONE = Pattern(
    category=PHONE,
    regex=re.compile(
        r"(?<![\d\-])(?:\+?\d{1,3}[\s.\-]?)?"      # optional country code
        r"(?:\(\d{3}\)|\d{3})[\s.\-]"               # area code
        r"\d{3}[\s.\-]\d{4}"                         # local number
        r"(?![\d\-])",
    ),
)

# US Social Security numbers: 123-45-6789.
_SSN = Pattern(
    category=SSN,
    regex=re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
)

# Credit cards: 13-19 digit runs allowing spaces/dashes, validated with Luhn.
_CREDIT_CARD = Pattern(
    category=CREDIT_CARD,
    regex=re.compile(r"\b(?:\d[ \-]?){12,18}\d\b"),
    validate=luhn_valid,
)

# IPv4 addresses with octet validation (each 0-255), so version strings like
# "1.2.3.4" still match but "999.1.1.1" doesn't. (IPv6 is a future addition.)
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_IPV4 = Pattern(
    category=IP,
    regex=re.compile(rf"\b{_OCTET}(?:\.{_OCTET}){{3}}\b"),
)


# Built-in patterns grouped by category, so callers can enable/disable whole
# categories cheaply.
BUILTIN_PATTERNS: dict[str, list[Pattern]] = {
    EMAIL: [_EMAIL],
    SECRET: list(_SECRET_PATTERNS),
    PHONE: [_PHONE],
    SSN: [_SSN],
    CREDIT_CARD: [_CREDIT_CARD],
    IP: [_IPV4],
}


def keyword_pattern(keyword: str) -> Pattern:
    """Build a case-insensitive whole-word pattern for a custom keyword.

    Used for client names / project codewords the user always wants redacted.
    """

    keyword = keyword.strip()
    escaped = re.escape(keyword)
    # \b doesn't work well around non-word chars, so anchor on word boundaries
    # only where the keyword starts/ends with a word character.
    left = r"\b" if keyword[:1].isalnum() else ""
    right = r"\b" if keyword[-1:].isalnum() else ""
    return Pattern(
        category=KEYWORD,
        regex=re.compile(left + escaped + right, re.IGNORECASE),
    )
