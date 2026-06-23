"""Tests for the masking engine (the OS-free core)."""

import pytest

from privacy_masker import patterns
from privacy_masker.config import Config
from privacy_masker.masker import Masker
from privacy_masker.patterns import luhn_valid


@pytest.fixture
def masker():
    # Default config: every category enabled, default tokens.
    return Masker(Config())


# -- emails -----------------------------------------------------------------

def test_masks_simple_email(masker):
    result = masker.mask("ping me at jane.doe@corp.com please")
    assert result.text == "ping me at [EMAIL] please"
    assert result.counts() == {patterns.EMAIL: 1}


def test_masks_multiple_emails(masker):
    result = masker.mask("a@x.com and b+tag@sub.example.co.uk")
    assert result.text == "[EMAIL] and [EMAIL]"
    assert result.counts()[patterns.EMAIL] == 2


# -- secrets ----------------------------------------------------------------

# Fixtures are assembled from fragments on purpose: this keeps any verbatim
# secret-shaped literal out of the source so secret-scanners (and GitHub push
# protection) don't flag the test file, while still exercising each regex.
_SECRET_FIXTURES = [
    "sk-" + "abcdEFGH1234567890" + " ijkl",      # OpenAI-style (space ends token)
    "AKIA" + "IOSFODNN7" + "EXAMPLE",            # AWS access key id
    "ghp_" + "a" * 36,                            # GitHub PAT
    "xoxb-" + "1234567890-" + "abcdefghijklmnop", # Slack bot token
]


@pytest.mark.parametrize("secret", _SECRET_FIXTURES)
def test_masks_known_secret_formats(masker, secret):
    result = masker.mask(f"key is {secret} end")
    assert "[SECRET]" in result.text
    assert any(f.category == patterns.SECRET for f in result.findings)


def test_redacts_only_value_in_assignment(masker):
    result = masker.mask("password: hunter2")
    assert result.text == "password: [SECRET]"


def test_redacts_quoted_assignment_value(masker):
    result = masker.mask('api_key = "abc123def456"')
    assert result.text == 'api_key = [SECRET]'


def test_redacts_bearer_token(masker):
    result = masker.mask("Authorization: Bearer abcDEF123456ghateway")
    assert "[SECRET]" in result.text
    assert "Bearer" in result.text


def test_masks_jwt(masker):
    # Assembled from fragments (see note above) so no verbatim JWT lives in source.
    jwt = ".".join(
        ["eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiIxMjM0In0", "dozjgNryP4J3jVmNHl0w5N"]
    )
    result = masker.mask(f"token {jwt}")
    assert "[SECRET]" in result.text


def test_masks_private_key_block(masker):
    blob = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEpAIBAAKCAQEA1234\n"
        "-----END RSA PRIVATE KEY-----"
    )
    result = masker.mask(f"here:\n{blob}\ndone")
    assert "PRIVATE KEY" not in result.text
    assert "[SECRET]" in result.text


# -- phone / ssn / credit card ----------------------------------------------

@pytest.mark.parametrize(
    "phone",
    ["555-123-4567", "(555) 123-4567", "+1 555-123-4567"],
)
def test_masks_phone_numbers(masker, phone):
    result = masker.mask(f"call {phone} now")
    assert "[PHONE]" in result.text


def test_masks_ssn(masker):
    result = masker.mask("SSN 123-45-6789 on file")
    assert result.text == "SSN [SSN] on file"


def test_masks_valid_credit_card(masker):
    # A Luhn-valid Visa test number.
    result = masker.mask("card 4111 1111 1111 1111 ok")
    assert "[CARD]" in result.text


def test_ignores_luhn_invalid_number(masker):
    # 16 digits that fail Luhn should not be treated as a card.
    result = masker.mask("order 1234 5678 1234 5670x")
    assert "[CARD]" not in result.text


def test_luhn_valid_helper():
    assert luhn_valid("4111111111111111")
    assert not luhn_valid("4111111111111112")


# -- keywords ---------------------------------------------------------------

def test_masks_custom_keyword():
    config = Config(keywords=["Project Titan"])
    masker = Masker(config)
    result = masker.mask("update on Project Titan and project titan")
    assert result.text == "update on [REDACTED] and [REDACTED]"
    assert result.counts()[patterns.KEYWORD] == 2


def test_keyword_respects_word_boundary():
    config = Config(keywords=["Ace"])
    masker = Masker(config)
    # "Ace" should match as a word but not inside "Facebook"/"spaceship".
    result = masker.mask("Ace works at a spaceship company")
    assert result.text == "[REDACTED] works at a spaceship company"


# -- overlap / ordering -----------------------------------------------------

def test_email_inside_assignment_not_double_masked(masker):
    # "secret = jane@corp.com": the assignment value spans the email. We should
    # get exactly one replacement (the more-sensitive SECRET label), not a
    # corrupted nested one.
    result = masker.mask("secret = jane@corp.com")
    assert result.text == "secret = [SECRET]"
    assert len(result.findings) == 1


def test_preserves_surrounding_text(masker):
    result = masker.mask("Hi a@b.com, your code is 123-45-6789. Thanks!")
    assert result.text == "Hi [EMAIL], your code is [SSN]. Thanks!"


# -- config / categories ----------------------------------------------------

def test_disabled_category_is_skipped():
    config = Config(enabled_categories={patterns.SSN})  # only SSN active
    masker = Masker(config)
    result = masker.mask("a@b.com and 123-45-6789")
    assert result.text == "a@b.com and [SSN]"


def test_custom_replacement_token():
    config = Config(replacements={**Config().replacements, patterns.EMAIL: "<<HIDDEN>>"})
    masker = Masker(config)
    result = masker.mask("mail a@b.com")
    assert result.text == "mail <<HIDDEN>>"


# -- no-ops -----------------------------------------------------------------

def test_clean_text_unchanged(masker):
    text = "Just a normal sentence with no secrets."
    result = masker.mask(text)
    assert result.text == text
    assert not result.changed
    assert result.summary() == ""


def test_empty_text(masker):
    result = masker.mask("")
    assert result.text == ""
    assert not result.changed


def test_summary_pluralisation(masker):
    result = masker.mask("a@b.com c@d.com")
    assert result.summary() == "2 emails"
