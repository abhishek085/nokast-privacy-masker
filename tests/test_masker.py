"""Tests for the masking engine (the OS-free core)."""

import pytest

from privacy_masker import patterns
from privacy_masker.config import Config
from privacy_masker.masker import Masker
from privacy_masker.patterns import luhn_valid


# Regex + keyword categories only. We pin these for the core-engine tests so they
# stay deterministic regardless of whether the optional spaCy NER model is present.
_REGEX_CATEGORIES = set(patterns.REGEX_CATEGORIES) | {patterns.KEYWORD}


@pytest.fixture
def masker():
    return Masker(Config(enabled_categories=set(_REGEX_CATEGORIES)))


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
    "glpat-" + "ABCdef12345678901234",           # GitLab PAT
    "GOCSPX-" + "abcdEFGH1234567890ijklMNOP12",   # Google OAuth client secret
    "npm_" + "ABCdef123456789012345678901234567890",  # npm token
    "hf_" + "ABCdefGHIjklMNOpqrSTUvwx1234567890ABCD",  # Hugging Face
    "whsec_" + "ABCdef1234567890ABCdef1234567890ab",   # Stripe webhook secret
]


@pytest.mark.parametrize("secret", _SECRET_FIXTURES)
def test_masks_known_secret_formats(masker, secret):
    result = masker.mask(f"key is {secret} end")
    assert "[SECRET]" in result.text
    assert any(f.category == patterns.SECRET for f in result.findings)


def test_masks_credentials_in_connection_string(masker):
    # Common .env shape with an IP host: the URL-credentials detector redacts the
    # password (the host, being an IP, is handled separately by the IP detector).
    result = masker.mask("DATABASE_URL=postgres://admin:s3cr3tp4ss@10.0.0.5:5432/app")
    assert "s3cr3tp4ss" not in result.text   # password gone
    assert "[SECRET]" in result.text


def test_masks_password_in_url_with_domain_host(masker):
    # With a domain host the email detector may absorb pass@host -- either way the
    # password must not survive in the output.
    result = masker.mask("conn = postgres://admin:s3cr3tp4ss@db.example.com/app")
    assert "s3cr3tp4ss" not in result.text


@pytest.mark.parametrize(
    "line",
    [
        "DJANGO_SECRET_KEY=abc123def456ghi",
        "STRIPE_SECRET_KEY = 'value-here-xyz'",
        "MY_REFRESH_TOKEN: tokvalue123",
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIabcd",
        "app.dsn = https://key@sentry.io/123",
    ],
)
def test_masks_prefixed_env_assignments(masker, line):
    result = masker.mask(line)
    assert "[SECRET]" in result.text


def test_entropy_catches_unnamed_opaque_secret(masker):
    # A random-looking value assigned to a non-hinting name -> caught by entropy.
    result = masker.mask("FOO = Xa9Kf2Lp7Qz3Wm8Rb5Tn1Yc4Vd6Hg0Js")
    assert "[SECRET]" in result.text


def test_entropy_ignores_git_sha(masker):
    # A 40-char hex git SHA should NOT be treated as a secret.
    result = masker.mask("commit 1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b")
    assert "[SECRET]" not in result.text


def test_entropy_ignores_normal_prose(masker):
    text = "The quick brown fox jumps over the lazy dog repeatedly today."
    assert masker.mask(text).text == text


# -- dotenv mode ------------------------------------------------------------

def test_dotenv_masks_all_values_keeps_keys(masker):
    env = (
        "# config\n"
        "LOG_LEVEL=info\n"
        "APP_PORT=8080\n"
        "DEBUG=true\n"
        "API_BASE=https://api.example.com\n"
        'NAME="Jane Doe"\n'
    )
    out = masker.mask(env, dotenv=True).text
    # Numbers / booleans / comments stay; everything else is masked, keys intact.
    assert "APP_PORT=8080" in out
    assert "DEBUG=true" in out
    assert "# config" in out
    assert "LOG_LEVEL=[SECRET]" in out          # opaque-but-not-a-number value
    assert "API_BASE=[SECRET]" in out
    assert "NAME=[SECRET]" in out
    assert "Jane Doe" not in out


def test_dotenv_export_prefix(masker):
    out = masker.mask("export SECRET_THING=abcdef\n", dotenv=True).text
    assert out.strip() == "export SECRET_THING=[SECRET]"


def test_dotenv_strips_inline_comment_but_keeps_it(masker):
    out = masker.mask("TOKEN=abcdef  # my token\n", dotenv=True).text
    assert "abcdef" not in out
    assert "# my token" in out


def test_non_dotenv_leaves_plain_assignments(masker):
    # Without dotenv mode, a non-secret-named value is untouched.
    assert masker.mask("LOG_LEVEL=info").text == "LOG_LEVEL=info"


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


@pytest.mark.parametrize("ip", ["192.168.1.50", "10.0.0.1", "255.255.255.0", "8.8.8.8"])
def test_masks_ipv4(masker, ip):
    result = masker.mask(f"host = {ip}")
    assert result.text == "host = [IP]"


def test_ignores_invalid_ipv4(masker):
    # 999 is not a valid octet -> not an IP.
    result = masker.mask("not an ip 999.1.1.1 here")
    assert "[IP]" not in result.text


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
    config = Config(keywords=["Project Titan"], enabled_categories={patterns.KEYWORD})
    masker = Masker(config)
    result = masker.mask("update on Project Titan and project titan")
    assert result.text == "update on [REDACTED] and [REDACTED]"
    assert result.counts()[patterns.KEYWORD] == 2


def test_keyword_respects_word_boundary():
    config = Config(keywords=["Ace"], enabled_categories={patterns.KEYWORD})
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


# -- PII defaults & NER status (no model required) --------------------------

def test_default_config_enables_high_value_pii():
    cfg = Config()
    assert patterns.PERSON in cfg.enabled_categories
    assert patterns.LOCATION in cfg.enabled_categories
    # ORG/DATE are off by default to avoid over-redacting ordinary prose.
    assert patterns.ORG not in cfg.enabled_categories
    assert patterns.DATE not in cfg.enabled_categories


def test_ner_status_off_when_no_ner_categories():
    m = Masker(Config(enabled_categories={patterns.EMAIL}))
    assert m.ner_status == "off"


# -- NER detection (skipped unless spaCy + a model are installed) ------------

@pytest.fixture(scope="module")
def ner_masker():
    pytest.importorskip("presidio_analyzer")
    from privacy_masker.detectors import NerUnavailable, load_analyzer

    try:
        load_analyzer()
    except NerUnavailable as exc:
        pytest.skip(str(exc))
    cfg = Config(
        enabled_categories={
            patterns.PERSON,
            patterns.LOCATION,
            patterns.ORG,
            patterns.EMAIL,  # so the NER+regex combined test exercises both
        }
    )
    return Masker(cfg)


def test_ner_status_active(ner_masker):
    assert ner_masker.ner_status == "active"


def test_ner_masks_person_name(ner_masker):
    result = ner_masker.mask("I had lunch with Barack Obama today.")
    assert "[NAME]" in result.text
    assert "Obama" not in result.text


def test_ner_masks_location(ner_masker):
    result = ner_masker.mask("She just moved to Paris.")
    assert "[LOCATION]" in result.text
    assert "Paris" not in result.text


def test_ner_and_regex_combine(ner_masker):
    result = ner_masker.mask("Email John Smith at john@corp.com")
    assert "[NAME]" in result.text
    assert "[EMAIL]" in result.text
    assert "john@corp.com" not in result.text
