"""Tests for the reversible vault (lock/unlock + encryption)."""

import json

import pytest

# The vault needs the optional 'cryptography' dependency.
pytest.importorskip("cryptography")

from privacy_masker import patterns
from privacy_masker.config import Config
from privacy_masker.masker import Masker
from privacy_masker.vault import (
    TOKEN_RE,
    Vault,
    VaultError,
    lock_text,
    unlock_text,
)

PASSPHRASE = "correct horse battery staple"

# Fake secrets assembled from fragments so no verbatim secret-shaped literal
# lives in source (keeps secret-scanners / GitHub push protection happy).
KEY1 = "sk-" + "ABCD1234efgh5678ijkl"
KEY2 = "sk-" + "WXYZ9876lkjh5432mnop"
KEY3 = "sk-" + "SUPERsecret1234567890abcd"

# A masker with NER off, so these tests don't depend on a spaCy model.
_REGEX_MASKER = Masker(
    Config(enabled_categories=set(patterns.REGEX_CATEGORIES) | {patterns.KEYWORD})
)


def test_lock_unlock_round_trip():
    original = f"host = 192.168.1.50\nkey = {KEY1}\nmail jane@corp.com"
    vault = Vault.create()

    locked = lock_text(original, PASSPHRASE, vault, _REGEX_MASKER)
    assert locked.count == 3
    # The real values are gone from the locked text...
    assert "192.168.1.50" not in locked.text
    assert KEY1 not in locked.text
    assert "jane@corp.com" not in locked.text
    # ...replaced by tokens.
    assert TOKEN_RE.search(locked.text)

    restored = unlock_text(locked.text, PASSPHRASE, vault)
    assert restored.text == original
    assert restored.count == 3


def test_wrong_passphrase_rejected():
    vault = Vault.create()
    locked = lock_text(f"token = {KEY1}", PASSPHRASE, vault, _REGEX_MASKER)
    with pytest.raises(VaultError):
        unlock_text(locked.text, "not the passphrase", vault)


def test_vault_file_holds_no_plaintext(tmp_path):
    vault = Vault.create()
    lock_text(f"key = {KEY3}", PASSPHRASE, vault, _REGEX_MASKER)

    path = tmp_path / ".privacy-vault"
    vault.save(path)
    raw = path.read_text()
    assert KEY3 not in raw  # only ciphertext is persisted
    data = json.loads(raw)
    assert data["entries"]  # but something is stored


def test_repeated_value_collapses_to_one_token():
    vault = Vault.create()
    locked = lock_text(f"a = {KEY1}\nb = {KEY1}", PASSPHRASE, vault, _REGEX_MASKER)
    tokens = set(TOKEN_RE.findall(locked.text))
    assert len(tokens) == 1  # same secret -> same token
    assert len(vault.entries) == 1


def test_save_load_preserves_unlock(tmp_path):
    original = f"key = {KEY1}"
    vault = Vault.create()
    locked = lock_text(original, PASSPHRASE, vault, _REGEX_MASKER)

    path = tmp_path / ".privacy-vault"
    vault.save(path)

    reloaded = Vault.load(path)
    restored = unlock_text(locked.text, PASSPHRASE, reloaded)
    assert restored.text == original


def test_token_counter_resumes_after_load(tmp_path):
    vault = Vault.create()
    lock_text(f"a = {KEY1}", PASSPHRASE, vault, _REGEX_MASKER)
    path = tmp_path / ".privacy-vault"
    vault.save(path)

    reloaded = Vault.load(path)
    locked2 = lock_text(f"b = {KEY2}", PASSPHRASE, reloaded, _REGEX_MASKER)
    # New token must not reuse the first id.
    assert "PMV_00000002" in locked2.text
    assert len(reloaded.entries) == 2


def test_unknown_token_left_untouched():
    vault = Vault.create()
    # Seed the vault/canary by locking something real first.
    lock_text(f"key = {KEY1}", PASSPHRASE, vault, _REGEX_MASKER)
    result = unlock_text("stray PMV_00009999 here", PASSPHRASE, vault)
    assert result.text == "stray PMV_00009999 here"
    assert result.count == 0


def test_no_secrets_is_noop():
    vault = Vault.create()
    result = lock_text("just a normal line of code", PASSPHRASE, vault, _REGEX_MASKER)
    assert result.count == 0
    assert result.text == "just a normal line of code"
