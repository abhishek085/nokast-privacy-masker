"""Reversible masking: lock secrets in a file, unlock with a passphrase.

Unlike :mod:`privacy_masker.masker` -- which redacts *irreversibly* (``[EMAIL]``)
-- this module replaces each secret with a unique token and stores the original
**encrypted** in a sidecar vault. The original can only be restored with the
passphrase used to lock it.

    privacy-masker lock app.py        # 192.168.1.5 -> PMV_00000001, etc.
    # ... share app.py with a coding assistant; the real values are gone ...
    privacy-masker unlock app.py      # prompts passphrase, restores originals

Crypto: the passphrase is stretched with **scrypt** into a 256-bit key; values
are sealed with **Fernet** (AES-128-CBC + HMAC) from the audited ``cryptography``
library. We never invent our own crypto.

Threat model -- read this. This protects secrets from leaking to a *cloud AI*. It
is NOT protection against a local attacker who has both the locked file and the
vault: with a weak passphrase they can brute-force it offline. Use a strong
passphrase, keep secrets out of source where you can, and gitignore the vault.
"""

from __future__ import annotations

import base64
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .masker import Masker

# Tokens are valid identifier characters so a locked file still *parses* (it
# won't *run* -- a locked file is meant for sharing/committing, not execution).
TOKEN_PREFIX = "PMV_"
TOKEN_RE = re.compile(r"\bPMV_\d{8}\b")
VAULT_FILENAME = ".privacy-vault"

# scrypt cost parameters (interactive-login strength).
_SCRYPT_N = 2 ** 15
_SCRYPT_R = 8
_SCRYPT_P = 1
_KEY_LEN = 32


class VaultError(Exception):
    """Base class for vault problems (missing dep, bad passphrase, ...)."""


def _require_cryptography():
    try:
        from cryptography.fernet import Fernet, InvalidToken  # noqa: F401

        return Fernet, InvalidToken
    except ImportError as exc:  # pragma: no cover - exercised when extra absent
        raise VaultError(
            "Reversible lock/unlock needs the 'cryptography' package. Install "
            "with: pip install 'nokast-privacy-masker[vault]'"
        ) from exc


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    """Stretch a passphrase into a urlsafe-base64 Fernet key via scrypt."""

    import hashlib

    # scrypt needs ~128*N*r*p bytes; the OpenSSL default cap (32 MiB) is exactly
    # what these parameters require, so set the limit explicitly with headroom.
    maxmem = 128 * _SCRYPT_N * _SCRYPT_R * _SCRYPT_P * 2
    raw = hashlib.scrypt(
        passphrase.encode("utf-8"),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=_KEY_LEN,
        maxmem=maxmem,
    )
    return base64.urlsafe_b64encode(raw)


@dataclass
class Vault:
    """An encrypted token->secret store persisted as JSON.

    On disk the vault holds only ciphertext plus the salt; no plaintext secret
    ever touches the file. A canary value lets us detect a wrong passphrase up
    front instead of silently producing garbage on unlock.
    """

    salt: bytes
    entries: dict[str, str] = field(default_factory=dict)  # token -> ciphertext(b64)
    canary: Optional[str] = None  # ciphertext of a known constant
    _counter: int = 0

    _CANARY_PLAINTEXT = "nokast-privacy-vault-v1"

    # -- construction / io ------------------------------------------------

    @classmethod
    def create(cls) -> "Vault":
        return cls(salt=os.urandom(16))

    @classmethod
    def load(cls, path: Path) -> "Vault":
        data = json.loads(path.read_text(encoding="utf-8"))
        entries = data.get("entries", {})
        vault = cls(
            salt=base64.b64decode(data["salt"]),
            entries=entries,
            canary=data.get("canary"),
        )
        # Resume the counter past the highest existing token id.
        ids = [int(t[len(TOKEN_PREFIX):]) for t in entries if TOKEN_RE.fullmatch(t)]
        vault._counter = max(ids, default=0)
        return vault

    def save(self, path: Path) -> None:
        path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "salt": base64.b64encode(self.salt).decode(),
                    "canary": self.canary,
                    "entries": self.entries,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

    # -- crypto-bound operations -----------------------------------------

    def unlock_cipher(self, passphrase: str):
        """Return a Fernet bound to this vault's key, verifying the passphrase."""

        Fernet, InvalidToken = _require_cryptography()
        fernet = Fernet(_derive_key(passphrase, self.salt))
        if self.canary is None:
            # First use: stamp a canary so future unlocks can verify the key.
            self.canary = fernet.encrypt(self._CANARY_PLAINTEXT.encode()).decode()
        else:
            try:
                if fernet.decrypt(self.canary.encode()).decode() != self._CANARY_PLAINTEXT:
                    raise VaultError("Wrong passphrase for this vault.")
            except InvalidToken as exc:
                raise VaultError("Wrong passphrase for this vault.") from exc
        return fernet

    def _next_token(self) -> str:
        self._counter += 1
        return f"{TOKEN_PREFIX}{self._counter:08d}"

    def seal(self, fernet, original: str) -> str:
        """Encrypt ``original``, store it, and return its token."""

        token = self._next_token()
        self.entries[token] = fernet.encrypt(original.encode("utf-8")).decode()
        return token

    def reveal(self, fernet, token: str) -> Optional[str]:
        cipher = self.entries.get(token)
        if cipher is None:
            return None
        return fernet.decrypt(cipher.encode()).decode("utf-8")


@dataclass
class LockResult:
    text: str
    count: int


def lock_text(
    text: str,
    passphrase: str,
    vault: Vault,
    masker: Optional[Masker] = None,
    dotenv: bool = False,
) -> LockResult:
    """Replace detected secrets in ``text`` with tokens, sealing originals in ``vault``.

    Identical values within a single call collapse to the same token (so a key
    repeated twice stays consistent). When ``dotenv`` is true, every ``KEY=VALUE``
    value is locked (the whole-file ``.env`` strategy). Returns the locked text and
    how many spans were replaced.
    """

    masker = masker or Masker()
    findings = masker.find(text, dotenv=dotenv)
    if not findings:
        return LockResult(text=text, count=0)

    fernet = vault.unlock_cipher(passphrase)
    seen: dict[str, str] = {}  # original value -> token (dedupe within this file)

    pieces: list[str] = []
    cursor = 0
    for finding in findings:
        pieces.append(text[cursor:finding.start])
        value = finding.text
        token = seen.get(value)
        if token is None:
            token = vault.seal(fernet, value)
            seen[value] = token
        pieces.append(token)
        cursor = finding.end
    pieces.append(text[cursor:])
    return LockResult(text="".join(pieces), count=len(findings))


def unlock_text(text: str, passphrase: str, vault: Vault) -> LockResult:
    """Restore tokens in ``text`` to their original values from ``vault``."""

    fernet = vault.unlock_cipher(passphrase)
    restored = 0

    def _replace(match: re.Match) -> str:
        nonlocal restored
        original = vault.reveal(fernet, match.group(0))
        if original is None:
            return match.group(0)  # unknown token: leave it untouched
        restored += 1
        return original

    return LockResult(text=TOKEN_RE.sub(_replace, text), count=restored)
