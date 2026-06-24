"""Command-line interface for Privacy Hook (nokast-privacy-masker).

A privacy-first CLI for builders. Mask sensitive data before it ever reaches an
AI tool::

    echo "ping me at jane@corp.com"   | privacy-masker mask
    pbpaste | privacy-masker mask | pbcopy        # mask the clipboard manually
    privacy-masker mask --clipboard               # same, in one step
    privacy-masker watch                          # auto-mask the clipboard live
    privacy-masker lock app.py                    # reversibly mask secrets in a file
    privacy-masker unlock app.py                  # restore them with your passphrase
    privacy-masker keywords add "Project Titan"   # manage the keyword list
"""

from __future__ import annotations

import argparse
import getpass
import sys
import time
from pathlib import Path

from . import __version__
from .config import Config
from .masker import Masker

KEYRING_SERVICE = "nokast-privacy-masker"

BANNER = r"""
  ┌──────────────────────────────────────────────┐
  │   _  _     _         _     ___      _         │
  │  | \| |___| |_____ _| |_  | _ \_ _ (_)_ __    │
  │  | .` / _ \ / / _ (_-<  _| |  _/ '_|| \ V /   │
  │  |_|\_\___/_\_\___/__/\__| |_| |_|  |_|\_/    │
  │                                              │
  │        🛡️  Privacy Hook  ·  mask before you AI │
  └──────────────────────────────────────────────┘
"""


def _ner_hint(masker: Masker) -> str | None:
    """Return an actionable hint if PII (NER) categories are on but unavailable."""

    status = getattr(masker, "ner_status", "off")
    if status in ("no_presidio", "no_model"):
        return getattr(masker, "ner_message", "NER detection unavailable.")
    return None


def _import_pyperclip():
    try:
        import pyperclip  # noqa: F401

        return pyperclip
    except ImportError:
        print(
            "Clipboard features need pyperclip. Install it with:\n"
            "    pip install 'nokast-privacy-masker[clipboard]'",
            file=sys.stderr,
        )
        return None


def cmd_mask(args: argparse.Namespace) -> int:
    config = Config.load()
    masker = Masker(config)

    hint = _ner_hint(masker)
    if hint:
        print(f"note: PII detection is enabled but inactive. {hint}", file=sys.stderr)

    if args.clipboard:
        pyperclip = _import_pyperclip()
        if pyperclip is None:
            return 1
        source = pyperclip.paste()
        result = masker.mask(source)
        pyperclip.copy(result.text)
        summary = result.summary() or "nothing"
        print(f"Masked clipboard: redacted {summary}.", file=sys.stderr)
        return 0

    source = sys.stdin.read()
    result = masker.mask(source)
    sys.stdout.write(result.text)
    if result.changed and not sys.stdout.isatty():
        # Keep stdout clean for piping; report to stderr.
        print(f"\n[redacted {result.summary()}]", file=sys.stderr)
    return 0


def cmd_watch(args: argparse.Namespace) -> int:
    """Continuously watch the clipboard and auto-mask sensitive content.

    No hotkey, no menu bar: copy anything, and the moment it lands on your
    clipboard it's scanned and (if needed) replaced in place with the masked
    version. Paste as usual -- it's already safe.
    """

    pyperclip = _import_pyperclip()
    if pyperclip is None:
        return 1

    config = Config.load()
    masker = Masker(config)
    interval = max(0.2, args.interval)

    if not args.quiet:
        print(BANNER)
        if masker.ner_status == "active":
            print("PII detection (names, locations) is active via Presidio NER.")
        hint = _ner_hint(masker)
        if hint:
            print(f"note: PII detection is enabled but inactive. {hint}")
        print(
            f"Watching clipboard every {interval:g}s. Copy anything; secrets are "
            "masked automatically.\nPress Ctrl+C to stop.\n",
            flush=True,
        )

    # Seed with current clipboard so we don't re-mask what's already there on
    # startup unless it's sensitive.
    last_seen = None
    try:
        while True:
            try:
                current = pyperclip.paste()
            except Exception as exc:  # pragma: no cover - platform clipboard issues
                print(f"clipboard read error: {exc}", file=sys.stderr)
                time.sleep(interval)
                continue

            if current != last_seen:
                result = masker.mask(current)
                if result.changed:
                    pyperclip.copy(result.text)
                    last_seen = result.text  # avoid re-processing our own write
                    if not args.quiet:
                        ts = time.strftime("%H:%M:%S")
                        print(f"[{ts}] redacted {result.summary()}", flush=True)
                else:
                    last_seen = current

            time.sleep(interval)
    except KeyboardInterrupt:
        if not args.quiet:
            print("\nStopped watching.")
        return 0


# --- reversible vault: lock / unlock / status ------------------------------

def _keyring():
    try:
        import keyring

        return keyring
    except ImportError:
        return None


def _resolve_vault_path(args) -> Path:
    from .vault import VAULT_FILENAME

    return Path(args.vault).expanduser() if args.vault else Path.cwd() / VAULT_FILENAME


def _get_passphrase(vault_path: Path, *, creating: bool, use_keychain: bool) -> tuple[str, bool]:
    """Return (passphrase, came_from_keychain).

    Tries the OS keychain first (unless disabled), then prompts. When creating a
    new vault we confirm the passphrase to avoid lock-out from a typo.
    """

    if use_keychain:
        kr = _keyring()
        if kr is not None:
            stored = kr.get_password(KEYRING_SERVICE, str(vault_path))
            if stored:
                return stored, True

    passphrase = getpass.getpass("Vault passphrase: ")
    if not passphrase:
        raise SystemExit("Aborted: empty passphrase.")
    if creating:
        if getpass.getpass("Confirm passphrase: ") != passphrase:
            raise SystemExit("Aborted: passphrases did not match.")
    return passphrase, False


def _maybe_store_passphrase(vault_path: Path, passphrase: str, use_keychain: bool) -> None:
    if not use_keychain:
        return
    kr = _keyring()
    if kr is not None:
        try:
            kr.set_password(KEYRING_SERVICE, str(vault_path), passphrase)
        except Exception:  # pragma: no cover - keychain may be locked/unavailable
            pass


def cmd_lock(args: argparse.Namespace) -> int:
    from .vault import Vault, VaultError, lock_text

    vault_path = _resolve_vault_path(args)
    use_keychain = not args.no_keychain
    creating = not vault_path.exists()

    try:
        vault = Vault.create() if creating else Vault.load(vault_path)
        passphrase, _ = _get_passphrase(vault_path, creating=creating, use_keychain=use_keychain)
        masker = Masker(Config.load())

        total = 0
        for file_arg in args.files:
            path = Path(file_arg)
            text = path.read_text(encoding="utf-8")
            result = lock_text(text, passphrase, vault, masker)
            path.write_text(result.text, encoding="utf-8")
            total += result.count
            print(f"locked {path}: {result.count} secret(s) masked")

        vault.save(vault_path)
        _maybe_store_passphrase(vault_path, passphrase, use_keychain)
    except VaultError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except (OSError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"\nVault: {vault_path}  ({total} token(s) sealed this run)")
    print("Add the vault to .gitignore so the encrypted secrets stay off your remote.")
    return 0


def cmd_unlock(args: argparse.Namespace) -> int:
    from .vault import Vault, VaultError, unlock_text

    vault_path = _resolve_vault_path(args)
    if not vault_path.exists():
        print(f"error: no vault at {vault_path}", file=sys.stderr)
        return 1
    use_keychain = not args.no_keychain

    try:
        vault = Vault.load(vault_path)
        passphrase, _ = _get_passphrase(vault_path, creating=False, use_keychain=use_keychain)

        for file_arg in args.files:
            path = Path(file_arg)
            text = path.read_text(encoding="utf-8")
            result = unlock_text(text, passphrase, vault)
            path.write_text(result.text, encoding="utf-8")
            print(f"unlocked {path}: {result.count} value(s) restored")

        _maybe_store_passphrase(vault_path, passphrase, use_keychain)
    except VaultError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except (OSError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


def cmd_vault_status(args: argparse.Namespace) -> int:
    from .vault import Vault

    vault_path = _resolve_vault_path(args)
    print(f"Vault path: {vault_path}")
    if not vault_path.exists():
        print("Status: no vault yet (run `privacy-masker lock <file>` to create one)")
        return 0
    vault = Vault.load(vault_path)
    print(f"Status: exists, {len(vault.entries)} sealed value(s)")
    kr = _keyring()
    cached = bool(kr and kr.get_password(KEYRING_SERVICE, str(vault_path))) if kr else False
    print(f"Keychain: {'passphrase cached' if cached else 'not cached (will prompt)'}")
    return 0


def cmd_keywords(args: argparse.Namespace) -> int:
    config = Config.load()

    if args.action == "list":
        if not config.keywords:
            print("No custom keywords configured.")
        for kw in config.keywords:
            print(kw)
        return 0

    if args.action == "add":
        keyword = args.keyword.strip()
        if keyword and keyword.lower() not in {k.lower() for k in config.keywords}:
            config.keywords.append(keyword)
            config.save()
            print(f"Added keyword: {keyword!r}")
        else:
            print(f"Keyword already present or empty: {keyword!r}")
        return 0

    if args.action == "remove":
        target = args.keyword.strip().lower()
        before = len(config.keywords)
        config.keywords = [k for k in config.keywords if k.lower() != target]
        if len(config.keywords) != before:
            config.save()
            print(f"Removed keyword: {args.keyword!r}")
        else:
            print(f"Keyword not found: {args.keyword!r}")
        return 0

    return 1


def cmd_config(args: argparse.Namespace) -> int:
    config = Config.load()
    print(f"Config file: {Config.path()}")
    print(f"Enabled categories: {', '.join(sorted(config.enabled_categories)) or '(none)'}")
    print(f"Keywords: {', '.join(config.keywords) or '(none)'}")

    masker = Masker(config)
    status_msg = {
        "off": "off (no PII categories enabled)",
        "active": "active (Presidio NER loaded)",
    }.get(masker.ner_status, getattr(masker, "ner_message", masker.ner_status))
    print(f"PII / NER detection: {status_msg}")

    if args.init:
        path = config.save()
        print(f"Wrote default config to {path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="privacy-masker",
        description="Privacy Hook: a privacy-first CLI that masks sensitive data before pasting into AI tools.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_mask = sub.add_parser("mask", help="Mask text from stdin (or the clipboard).")
    p_mask.add_argument(
        "-c",
        "--clipboard",
        action="store_true",
        help="Read from and write back to the system clipboard.",
    )
    p_mask.set_defaults(func=cmd_mask)

    p_watch = sub.add_parser(
        "watch", help="Watch the clipboard and auto-mask sensitive content live."
    )
    p_watch.add_argument(
        "-i",
        "--interval",
        type=float,
        default=1.0,
        help="Polling interval in seconds (default: 1.0).",
    )
    p_watch.add_argument(
        "-q", "--quiet", action="store_true", help="Suppress banner and per-redaction logs."
    )
    p_watch.set_defaults(func=cmd_watch)

    # Reversible vault commands.
    def _add_vault_opts(p):
        p.add_argument("files", nargs="+", help="File(s) to process.")
        p.add_argument("--vault", help="Vault file path (default: ./.privacy-vault).")
        p.add_argument(
            "--no-keychain",
            action="store_true",
            help="Always prompt for the passphrase; don't use the OS keychain.",
        )

    p_lock = sub.add_parser(
        "lock", help="Reversibly mask secrets in a file (restore later with `unlock`)."
    )
    _add_vault_opts(p_lock)
    p_lock.set_defaults(func=cmd_lock)

    p_unlock = sub.add_parser("unlock", help="Restore secrets previously locked in a file.")
    _add_vault_opts(p_unlock)
    p_unlock.set_defaults(func=cmd_unlock)

    p_vstatus = sub.add_parser("vault-status", help="Show the vault location and contents.")
    p_vstatus.add_argument("--vault", help="Vault file path (default: ./.privacy-vault).")
    p_vstatus.add_argument("--no-keychain", action="store_true", help=argparse.SUPPRESS)
    p_vstatus.set_defaults(func=cmd_vault_status)

    p_kw = sub.add_parser("keywords", help="Manage the custom keyword redaction list.")
    kw_sub = p_kw.add_subparsers(dest="action", required=True)
    kw_sub.add_parser("list", help="List configured keywords.")
    kw_add = kw_sub.add_parser("add", help="Add a keyword.")
    kw_add.add_argument("keyword")
    kw_rm = kw_sub.add_parser("remove", help="Remove a keyword.")
    kw_rm.add_argument("keyword")
    p_kw.set_defaults(func=cmd_keywords)

    p_cfg = sub.add_parser("config", help="Show (or initialise) configuration.")
    p_cfg.add_argument("--init", action="store_true", help="Write the default config file.")
    p_cfg.set_defaults(func=cmd_config)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
