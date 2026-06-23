<p align="center">
  <img src="assets/logo.svg" alt="Nokast Privacy Hook" width="560">
</p>

<h1 align="center">🛡️ Privacy Hook</h1>

<p align="center">
  <b>A privacy-first CLI tool for builders.</b><br>
  Mask sensitive data <i>before</i> it ever reaches an AI tool — 100% local, no accounts, no network.
</p>

```
  ┌──────────────────────────────────────────────┐
  │   _  _     _         _     ___      _         │
  │  | \| |___| |_____ _| |_  | _ \_ _ (_)_ __    │
  │  | .` / _ \ / / _ (_-<  _| |  _/ '_|| \ V /   │
  │  |_|\_\___/_\_\___/__/\__| |_| |_|  |_|\_/    │
  │                                              │
  │        🛡️  Privacy Hook  ·  mask before you AI │
  └──────────────────────────────────────────────┘
```

---

## The problem

When you copy-paste into an AI (ChatGPT, Claude, Copilot, …), you often *accidentally*
include sensitive data: internal emails, API keys, client names, passwords. Once it's
sent to the cloud, you can't un-paste it.

## The Privacy Hook

`privacy-masker` is a tiny CLI that sits between your clipboard and the AI. It scans
text for sensitive patterns and swaps them for safe, labelled placeholders:

```
Before:  Email jane@corp.com, our key is sk-AbCd1234..., re: Project Titan
After:   Email [EMAIL], our key is [SECRET], re: [REDACTED]
```

**Privacy-first by design** — everything runs locally on your machine. No telemetry,
no accounts, no network calls. It's a hook you control, for the way builders actually
work: in the terminal and the clipboard.

---

## What it detects

| Category | Examples |
| --- | --- |
| **Emails** | `jane.doe@corp.com` → `[EMAIL]` |
| **API keys & passwords** | OpenAI/Anthropic `sk-…`, AWS `AKIA…`, GitHub `ghp_…`, Slack, Stripe, Google, JWTs, PEM private keys, `password: …` / `api_key = …` assignments, `Bearer …` tokens |
| **Phone numbers** | `(555) 123-4567`, `+1 555-123-4567` → `[PHONE]` |
| **Social Security numbers** | `123-45-6789` → `[SSN]` |
| **Credit cards** | 13–19 digit numbers that pass the Luhn check → `[CARD]` |
| **Custom keywords** | Your own list of client names / project codewords → `[REDACTED]` |

Placeholders are **labelled** (`[EMAIL]`, not `XXX`) so the AI still understands the
shape of your text — it knows an email *was* there without ever seeing the address.
Every token, category, and the keyword list is configurable.

---

## Install

```bash
# Core engine + CLI (no third-party dependencies):
pip install -e .

# With clipboard support (for `mask --clipboard` and `watch`):
pip install -e '.[clipboard]'
```

Requires Python 3.9+.

---

## Usage

### 1. Mask a pipe / stdin

```bash
echo "ping jane@corp.com, pw: hunter2" | privacy-masker mask
# -> ping [EMAIL], pw: [SECRET]
```

### 2. Mask your clipboard in place

```bash
privacy-masker mask --clipboard
```

### 3. Watch mode — auto-mask as you copy 🪝

The hook you set and forget. Run it once; from then on, **anything you copy is scanned
and cleaned automatically** before you paste it anywhere. No hotkeys, no menu bar.

```bash
privacy-masker watch
# [14:02:51] redacted 1 email, 1 secret
# [14:03:10] redacted 2 keywords
```

`Ctrl+C` to stop. Tune the poll rate with `--interval 0.5`, or run silently with `--quiet`.

### 4. Manage your keyword redaction list

```bash
privacy-masker keywords add "Project Titan"
privacy-masker keywords list
privacy-masker keywords remove "Project Titan"
```

### 5. Inspect / create the config

```bash
privacy-masker config --init
```

---

## Configuration

Config lives at
`~/Library/Application Support/nokast-privacy-masker/config.json` (override with the
`PRIVACY_MASKER_CONFIG_DIR` environment variable):

```json
{
  "enabled_categories": ["email", "secret", "phone", "ssn", "credit_card", "keyword"],
  "replacements": {
    "email": "[EMAIL]",
    "secret": "[SECRET]",
    "phone": "[PHONE]",
    "ssn": "[SSN]",
    "credit_card": "[CARD]",
    "keyword": "[REDACTED]"
  },
  "keywords": ["Project Titan", "Acme Corp"]
}
```

---

## Project layout

```
privacy_masker/
├── patterns.py   # Regex detectors per category + Luhn validation
├── masker.py     # The engine: applies patterns, resolves overlaps, redacts
├── config.py     # Load/save user config (categories, tokens, keywords)
└── cli.py        # `privacy-masker` command-line interface (mask · watch · keywords)
tests/
└── test_masker.py
assets/
└── logo.svg
```

The engine (`patterns.py` + `masker.py` + `config.py`) is OS-free and fully unit
tested, so it's easy to add new detectors or embed it elsewhere.

## Development

```bash
pip install -e '.[dev]'
pytest
```

## A note on guarantees

This is a strong *safety net*, not a guarantee. Pattern-based detection can miss novel
secret formats or unusual phrasings — treat it as defence-in-depth, not a licence to
paste anything. Contributions of new detectors are welcome.

## License

MIT
