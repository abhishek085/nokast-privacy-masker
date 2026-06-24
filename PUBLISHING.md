# Publishing to PyPI

This package is configured and validated for PyPI. Below are both the automated
and manual release paths. The distribution name `nokast-privacy-masker` was
available at the time of writing.

## Prerequisites (once)

- A [PyPI](https://pypi.org/account/register/) account (and ideally a
  [TestPyPI](https://test.pypi.org/account/register/) one for dry runs).

## Option A — Automated (recommended): GitHub Release + Trusted Publishing

No API tokens or secrets to manage. The workflow at
`.github/workflows/publish.yml` builds and uploads on every published GitHub
Release using OIDC.

1. **Configure the trusted publisher on PyPI** (one time):
   PyPI → your project (or "pending publisher" before the first upload) →
   *Publishing* → add:
   - Owner: `abhishek085`
   - Repository: `nokast-privacy-masker`
   - Workflow filename: `publish.yml`
   - Environment: `pypi`
2. **Cut a release**: bump `version` in `pyproject.toml`, commit, then
   ```bash
   git tag v0.1.0 && git push origin v0.1.0
   gh release create v0.1.0 --generate-notes
   ```
   The workflow builds, runs `twine check`, and publishes automatically.

## Option B — Manual with twine

```bash
# 1. Build fresh artifacts
rm -rf dist build *.egg-info
python -m build

# 2. Validate
python -m twine check dist/*

# 3. (Optional) dry run on TestPyPI
python -m twine upload --repository testpypi dist/*
pip install --index-url https://test.pypi.org/simple/ nokast-privacy-masker

# 4. Publish to the real PyPI
python -m twine upload dist/*
```

`twine` will prompt for credentials; use a PyPI API token (username
`__token__`, password = the `pypi-…` token).

## After publishing

```bash
pipx install nokast-privacy-masker          # global CLI
# or
pip install 'nokast-privacy-masker[all]'    # library + clipboard + NER + vault
python -m spacy download en_core_web_sm      # only if you want PII (NER) detection
```

## Release checklist

- [ ] `version` bumped in `pyproject.toml`
- [ ] `pytest` green
- [ ] `python -m build && python -m twine check dist/*` pass
- [ ] README renders (the logo uses an absolute raw-GitHub URL for PyPI)
- [ ] Tag + GitHub Release created
