# Contributing to MORTIS

MORTIS is a coursework prototype, but it follows a lightweight open-source
workflow so changes are reviewable and safe to merge.

## Reporting bugs / suggesting features

Open a GitHub Issue describing:
- What you expected vs. what happened (for bugs), or the problem you want
  solved (for features).
- Steps to reproduce, including the target used (e.g. DVWA, Juice Shop).
- Whether it affects a specific scanner module (`app/scanner/*.py`), the web
  app (`routes.py`, templates), or reporting (`reporting.py`).

## Making a change

1. **Fork/branch**: create a branch off `main` named `fix/...`, `feat/...`,
   or `docs/...` describing the change.
2. **Scope**: keep pull requests focused on one thing. A new scanner check,
   a bug fix, and a template tweak should be three PRs, not one.
3. **Non-destructive checks only**: any new scanner module must be passive
   or use safe, non-destructive probes (no exploitation, no payloads that
   could modify or delete remote data). See `app/scanner/access.py` and
   `app/scanner/injection.py` for the expected style.
4. **Tests**: add or update a `tests/test_<module>.py` covering the new
   behaviour. Run `pytest` locally before opening the PR.
5. **No secrets**: never commit API keys, real target URLs, or credentials.
   Configuration belongs in environment variables (see `README.md`).

## Pull request review

- At least one reviewer (or, for solo coursework submissions, a
  self-review checklist — see the PR template) must confirm the change
  builds, passes `pytest`, and doesn't weaken an existing security control
  (e.g. CSRF protection, security headers, password hashing).
- Branch protection on `main` should require this check before merge.

## Coding style

- Follow the existing pattern in each scanner module: a `check_*(url,
  timeout=8)` function returning a list of `make_finding(...)` dicts.
- Keep new dependencies minimal; the project intentionally avoids heavy
  frameworks so it stays easy to run for coursework demonstration.
