# MORTIS — changes made in this updated build

All changes are non-destructive and the app still runs exactly as before with no
setup beyond `pip install -r requirements.txt`. New features activate via
optional environment variables. All 16 pytest tests pass (was 11).

## Latest round: RE8, RE11, RE12, RE14, RE15

9. **Configurable scan depth + module toggles** (`app/scanner/engine.py`,
   `app/routes.py`, `app/templates/scan.html`)
   - `run_scan()` now accepts `enabled_modules` and `depth` ("standard" or
     "quick"; quick skips the active-probe Access Control and Injection/XSS
     checks). The scan form exposes both as checkboxes/a dropdown.
10. **Real-time scan progress** (`app/models.py`, `app/routes.py`,
    `app/templates/scan_progress.html`)
    - Scans now run in a background thread. `Scan.status` /
      `modules_done` / `modules_total` / `current_module` are updated as each
      module completes and polled via `GET /scan/<id>/status` (JSON), shown
      as a live progress bar on `GET /scan/<id>/progress`. The dashboard
      shows a "Running…" badge for in-flight scans.
11. **CVSS v3.1 base scoring** (`app/scanner/risk.py` + every `check_*`
    module)
    - `make_finding()` gained an optional `cvss_vector` parameter. When
      supplied, a real CVSS v3.1 base score/rating is computed from the
      vector (verified against NVD reference vectors) and stored alongside
      the existing severity band, which is unchanged and still drives
      sorting/overall rating for backward compatibility.
12. **HTML report export** (`app/routes.py`, `app/templates/results.html`)
    - New `GET /report/<id>.html` route; "Download HTML Report" button added
      next to the existing TXT export.
13. **Contribution workflow docs** (`CONTRIBUTING.md`,
    `.github/PULL_REQUEST_TEMPLATE.md`)

Note: the `Finding`/`Scan` tables gained new columns (`cvss_vector`,
`cvss_score`, `cvss_rating`, `status`, `modules_total`, `modules_done`,
`current_module`). If you're running against an existing
`instance/mortis.sqlite3` from before this change, run an `ALTER TABLE` to
add them (there's no Flask-Migrate/Alembic in this prototype) — see the
migration commands used during verification, or delete the file to let
`db.create_all()` recreate it from scratch (this discards scan history).

## Must-haves
1. **Live LLM reporting** (`app/reporting.py`)
   - Uses Claude when `ANTHROPIC_API_KEY` is set; otherwise falls back to the
     original local summary. Only non-sensitive finding metadata is sent.
   - Optional: `MORTIS_LLM_MODEL` to change the model.
2. **Broken Access Control module — OWASP A01** (`app/scanner/access.py`, new)
   - Non-destructive check for common sensitive paths; registered in the engine.
3. **Scan throttling / rate limiting** (`app/scanner/engine.py`)
   - Delay between modules, configurable via `MORTIS_DELAY` (default 0.3s).
4. **Application hardening**
   - `SECRET_KEY` from env with a random dev fallback (`app/__init__.py`).
   - Default admin password from `MORTIS_ADMIN_PW` (`app/__init__.py`).
   - Debug off by default; enable with `FLASK_DEBUG=1` (`run.py`).
   - CSRF protection on all POST forms via Flask-WTF (`app/__init__.py`,
     `login.html`, `scan.html`).

## Should-haves
5. **Reflected-XSS probe** added to `app/scanner/injection.py`.
6. **TLS cipher-strength reporting** added to `app/scanner/tls.py`.

## Bug fixes
7. `app/scanner/cookies.py` — correctly reads multiple Set-Cookie headers.
8. `app/scanner/utils.py` — localhost/127.0.0.1 default to http:// (so
   `localhost:8080` works for DVWA).

## New tests
- `tests/test_access.py`, `tests/test_reporting.py`, plus a localhost case in
  `tests/test_utils.py`.

## requirements.txt
- Added `Flask-WTF` (CSRF) and `anthropic` (LLM).

## To use the AI reporting feature
    set ANTHROPIC_API_KEY=your-key   (Windows PowerShell: $env:ANTHROPIC_API_KEY="your-key")
    python run.py
Without a key the app runs normally using the local summary.
