🚨 **WARNING** THIS PROTOTYPE IS INTENDED TO BE EXECUTED LOCALLY AND TESTED AGAINST A SAFE VULNERABLE TARGET LIKE DVWA. DO NOT USE AGAINST UNAUTHORISED PUBLIC SYSTEMS!! 🚨

# M.O.R.T.I.S Prototype v1

Mapped Open-Route Threat Identification System: a first working Flask prototype.

## Current Prototype features

- Flask dashboard
- Default login
- SQLite database
- Authorised scan confirmation
- Scan history
- Security header checks
- SSL/TLS certificate check
- Cookie flag audit
- CORS misconfiguration check
- Basic non-destructive injection smoke test
- OWASP-style severity labels and risk score
- AI-style report scaffold
- Downloadable TXT scan report

## Default login

Username: `admin`  
Password: `mortis123`

Change these before any real deployment.

## Setup

```bash

python -m venv .venv

# Windows

.venv\Scripts\activate

# macOS/Linux

source .venv/bin/activate

pip install -r requirements.txt

python run.py
```

Open: `http://127.0.0.1:5000`

## Safe testing guidance

Only scan systems you own or have explicit permission to test. For coursework evidence, use intentionally vulnerable local targets such as DVWA or OWASP Juice Shop.

## Suggested next development steps

1. Replace the prototype report generator in `app/reporting.py` with Claude/OpenAI API calls using environment variables.
2. Add user registration and password reset.
3. Add scan module toggles and configurable scan depth.
4. Add HTML/PDF report export.
5. Add deeper crawler-based input discovery.
6. Add pytest coverage for each scanner module.

## Project structure

```text
M.O.R.T.I.S_APP/
  app/
    scanner/          # Modular scan checks
    templates/        # Dashboard pages
    static/css/       # Styling
    models.py         # SQLite models
    routes.py         # Flask routes
    reporting.py      # AI-report scaffold
  docs/evidence/      # Place screenshots for TM470 appendices
  tests/              # Future pytest tests
  run.py
  requirements.txt
```
