# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

PentReport is a Flask web application for penetration testers to manage clients, reports, and vulnerabilities, with PDF export via WeasyPrint. The UI is in Portuguese (Brazilian).

## Development Commands

The project uses a Python 3 virtualenv at `.venv/`. Always activate it first:

```bash
source .venv/bin/activate
```

**Run the app:**
```bash
python run.py
# or
./start.sh   # handles full setup + DB init on first run
```

**Database management:**
```bash
FLASK_APP=run.py flask init-db        # create all tables
FLASK_APP=run.py flask create-admin   # create default admin user (admin/admin123)
FLASK_APP=run.py flask db migrate -m "description"  # generate migration
FLASK_APP=run.py flask db upgrade     # apply migrations
```

**Seed sample data:**
```bash
python seed.py
```

**Lint:**
```bash
flake8 app/
```

**Flask shell (with model context):**
```bash
FLASK_APP=run.py flask shell
# db, User, Client, Report, Vulnerability are pre-imported
```

## Architecture

**App factory pattern:** `app/__init__.py` defines `create_app(config_name)` which initializes extensions (SQLAlchemy, LoginManager, Flask-Migrate, CSRFProtect) and registers blueprints.

**Configuration:** `config.py` has `DevelopmentConfig` / `ProductionConfig` classes; selection via `FLASK_ENV` env var. All DB settings come from `.env` (see `.env.example`).

**Database:** MySQL/MariaDB via PyMySQL. ORM models in `app/models.py`:
- `User` — roles: `admin` or `pentester`
- `Client` — client companies
- `Report` — linked to one Client and one User (author); statuses: `Draft`, `In Review`, `Final`
- `Vulnerability` — belongs to a Report; severities: `Critical`, `High`, `Medium`, `Low`, `Informational`; statuses: `Open`, `Remediated`, `Accepted Risk`, `False Positive`

**Severity ordering:** `Vulnerability.severity_order` (0=Critical … 4=Informational) is set via `set_severity()` — always use this method when updating severity, not direct field assignment.

**Blueprints** (all require `@login_required`):
- `auth_bp` — `/login`, `/logout`, `/register`
- `dashboard_bp` — `/`
- `reports_bp` — `/reports/...` — includes `/reports/<id>/pdf` for WeasyPrint PDF generation
- `vulns_bp` — `/vulnerabilities/...` — nested under reports
- `clients_bp` — `/clients/...`

**Forms:** WTF forms in `app/forms.py` with CSRF protection enabled globally.

**PDF generation:** `reports_bp.generate_pdf` renders `templates/reports/pdf.html` and passes it to WeasyPrint. Requires system libs (`libpango`, `libcairo`). WeasyPrint is imported lazily inside the route so the app still runs if it's not installed.

**Templates:** Jinja2, extending `base.html`. Template folders mirror blueprint names (`auth/`, `clients/`, `reports/`, `vulnerabilities/`, `dashboard/`).
