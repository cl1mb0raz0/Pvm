# PVM (Patch - Vulnerability Management)

An internal web application for managing the vulnerabilities Qualys
detects. It supports several users and integrates with the Qualys API.
PVM turns weekly scan results into **persistent findings**: a finding is
tracked across scans rather than re-created by each one. It then works
through the false positives that version banners produce, checking each
flagged package against the version actually installed on the host,
using the distribution's own security data.

Built with Django, PostgreSQL, Celery/Redis and server-rendered templates
with HTMX, and shipped as one Docker Compose stack.

> Host names, domains and addresses in the docs and tests are
> placeholders (`.test` / `.corp` names, documentation IP ranges).

## What it does

- **Imports**: upload Qualys CSV reports, or pull finished scans from the
  Qualys VMDR API. Imports happen on demand, or through weekly and monthly
  rules. Each import is assigned a perimeter (Internal or External) and
  tags. Imports run in the background, can be stopped, and can be undone
  from the backup taken before them.
- **Persistent findings**: a finding is one row per host, QID, port and
  perimeter. Each scan updates it to new, still open, resolved or
  reopened ("needs review").
- **Severity and risk**: Qualys severity, NVD CVSS, FIRST EPSS and the
  CISA KEV catalog, combined into a 0-100 priority score with bands
  P1 to P4.
- **Patch checks**, which catch the findings raised from a version banner
  when the distribution has already backported the fix:
  - *Ubuntu*: checked against the Ubuntu security tracker, comparing
    versions with dpkg's rules.
  - *Rocky Linux*: checked against Rocky's RLSA errata, comparing versions
    with RPM's rules.
  - *Windows*: looked up by QID in Qualys Patch Management.

  An analyst confirms every verdict before it closes a finding.
- **Inventory**: installed packages come from the Qualys CSAM Cloud Agent,
  from a package list pasted by hand, or over SSH ("Ask Server", using a
  forced read-only command).
- **Network context**: private IPs, load balancer marks, and A10 ACOS
  configuration parsing (VIP, then pool, then real servers).
- **Workflow**: SLA due dates, triage by team, due date and status, and a
  full audit log.
- **Reports**: CSV, HTML and PDF exports with every filter. The
  Vulnerabilities list and the exports can also show the situation
  **as of a past date**, from snapshots or reconstructed from the scans.
- **Operations**: backups (regular or full, including the raw reports),
  restore, upload of a backup to a new server, data reset and factory
  reset.
- **Security**: four roles (Super Admin, Admin, Analyst, Read-only),
  mandatory TOTP MFA with backup codes, sign-in throttling and idle
  session expiry.

## Quick start

```bash
cp .env.example .env        # then set real secrets: see docs/INSTALL.md
docker compose up --build -d
docker compose exec web python manage.py createsuperuser
```

Open `http://<server>:8080/`, sign in and set up the authenticator app.
To try it with made-up data, run
`docker compose exec web python manage.py seed_demo` on an empty database.

**[docs/INSTALL.md](docs/INSTALL.md)** covers the full setup: requirements,
configuration, outbound access, first steps, moving to another server,
upgrading and tests.

## Documentation

Installing, configuring, upgrading and moving PVM: [docs/INSTALL.md](docs/INSTALL.md).

## Tests

```bash
docker compose exec web python manage.py test --noinput
```

The tests need Python 3.12 or 3.13, because Django 5.1 does not run on
3.14. They use synthetic fixtures only.

## License

Released under the [MIT License](LICENSE).
