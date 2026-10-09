# Installing PVM

This guide sets PVM up on a new server: either an empty installation, or
a copy of an existing one with its data (see "Moving to another server").

## Requirements

- A Linux server or VM with Docker Engine and the Docker Compose plugin
  (`docker compose`). 2 CPUs and 4 GB of RAM are plenty for a few thousand
  findings. The PDF export runs inside the web request and takes a few
  seconds for about 1,000 rows.
- Outbound HTTPS from the containers to the public sources PVM mirrors.
  Only CVE IDs are sent, never hosts or addresses:

  | Host | Used for | Turn off with |
  |---|---|---|
  | `services.nvd.nist.gov` | CVSS scores | `NVD_ENABLED=false` |
  | `ubuntu.com` | Ubuntu security tracker | `UBUNTU_TRACKER_ENABLED=false` |
  | `errata.rockylinux.org` | Rocky Linux errata | `ROCKY_TRACKER_ENABLED=false` |
  | `www.cisa.gov` | CISA KEV catalog (downloaded whole) | `KEV_ENABLED=false` |
  | `api.first.org` | EPSS | `EPSS_ENABLED=false` |

- Optional: network access to your Qualys platform's API and gateway
  (VMDR, CSAM, Patch Management). If the platform is only reachable
  through a VPN, the containers' traffic must go through it too, for
  example with the VPN client running on the host.
- Optional: outbound SSH from the server to the hosts, for "Ask Server".

## 1. Get the code

```bash
git clone git@github.com:<you>/<repo>.git pvm
cd pvm
```

## 2. Configure `.env`

```bash
cp .env.example .env
chmod 600 .env
```

Every variable is explained in `.env.example`. The ones you must set:

| Variable | What to put |
|---|---|
| `DJANGO_SECRET_KEY` | 32 characters or more. PVM refuses to start with the example value. Generate one: `python3 -c 'import secrets; print(secrets.token_urlsafe(64))'` |
| `DJANGO_ALLOWED_HOSTS` | The names and IPs users will open PVM with, comma-separated |
| `POSTGRES_PASSWORD` | A long random value. Prefer letters and digits only: no `$`, `#` or quotes |
| `PVM_SSH_KEY_SECRET` | Only if you will use "Ask Server". It encrypts PVM's SSH key; keep it, because changing it makes the stored key unreadable |
| `QUALYS_API_URL`, `QUALYS_GATEWAY_URL`, `QUALYS_USERNAME`, `QUALYS_PASSWORD` | Only for the Qualys API. The URLs depend on your platform. Use a dedicated read-only API user |
| `PVM_LISTEN` | `8080` (every interface) or `127.0.0.1:8080` / `<ip>:8080` |
| `PVM_TIME_ZONE` | Time zone of every date and time shown, of "today" and of the nightly jobs (default `Europe/Rome`) |
| `PVM_SCHEDULE_TIME_ZONE` | Time zone of the automatic import rules (default: `PVM_TIME_ZONE`) |

Docker Compose expands `$` inside `.env` values. A value containing `$`
must be written in single quotes (`QUALYS_PASSWORD='pa$$word'`),
otherwise the containers get it truncated. Compose then warns that a
variable "is not set", and Qualys answers 401.

The containers read `.env` only when they are created. After changing it,
run `docker compose up -d --force-recreate`.

**Never commit `.env`.** It is ignored by `.gitignore`; keep a copy of it
somewhere safe, apart from the repository and the backups.

## 3. Start

```bash
docker compose up --build -d
docker compose ps          # every service "running" / "healthy"
```

This starts seven containers:

| Container | Role |
|---|---|
| `db` | PostgreSQL 16 |
| `redis` | Celery broker |
| `web` | gunicorn; runs the migrations before it starts |
| `worker` | Imports and host checks |
| `worker-background` | NVD, KEV, EPSS and the nightly jobs |
| `beat` | The scheduler |
| `nginx` | Reverse proxy, published on `PVM_LISTEN` |

Data lives in three folders next to the compose file: `data/postgres`,
`data/scan_imports` (the raw Qualys reports) and `data/backups`. Postgres
runs as `PVM_UID:PVM_GID` (default 1000:1000): the folder must belong to
that user, mode 700 for `data/postgres`.

## 4. First user

```bash
docker compose exec web python manage.py createsuperuser
```

Open `http://<server>:8080/` and sign in. Super Admins, Admins and
Analysts must enroll an authenticator app (TOTP) at their first sign-in,
and they get 10 backup codes, shown once. Further users are created in
the Django admin (`/admin/`); every user must be given a role.

To explore the interface with made-up data instead, run this on an empty
database:

```bash
docker compose exec web python manage.py seed_demo
```

## 5. First data

- **Imports > New Import**: upload a Qualys CSV scan report, choose the
  perimeter (Internal / External), the columns to import and, optionally,
  tags.
- **Imports > Qualys Scans**: "Ask Qualys" lists the finished scans.
  Import the ones you choose, or have an admin create a weekly or monthly
  rule for a scan title.
- **Imports > Qualys Csam**: installed packages and OS from the Cloud
  Agent, for the Ubuntu and Rocky Linux patch checks.
- **Imports > Qualys Pm**: the Windows patch check.

The first import also downloads the CISA KEV catalog. NVD scores arrive
in the background; without `NVD_API_KEY` NVD allows 5 requests every 30
seconds, so the first refresh of thousands of CVEs takes hours. A free
key from NVD makes it about 10 times faster.

Scheduled jobs (`beat`): automatic Qualys import rules every 15 minutes,
NVD at 03:00, KEV at 03:30, EPSS at 03:45, the patch re-check at 04:00,
the priority recompute at 04:30 and the history snapshot at 05:00.

## "Ask Server" (optional)

1. **Access (Ssh)** (Admins): generate PVM's key (Ed25519) or upload one.
2. On each host, the sysadmin creates the account `PVM_SSH_USER` and
   installs the read-only script and the restricted `authorized_keys`
   line shown on that page. The line is limited to the forced command and
   to `PVM_SSH_FROM`.
3. On the host page, enable SSH. Then, at the first contact, confirm the
   host key's fingerprint against `ssh-keygen -lf` on the server.

## TLS

nginx listens on plain HTTP (port 8080 by default). Before exposing PVM
beyond a trusted network:

1. Add a TLS server block to `nginx/nginx.conf`, with your certificate
   mounted into the `nginx` container.
2. Publish port 443.
3. Set `DJANGO_HTTPS=true`, so that cookies are sent over HTTPS only.

`python manage.py check --deploy` lists what remains.

## Backups

The **Backups** page (Admin and Super Admin) shows:

- **Automatic backups**, taken before every import, restore, mapping and
  reset.
- **Backups on demand**:
  - *Backup Now*: the database only.
  - *FULL BACKUP*: the database plus the raw Qualys reports, in one
    `tar.gz`.

Backups live in `data/backups`, on the same server: download a copy
regularly and keep it elsewhere. No backup ever contains `.env`.

## Moving to another server

1. On the old server: **Backups > FULL BACKUP**, then download it.
2. On the new server: install PVM as above, using a copy of the old `.env`.
   A new `DJANGO_SECRET_KEY` is fine: it only signs everyone out. Keeping
   `PVM_SSH_KEY_SECRET` keeps the SSH key usable.
3. Create a Super Admin (`createsuperuser`) and sign in.
4. **Imports > Upload** (Super Admins): upload the file. PVM validates it
   and registers it as a backup; uploading it replaces nothing.
5. Confirm the restore (type `RESTORE`). The users, their MFA devices and
   all the data of the old server come back. The account created in
   step 3 is replaced by the ones in the backup.

## Upgrading

```bash
git pull
docker compose up --build -d
```

The code is baked into the image, so a change reaches the running app
only after `--build`. Migrations run automatically when `web` starts.
Take a backup first; one is also taken automatically before every import
and restore.

## Tests

```bash
docker compose up --build -d          # the tests run the code of the last build
docker compose exec web python manage.py test --noinput
```

For local runs without Docker, use Python 3.12 or 3.13, because Django 5.1
does not run on 3.14. Also run the tests against PostgreSQL when a change
touches queries, migrations or backups.

After changing a model:
`python manage.py makemigrations --check --dry-run` must report no changes.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `web` exits at start | `DJANGO_SECRET_KEY` missing, the example value, or shorter than 32 characters |
| "Qualys Refused the Credentials" | A `$` in `QUALYS_PASSWORD` not in single quotes, or the platform URLs are wrong |
| Qualys unreachable | The VPN to the Qualys platform is down, or there is no outbound HTTPS |
| An import stays "Downloading" after a restart | Its task died. Use "Stop Import" on its page |
| "Checking…" never ends on a host | The worker restarted mid-check; it re-queues the check when it starts again |
| NVD scores slow to appear | No `NVD_API_KEY` (5 requests every 30 seconds) |
