"""
Django settings for the PVM project.

Configuration is read from environment variables so the same image can run
on the founding developer VM and, later, in pre-production/production with
no code changes (only the .env file differs).
"""

import os
from pathlib import Path

from celery.schedules import crontab

BASE_DIR = Path(__file__).resolve().parent.parent

# --- Core -------------------------------------------------------------

# The fallback lets the image build (collectstatic) without a .env; the
# running app refuses it, see pvm/startup.py.
SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "insecure-dev-key-change-me")
DEBUG = os.environ.get("DJANGO_DEBUG", "false").lower() == "true"
ALLOWED_HOSTS = [h.strip() for h in os.environ.get("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1").split(",") if h.strip()]

# --- Applications -------------------------------------------------------

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    # MFA: native TOTP devices plus static (backup) tokens.
    "django_otp",
    "django_otp.plugins.otp_totp",
    "django_otp.plugins.otp_static",
    # Local apps.
    "accounts",
    "core",
    "backups",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    # Must come after AuthenticationMiddleware: attaches user.otp_device
    # and powers the @otp_required decorator used on sensitive views.
    "django_otp.middleware.OTPMiddleware",
    # Every page requires a logged-in user unless the view opts out with
    # @login_not_required (only the login page does).
    "django.contrib.auth.middleware.LoginRequiredMiddleware",
    # Sends a password-authenticated but not yet OTP-verified user to the
    # verify or enrollment screen; see accounts.middleware.
    "accounts.middleware.MFAEnforcementMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "pvm.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "pvm.wsgi.application"

# --- Database -------------------------------------------------------------
# Matches the "db" service name used in docker-compose.

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.environ.get("POSTGRES_DB", "pvm"),
        "USER": os.environ.get("POSTGRES_USER", "pvm"),
        "PASSWORD": os.environ.get("POSTGRES_PASSWORD", "pvm"),
        "HOST": os.environ.get("POSTGRES_HOST", "db"),
        "PORT": os.environ.get("POSTGRES_PORT", "5432"),
    }
}

# --- Auth -------------------------------------------------------------

AUTH_USER_MODEL = "accounts.User"

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 12}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LOGIN_URL = "accounts:login"
LOGIN_REDIRECT_URL = "core:dashboard"
LOGOUT_REDIRECT_URL = "accounts:login"

# MFA is mandatory for the admin and analyst roles; enforced in application
# logic (see accounts.middleware) rather than here, since django-otp has
# no per-role concept of its own.
OTP_TOTP_ISSUER = "Pvm"

# Password sign-in limits (accounts/throttle.py): after this many failures
# within the window, further attempts are refused until the window passes.
LOGIN_LOCKOUT_MINUTES = int(os.environ.get("PVM_LOGIN_LOCKOUT_MINUTES", "15"))
LOGIN_MAX_FAILURES_PER_USER = int(os.environ.get("PVM_LOGIN_MAX_FAILURES_PER_USER", "5"))
LOGIN_MAX_FAILURES_PER_IP = int(os.environ.get("PVM_LOGIN_MAX_FAILURES_PER_IP", "20"))

# Sessions end after this long without activity (every request renews it).
SESSION_COOKIE_AGE = int(os.environ.get("PVM_SESSION_IDLE_HOURS", "8")) * 3600
SESSION_SAVE_EVERY_REQUEST = True

# Set DJANGO_HTTPS=true once nginx serves TLS: cookies are then sent over
# HTTPS only, and nginx's X-Forwarded-Proto tells Django the request was secure.
if os.environ.get("DJANGO_HTTPS", "false").lower() == "true":
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# --- I18N / TZ -------------------------------------------------------------

LANGUAGE_CODE = "en-us"
# The zone every date and time is shown in, and the one "today" means (SLA
# start days, "As Of", the nightly jobs below). Stored values stay UTC
# (USE_TZ), so changing it only changes how they are read and displayed.
TIME_ZONE = os.environ.get("PVM_TIME_ZONE", "Europe/Rome")
USE_I18N = True
USE_TZ = True

# --- Static files -------------------------------------------------------------

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR / "static"]

STORAGES = {
    "default": {
        "BACKEND": "django.core.files.storage.FileSystemStorage",
    },
    "staticfiles": {
        "BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage",
    },
}

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# --- Celery -------------------------------------------------------------
# Broker and result backend share the same Redis instance for now; split
# them into two databases (or two Redis instances) once load justifies it.

CELERY_BROKER_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
CELERY_RESULT_BACKEND = os.environ.get("REDIS_URL", "redis://redis:6379/0")
CELERY_TIMEZONE = TIME_ZONE
CELERY_TASK_TRACK_STARTED = True

# Two queues, two workers (docker-compose.yml). "celery" holds what a user
# is waiting for (imports, a host's Ubuntu check); "background" holds the
# long refreshes (NVD can run for an hour, the nightly jobs). On one queue a
# long refresh could hold up a check the user just asked for.
BACKGROUND_QUEUE = "background"
CELERY_TASK_DEFAULT_QUEUE = "celery"
CELERY_TASK_ROUTES = {
    "core.tasks.refresh_nvd": {"queue": BACKGROUND_QUEUE},
    "core.tasks.refresh_kev": {"queue": BACKGROUND_QUEUE},
    "core.tasks.check_all_patches": {"queue": BACKGROUND_QUEUE},
    "core.tasks.refresh_epss": {"queue": BACKGROUND_QUEUE},
    "core.tasks.refresh_priorities": {"queue": BACKGROUND_QUEUE},
    "core.tasks.take_snapshot": {"queue": BACKGROUND_QUEUE},
}
# Each worker process takes one task at a time instead of reserving
# several, so nothing waits behind a long task it happened to be queued after.
CELERY_WORKER_PREFETCH_MULTIPLIER = 1

CELERY_BEAT_SCHEDULE = {
    # Automatic Qualys imports the user set up (QualysImportRule): every 15
    # minutes, due rules import the latest finished run of their scan.
    "qualys-rules": {
        "task": "core.tasks.run_qualys_rules",
        "schedule": crontab(minute="*/15"),
    },
    # CVSS scores for new CVEs and a periodic re-check of known ones.
    "nvd-refresh": {
        "task": "core.tasks.refresh_nvd",
        "schedule": crontab(hour=3, minute=0),
    },
    # CISA Known Exploited Vulnerabilities catalog.
    "kev-refresh": {
        "task": "core.tasks.refresh_kev",
        "schedule": crontab(hour=3, minute=30),
    },
    # EPSS scores are recomputed by FIRST every day.
    "epss-refresh": {
        "task": "core.tasks.refresh_epss",
        "schedule": crontab(hour=3, minute=45),
    },
    # Due dates pass and findings age: priorities follow the calendar.
    "priority-refresh": {
        "task": "core.tasks.refresh_priorities",
        "schedule": crontab(hour=4, minute=30),
    },
    # Re-check findings against the Ubuntu security tracker or Rocky Linux's
    # own errata, whichever applies to each host (core.tasks.check_host_patches).
    "ubuntu-patch-check": {
        "task": "core.tasks.check_all_patches",
        "schedule": crontab(hour=4, minute=0),
    },
    # One snapshot a night (core/history.py): what "As Of <date>" answers with,
    # exactly, for every day from here on. After the nightly re-check and the
    # priority recompute, so it records the state the morning starts from.
    "history-snapshot": {
        "task": "core.tasks.take_snapshot",
        "schedule": crontab(hour=5, minute=0),
    },
}

# --- NVD -------------------------------------------------------------
# CVSS scores are read from the NVD CVE API (core.nvd). Only CVE IDs are
# sent. Without an API key NVD allows 5 requests per 30 s; a free key
# (https://nvd.nist.gov/developers/request-an-api-key) raises it to 50.

NVD_ENABLED = os.environ.get("NVD_ENABLED", "true").lower() == "true"
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
NVD_REFRESH_DAYS = int(os.environ.get("NVD_REFRESH_DAYS", "7"))

# Per-release fix status from the Ubuntu security tracker (core.ubuntu),
# used to check findings against a host's installed packages. Only CVE IDs
# are sent. Tracker data older than this is fetched again before a check.
UBUNTU_TRACKER_ENABLED = os.environ.get("UBUNTU_TRACKER_ENABLED", "true").lower() == "true"
UBUNTU_REFRESH_HOURS = int(os.environ.get("UBUNTU_REFRESH_HOURS", "24"))
# Tracker requests made at the same time by one check, and how long a CVE
# the tracker failed to answer waits before it is asked again.
UBUNTU_TRACKER_WORKERS = max(1, int(os.environ.get("UBUNTU_TRACKER_WORKERS", "8")))
UBUNTU_ERROR_RETRY_MINUTES = int(os.environ.get("UBUNTU_ERROR_RETRY_MINUTES", "60"))

# Same, from Rocky Linux's own errata (core.rocky): per-CVE RLSA advisories,
# only CVE IDs sent. The Rocky equivalent of the block above.
ROCKY_TRACKER_ENABLED = os.environ.get("ROCKY_TRACKER_ENABLED", "true").lower() == "true"
ROCKY_REFRESH_HOURS = int(os.environ.get("ROCKY_REFRESH_HOURS", "24"))
ROCKY_TRACKER_WORKERS = max(1, int(os.environ.get("ROCKY_TRACKER_WORKERS", "8")))
ROCKY_ERROR_RETRY_MINUTES = int(os.environ.get("ROCKY_ERROR_RETRY_MINUTES", "60"))

# CISA Known Exploited Vulnerabilities catalog (core.kev): one public JSON
# file downloaded nightly, nothing sent. Off if the VM has no internet.
KEV_ENABLED = os.environ.get("KEV_ENABLED", "true").lower() == "true"

# FIRST's EPSS scores (core.epss): CVE IDs sent to api.first.org, nothing
# else. Off if the VM has no internet; priorities then ignore EPSS.
EPSS_ENABLED = os.environ.get("EPSS_ENABLED", "true").lower() == "true"

# Package inventory over SSH (core.ssh). The secret encrypts PVM's private
# key in the database; without it SSH is unavailable. The user is the
# dedicated account the sysadmins create on each host; SSH_FROM, if set,
# is PVM's address, written into the suggested authorized_keys line.
SSH_KEY_SECRET = os.environ.get("PVM_SSH_KEY_SECRET", "")
SSH_DEFAULT_USER = os.environ.get("PVM_SSH_USER", "pvm-inventory")
SSH_FROM = os.environ.get("PVM_SSH_FROM", "")

# --- File storage -------------------------------------------------------------
# Qualys VMDR API (core.qualys), reached through Cato on the VM. Nothing is
# imported unless a user picks a scan or creates a rule for it.
QUALYS_API_URL = os.environ.get("QUALYS_API_URL", "")
# The gateway for Qualys CSAM (core.csam): same credentials, token-based.
QUALYS_GATEWAY_URL = os.environ.get("QUALYS_GATEWAY_URL", "")
QUALYS_USERNAME = os.environ.get("QUALYS_USERNAME", "")
QUALYS_PASSWORD = os.environ.get("QUALYS_PASSWORD", "")
QUALYS_SCAN_LIST_DAYS = int(os.environ.get("QUALYS_SCAN_LIST_DAYS", "90"))
# Scans whose title starts with one of these (comma-separated, any case)
# are never listed nor imported: e.g. the cloud connector's daily scans.
QUALYS_EXCLUDED_TITLE_PREFIXES = [
    p.strip().lower() for p in os.environ.get("QUALYS_EXCLUDED_TITLE_PREFIXES", "connector-cps").split(",") if p.strip()
]
# The times of automatic-import rules ("every Monday at 08:00") are in
# this zone; by default the same as TIME_ZONE.
SCHEDULE_TIME_ZONE = os.environ.get("PVM_SCHEDULE_TIME_ZONE", TIME_ZONE)

# Where raw Qualys reports (manual or API) are archived after import, so a
# finding's provenance can always be traced back and reprocessed.

SCAN_IMPORTS_ROOT = Path(os.environ.get("SCAN_IMPORTS_ROOT", BASE_DIR / "scan_imports"))

# Where backup files are written (see backups.service). A named Docker
# volume in docker-compose.yml; download copies from the Backups page to
# keep one off the VM.
BACKUP_ROOT = Path(os.environ.get("BACKUP_ROOT", BASE_DIR / "backups_data"))
