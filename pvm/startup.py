"""Checks run when a long-lived process (gunicorn, Celery) starts, not at image build."""

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

PLACEHOLDERS = ("", "insecure-dev-key-change-me", "change-me-to-a-long-random-value")


def require_real_secret_key():
    """Refuse to run with a missing or example DJANGO_SECRET_KEY (sessions could be forged)."""
    if settings.DEBUG:
        return
    key = settings.SECRET_KEY
    if key in PLACEHOLDERS or key.startswith("change-me") or len(key) < 32:
        raise ImproperlyConfigured(
            "DJANGO_SECRET_KEY is missing, an example value or shorter than 32 characters. "
            "Set a long random value in .env, e.g. the output of: "
            "python3 -c 'import secrets; print(secrets.token_urlsafe(64))'"
        )
