"""
Sign-in throttling, counted from the audit log.

Every failed password sign-in is written to AuditLog ("auth.login_failed",
with the username typed and the client IP); that same record is what the
limits below count, so they hold across gunicorn workers and restarts
with no extra store. While a limit is exceeded every attempt is refused,
the right password included, and the answer does not say whether it was.

TOTP codes have their own throttling in django-otp.
"""

from datetime import timedelta

from django.conf import settings
from django.utils import timezone

from core.models import AuditLog

FAILED = "auth.login_failed"


def client_ip(request):
    # nginx overwrites X-Real-IP with the peer address; `web` is reachable
    # only through nginx, so the header cannot be forged by the client.
    return request.META.get("HTTP_X_REAL_IP") or request.META.get("REMOTE_ADDR") or ""


def _recent_failures():
    since = timezone.now() - timedelta(minutes=settings.LOGIN_LOCKOUT_MINUTES)
    return AuditLog.objects.filter(action=FAILED, timestamp__gte=since)


def is_locked(username, ip):
    failures = _recent_failures()
    if username and failures.filter(entity_id=username.lower()[:64]).count() >= settings.LOGIN_MAX_FAILURES_PER_USER:
        return True
    return bool(ip) and failures.filter(details__ip=ip).count() >= settings.LOGIN_MAX_FAILURES_PER_IP


def record_failure(username, ip, locked=False):
    AuditLog.objects.create(
        user=None,
        action=FAILED,
        entity_type="accounts.User",
        entity_id=(username or "").lower()[:64],
        details={"ip": ip, "locked": locked},
    )
