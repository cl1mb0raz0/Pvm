"""
MFA helpers shared by the enforcement middleware and the auth views.

TOTP devices and backup codes are django-otp models (otp_totp / otp_static);
this module only decides which step a user still has to complete and
issues backup codes.
"""

from django_otp.plugins.otp_static.models import StaticDevice, StaticToken
from django_otp.plugins.otp_totp.models import TOTPDevice

BACKUP_CODE_COUNT = 10
BACKUP_DEVICE_NAME = "backup"

VERIFY = "verify"
ENROLL = "enroll"


def has_confirmed_totp(user):
    return TOTPDevice.objects.devices_for_user(user, confirmed=True).exists()


def pending_step(user):
    """
    Return the MFA step still required before `user` may use the app:
    VERIFY (has a device, must enter a code), ENROLL (role requires MFA
    but no device yet) or None (nothing left to do).
    """
    if not user.is_authenticated or user.is_verified():
        return None
    if has_confirmed_totp(user):
        return VERIFY
    if user.mfa_required:
        return ENROLL
    return None


def issue_backup_codes(user):
    """Replace the user's backup codes with a fresh set and return them."""
    device, _ = StaticDevice.objects.get_or_create(user=user, name=BACKUP_DEVICE_NAME)
    device.token_set.all().delete()
    codes = [StaticToken.random_token() for _ in range(BACKUP_CODE_COUNT)]
    StaticToken.objects.bulk_create(StaticToken(device=device, token=code) for code in codes)
    return codes


def remaining_backup_codes(user):
    return StaticToken.objects.filter(device__user=user, device__name=BACKUP_DEVICE_NAME).count()
