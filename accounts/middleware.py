from django.shortcuts import redirect, render
from django.urls import Resolver404, resolve
from django.utils.http import urlencode

from . import mfa

# Views a password-authenticated but not yet OTP-verified user may reach.
EXEMPT_URL_NAMES = {
    "accounts:login",
    "accounts:logout",
    "accounts:mfa_verify",
    "accounts:mfa_enroll",
}


class MFAEnforcementMiddleware:
    """
    Enforces MFA at the application layer, since django-otp has no notion
    of roles: a user who owns a TOTP device must verify it, and an
    admin/analyst without one must enroll, before reaching any other page
    (the Django admin included).
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        step = mfa.pending_step(request.user)
        if step and _view_name(request) not in EXEMPT_URL_NAMES:
            target = "accounts:mfa_verify" if step == mfa.VERIFY else "accounts:mfa_enroll"
            response = redirect(target)
            response["Location"] += "?" + urlencode({"next": request.get_full_path()})
            return response
        # A signed-in user nobody has given a role yet sees nothing.
        if (
            request.user.is_authenticated
            and not request.user.role
            and not request.user.is_superuser
            and _view_name(request) not in EXEMPT_URL_NAMES
        ):
            return render(request, "accounts/no_role.html", status=403)
        return self.get_response(request)


def _view_name(request):
    try:
        return resolve(request.path_info).view_name
    except Resolver404:
        return None
