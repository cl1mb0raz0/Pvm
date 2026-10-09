from base64 import b32encode

import qrcode
import qrcode.image.svg
from django.contrib.auth import views as auth_views
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme, urlencode
from django.views.decorators.http import require_POST
from django_otp import login as otp_login
from django_otp import match_token
from django_otp.plugins.otp_static.models import StaticDevice
from django_otp.plugins.otp_totp.models import TOTPDevice

from core import audit

from . import mfa, throttle
from .forms import LoginForm, TokenForm

# Backup codes are shown exactly once, on the page right after they are
# issued; they travel there through the session and are popped on display.
BACKUP_CODES_SESSION_KEY = "pvm_new_backup_codes"


class LoginView(auth_views.LoginView):
    template_name = "accounts/login.html"
    redirect_authenticated_user = True
    form_class = LoginForm

    def form_valid(self, form):
        response = super().form_valid(form)
        audit.log(form.get_user(), "auth.login", form.get_user(), ip=throttle.client_ip(self.request))
        return response


def mfa_verify(request):
    if mfa.pending_step(request.user) != mfa.VERIFY:
        return redirect(_next_url(request))

    form = TokenForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        device = match_token(request.user, form.cleaned_data["token"])
        if device:
            otp_login(request, device)
            if isinstance(device, StaticDevice):
                audit.log(request.user, "mfa.backup_code_used", request.user)
            return redirect(_next_url(request))
        form.add_error("token", "Invalid or Expired Code.")

    return render(request, "accounts/mfa_verify.html", {"form": form, "next": _next_url(request)})


def mfa_enroll(request):
    user = request.user
    if mfa.has_confirmed_totp(user):
        return redirect("accounts:account")

    # Reuse the pending device across page reloads so the QR code already
    # scanned into the authenticator app stays valid.
    device = TOTPDevice.objects.filter(user=user, confirmed=False).first()
    if device is None:
        device = TOTPDevice.objects.create(user=user, name="Authenticator app", confirmed=False)

    form = TokenForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        if device.verify_token(form.cleaned_data["token"]):
            device.confirmed = True
            device.save(update_fields=["confirmed"])
            user.mfa_confirmed_at = timezone.now()
            user.save(update_fields=["mfa_confirmed_at"])
            otp_login(request, device)
            request.session[BACKUP_CODES_SESSION_KEY] = mfa.issue_backup_codes(user)
            audit.log(user, "mfa.enrolled", user)
            return redirect(_with_next("accounts:backup_codes", _next_url(request)))
        form.add_error("token", "That Code Does Not Match. Check the Time on Your Device and Try Again.")

    qr_svg = qrcode.make(device.config_url, image_factory=qrcode.image.svg.SvgPathImage, box_size=8, border=2)
    return render(
        request,
        "accounts/mfa_enroll.html",
        {
            "form": form,
            "qr_svg": qr_svg.to_string(encoding="unicode"),
            "secret": b32encode(device.bin_key).decode(),
            "next": _next_url(request),
            "required": user.mfa_required,
        },
    )


def backup_codes(request):
    codes = request.session.pop(BACKUP_CODES_SESSION_KEY, None)
    return render(request, "accounts/backup_codes.html", {"codes": codes, "next": _next_url(request)})


@require_POST
def regenerate_backup_codes(request):
    if not mfa.has_confirmed_totp(request.user):
        return redirect("accounts:account")
    request.session[BACKUP_CODES_SESSION_KEY] = mfa.issue_backup_codes(request.user)
    audit.log(request.user, "mfa.backup_codes_regenerated", request.user)
    return redirect(_with_next("accounts:backup_codes", reverse("accounts:account")))


def account(request):
    user = request.user
    return render(
        request,
        "accounts/account.html",
        {
            "has_totp": mfa.has_confirmed_totp(user),
            "backup_codes_left": mfa.remaining_backup_codes(user),
        },
    )


def _next_url(request):
    url = request.POST.get("next") or request.GET.get("next")
    if url and url_has_allowed_host_and_scheme(url, allowed_hosts={request.get_host()}, require_https=request.is_secure()):
        return url
    return reverse("core:dashboard")


def _with_next(view_name, next_url):
    return reverse(view_name) + "?" + urlencode({"next": next_url})
