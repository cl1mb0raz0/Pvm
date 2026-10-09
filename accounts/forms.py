from django import forms
from django.conf import settings
from django.contrib.auth.forms import AuthenticationForm
from django.core.exceptions import ValidationError

from . import throttle


class TokenForm(forms.Form):
    """A TOTP code or a backup code, entered after the password step."""

    token = forms.CharField(
        max_length=32,
        widget=forms.TextInput(attrs={"autocomplete": "one-time-code", "autofocus": True}),
    )

    def clean_token(self):
        # Tolerate the spaces authenticator apps display ("123 456") and
        # the case of backup codes, which django-otp stores in lowercase.
        return "".join(self.cleaned_data["token"].split()).lower()


class LoginForm(AuthenticationForm):
    """Django's sign-in form, refusing attempts while the limits in accounts/throttle.py are exceeded."""

    error_messages = {
        **AuthenticationForm.error_messages,
        "invalid_login": "Wrong Username or Password.",
        "inactive": "This Account Is Disabled.",
        "locked": "Too Many Failed Attempts. Try Again in %(minutes)s Minutes.",
    }

    def clean(self):
        username = self.cleaned_data.get("username") or ""
        ip = throttle.client_ip(self.request)
        if throttle.is_locked(username, ip):
            throttle.record_failure(username, ip, locked=True)
            raise ValidationError(
                self.error_messages["locked"], code="locked", params={"minutes": settings.LOGIN_LOCKOUT_MINUTES}
            )
        try:
            return super().clean()
        except ValidationError:
            throttle.record_failure(username, ip)
            raise
