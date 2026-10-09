from django.contrib.auth.models import AbstractUser, UserManager
from django.db import models


class Team(models.Model):
    """A group vulnerabilities can be assigned to (e.g. Platform, DevOps)."""

    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name


class PVMUserManager(UserManager):
    def create_superuser(self, username, email=None, password=None, **extra_fields):
        # A Django superuser is a Super Admin in PVM, not the default read-only.
        extra_fields.setdefault("role", User.Role.SUPER_ADMIN)
        return super().create_superuser(username, email, password, **extra_fields)


class User(AbstractUser):
    """
    Application user.

    MFA itself (TOTP devices and backup/static tokens) is handled by
    django-otp (django_otp.plugins.otp_totp / otp_static); this model only
    tracks role, team and whether enrollment has been completed.
    """

    class Role(models.TextChoices):
        SUPER_ADMIN = "superadmin", "Super Admin"
        ADMIN = "admin", "Admin"
        ANALYST = "analyst", "Analyst"
        READONLY = "readonly", "Read-Only"

    class AuthProvider(models.TextChoices):
        LOCAL = "local", "Local (TOTP)"
        SSO = "sso", "Single Sign-On"

    email = models.EmailField(unique=True)
    # No default on purpose: whoever creates a user must choose the role.
    # A user left without one can sign in but reaches no page
    # (see accounts.middleware).
    role = models.CharField(max_length=16, choices=Role.choices)
    team = models.ForeignKey(
        Team, on_delete=models.SET_NULL, null=True, blank=True, related_name="members"
    )
    auth_provider = models.CharField(
        max_length=16, choices=AuthProvider.choices, default=AuthProvider.LOCAL
    )
    # Set once the user has confirmed their first TOTP device; used to
    # enforce mandatory MFA for admin/analyst roles at the application layer.
    mfa_confirmed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    objects = PVMUserManager()

    class Meta:
        ordering = ["email"]

    def __str__(self):
        return self.email

    def save(self, *args, **kwargs):
        # Super Admin can do everything, the Django admin included.
        if self.role == self.Role.SUPER_ADMIN:
            self.is_staff = True
            self.is_superuser = True
        super().save(*args, **kwargs)

    @property
    def mfa_enabled(self):
        return self.mfa_confirmed_at is not None

    @property
    def mfa_required(self):
        """
        Admins and analysts must have MFA enabled; read-only is optional.
        Anyone with Django admin access needs it too, whatever their role.
        """
        return self.is_staff or self.role in {self.Role.SUPER_ADMIN, self.Role.ADMIN, self.Role.ANALYST}
