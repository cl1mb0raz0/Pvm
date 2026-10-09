from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import Group

from .models import Team, User

# PVM's permissions come from User.role (see accounts/permissions.py), not
# from Django's groups and per-model permissions, so those are hidden: they
# would only suggest a second, unused permission system.
admin.site.unregister(Group)


@admin.register(Team)
class TeamAdmin(admin.ModelAdmin):
    list_display = ("name", "description")
    search_fields = ("name",)


class PVMUserCreationForm(UserCreationForm):
    """The admin's "add user" form, with the role chosen up front (required)."""

    class Meta(UserCreationForm.Meta):
        model = User
        fields = ("username", "email", "role", "team")


@admin.register(User)
class UserAdmin(DjangoUserAdmin):
    add_form = PVMUserCreationForm
    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": ("username", "email", "role", "team", "password1", "password2"),
            },
        ),
    )
    list_display = ("email", "username", "role", "team", "auth_provider", "is_mfa_enabled", "is_active")
    list_filter = ("role", "auth_provider", "team", "is_active")
    fieldsets = (
        (None, {"fields": ("username", "password")}),
        ("Personal info", {"fields": ("first_name", "last_name", "email")}),
        ("Pvm", {"fields": ("role", "team", "auth_provider", "mfa_confirmed_at")}),
        ("Status", {"fields": ("is_active", "is_staff", "is_superuser")}),
        ("Important dates", {"fields": ("last_login", "date_joined")}),
    )
    filter_horizontal = ()

    @admin.display(boolean=True, description="MFA enabled")
    def is_mfa_enabled(self, obj):
        return obj.mfa_enabled
