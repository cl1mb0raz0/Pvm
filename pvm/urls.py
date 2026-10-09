from django.contrib import admin
from django.contrib.auth.decorators import login_not_required
from django.urls import include, path
from django.views.generic import RedirectView

urlpatterns = [
    # The admin shares the app's login so it goes through the same MFA
    # step (see accounts.middleware) instead of its password-only form.
    path(
        "admin/login/",
        login_not_required(RedirectView.as_view(pattern_name="accounts:login", query_string=True)),
    ),
    path("admin/", admin.site.urls),
    path("account/", include("accounts.urls")),
    path("backups/", include("backups.urls")),
    path("", include("core.urls")),
]
