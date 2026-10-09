from django.contrib.auth import views as auth_views
from django.urls import path

from . import views

app_name = "accounts"

urlpatterns = [
    path("login/", views.LoginView.as_view(), name="login"),
    path("logout/", auth_views.LogoutView.as_view(), name="logout"),
    path("mfa/verify/", views.mfa_verify, name="mfa_verify"),
    path("mfa/enroll/", views.mfa_enroll, name="mfa_enroll"),
    path("mfa/backup-codes/", views.backup_codes, name="backup_codes"),
    path("mfa/backup-codes/regenerate/", views.regenerate_backup_codes, name="regenerate_backup_codes"),
    path("", views.account, name="account"),
]
