from datetime import timedelta

from django.test import TestCase
from django.utils import timezone
from django_otp.oath import totp
from django_otp.plugins.otp_totp.models import TOTPDevice

from core.models import AuditLog

from .models import User
from .permissions import can_edit

PASSWORD = "correct-horse-battery"


def current_code(device):
    return f"{totp(device.bin_key, device.step, device.t0, device.digits, device.drift):06d}"


class MFAFlowTests(TestCase):
    def setUp(self):
        self.analyst = User.objects.create_user("ana", "ana@example.com", PASSWORD, role=User.Role.ANALYST)
        self.readonly = User.objects.create_user("ro", "ro@example.com", PASSWORD, role=User.Role.READONLY)

    def login(self, username):
        self.client.post("/account/login/", {"username": username, "password": PASSWORD})

    def enroll(self):
        self.client.get("/account/mfa/enroll/")
        device = TOTPDevice.objects.get(user=self.analyst)
        response = self.client.post("/account/mfa/enroll/", {"token": current_code(device), "next": "/hosts/"})
        return device, response

    def test_anonymous_is_sent_to_login(self):
        response = self.client.get("/")
        self.assertRedirects(response, "/account/login/?next=/", fetch_redirect_response=False)

    def test_admin_login_uses_app_login(self):
        response = self.client.get("/admin/login/?next=/admin/")
        self.assertRedirects(response, "/account/login/?next=/admin/", fetch_redirect_response=False)

    def test_analyst_without_device_must_enroll_everywhere(self):
        self.login("ana")
        for url in ["/", "/hosts/", "/admin/", "/does-not-exist/"]:
            response = self.client.get(url)
            self.assertEqual(response.status_code, 302, url)
            self.assertTrue(response["Location"].startswith("/account/mfa/enroll/"), url)

    def test_staff_needs_mfa_whatever_the_role(self):
        User.objects.create_superuser("root", "root@example.com", PASSWORD)
        self.login("root")
        self.assertTrue(self.client.get("/admin/")["Location"].startswith("/account/mfa/enroll/"))

    def test_readonly_without_device_is_let_in(self):
        self.login("ro")
        self.assertEqual(self.client.get("/").status_code, 200)

    def test_enrollment_confirms_device_and_shows_backup_codes_once(self):
        self.login("ana")
        device, response = self.enroll()
        self.assertTrue(response["Location"].startswith("/account/mfa/backup-codes/"))

        device.refresh_from_db()
        self.analyst.refresh_from_db()
        self.assertTrue(device.confirmed)
        self.assertIsNotNone(self.analyst.mfa_confirmed_at)

        page = self.client.get(response["Location"])
        self.assertEqual(len(page.context["codes"]), 10)
        self.assertEqual(page.context["next"], "/hosts/")
        self.assertIsNone(self.client.get("/account/mfa/backup-codes/").context["codes"])
        self.assertEqual(self.client.get("/").status_code, 200)
        self.assertTrue(AuditLog.objects.filter(action="mfa.enrolled").exists())

    def test_wrong_enrollment_code_is_rejected(self):
        self.login("ana")
        self.client.get("/account/mfa/enroll/")
        response = self.client.post("/account/mfa/enroll/", {"token": "000000"})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(TOTPDevice.objects.get(user=self.analyst).confirmed)

    def test_enrolled_user_must_verify_and_backup_code_is_single_use(self):
        self.login("ana")
        _, response = self.enroll()
        code = self.client.get(response["Location"]).context["codes"][0]
        self.client.post("/account/logout/")

        self.login("ana")
        self.assertTrue(self.client.get("/")["Location"].startswith("/account/mfa/verify/"))
        response = self.client.post("/account/mfa/verify/", {"token": code.upper(), "next": "/hosts/"})
        self.assertRedirects(response, "/hosts/", fetch_redirect_response=False)
        self.assertTrue(AuditLog.objects.filter(action="mfa.backup_code_used").exists())

        self.client.post("/account/logout/")
        self.login("ana")
        response = self.client.post("/account/mfa/verify/", {"token": code})
        self.assertEqual(response.status_code, 200)

    def test_verify_ignores_offsite_next(self):
        self.login("ana")
        _, response = self.enroll()
        code = self.client.get(response["Location"]).context["codes"][0]
        self.client.post("/account/logout/")
        self.login("ana")
        response = self.client.post("/account/mfa/verify/", {"token": code, "next": "https://evil.example/"})
        self.assertRedirects(response, "/", fetch_redirect_response=False)

    def test_regenerating_backup_codes_invalidates_old_ones(self):
        self.login("ana")
        _, response = self.enroll()
        old = set(self.client.get(response["Location"]).context["codes"])
        response = self.client.post("/account/mfa/backup-codes/regenerate/")
        new = set(self.client.get(response["Location"]).context["codes"])
        self.assertFalse(old & new)
        self.assertEqual(self.client.get("/account/").context["backup_codes_left"], 10)


class SuperAdminTests(TestCase):
    def test_createsuperuser_makes_a_super_admin(self):
        root = User.objects.create_superuser("root", "root@example.com", PASSWORD)
        self.assertEqual(root.role, User.Role.SUPER_ADMIN)
        self.assertTrue(root.mfa_required)

    def test_super_admin_role_grants_django_admin(self):
        user = User.objects.create_user("boss", "boss@example.com", PASSWORD, role=User.Role.SUPER_ADMIN)
        self.assertTrue(user.is_staff)
        self.assertTrue(user.is_superuser)

    def test_super_admin_can_edit(self):
        user = User.objects.create_user("boss", "boss@example.com", PASSWORD, role=User.Role.SUPER_ADMIN)
        self.assertTrue(can_edit(user))


class RoleRequiredTests(TestCase):
    def test_admin_add_form_requires_a_role(self):
        from .admin import PVMUserCreationForm

        data = {"username": "new", "email": "new@example.com", "password1": PASSWORD, "password2": PASSWORD}
        form = PVMUserCreationForm(data)
        self.assertFalse(form.is_valid())
        self.assertIn("role", form.errors)

        form = PVMUserCreationForm({**data, "role": User.Role.ANALYST})
        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(form.save().role, User.Role.ANALYST)

    def test_user_without_role_sees_nothing(self):
        User.objects.create_user("norole", "norole@example.com", PASSWORD)
        self.client.post("/account/login/", {"username": "norole", "password": PASSWORD})
        for url in ["/", "/vulnerabilities/", "/imports/", "/account/"]:
            response = self.client.get(url)
            self.assertEqual(response.status_code, 403, url)
            self.assertContains(response, "No Role Assigned", status_code=403)

    def test_admin_add_user_page_asks_for_role(self):
        root = User.objects.create_superuser("root", "root@example.com", PASSWORD)
        device = TOTPDevice.objects.create(user=root, name="app", confirmed=True)
        self.client.post("/account/login/", {"username": "root", "password": PASSWORD})
        self.client.post("/account/mfa/verify/", {"token": current_code(device)})
        response = self.client.get("/admin/accounts/user/add/")
        self.assertContains(response, 'name="role"')
        self.assertContains(response, '<option value="" selected>---------</option>', html=True)


class AdminWithoutGroupsTests(TestCase):
    def setUp(self):
        root = User.objects.create_superuser("root", "root@example.com", PASSWORD)
        device = TOTPDevice.objects.create(user=root, name="app", confirmed=True)
        self.client.post("/account/login/", {"username": "root", "password": PASSWORD})
        self.client.post("/account/mfa/verify/", {"token": current_code(device)})
        self.root = root

    def test_groups_are_not_in_the_admin(self):
        self.assertEqual(self.client.get("/admin/auth/group/").status_code, 404)
        self.assertNotContains(self.client.get("/admin/"), "/admin/auth/group/")

    def test_user_form_shows_role_not_groups(self):
        page = self.client.get(f"/admin/accounts/user/{self.root.pk}/change/")
        self.assertContains(page, 'name="role"')
        self.assertNotContains(page, 'name="groups"')
        self.assertNotContains(page, 'name="user_permissions"')

    def test_saving_a_user_still_works(self):
        analyst = User.objects.create_user("ana", "ana@example.com", PASSWORD, role=User.Role.ANALYST)
        response = self.client.post(
            f"/admin/accounts/user/{analyst.pk}/change/",
            {
                "username": "ana",
                "email": "ana@example.com",
                "role": User.Role.ADMIN,
                "auth_provider": "local",
                "is_active": "on",
                "date_joined_0": "2026-09-23",
                "date_joined_1": "10:00:00",
            },
        )
        self.assertEqual(response.status_code, 302, response.content[:2000])
        analyst.refresh_from_db()
        self.assertEqual(analyst.role, User.Role.ADMIN)


class LoginThrottleTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("ro", "ro@example.com", PASSWORD, role=User.Role.READONLY)

    def attempt(self, password, username="ro", ip="198.51.100.7"):
        return self.client.post("/account/login/", {"username": username, "password": password}, HTTP_X_REAL_IP=ip)

    def test_success_and_failure_are_audited(self):
        self.attempt("wrong-password")
        self.assertEqual(self.attempt(PASSWORD).status_code, 302)
        actions = list(AuditLog.objects.order_by("timestamp").values_list("action", flat=True))
        self.assertEqual(actions, ["auth.login_failed", "auth.login"])
        self.assertEqual(AuditLog.objects.get(action="auth.login_failed").details["ip"], "198.51.100.7")

    def test_user_is_locked_after_five_failures_even_with_the_right_password(self):
        for _ in range(5):
            self.assertContains(self.attempt("wrong-password"), "Wrong Username or Password.")
        response = self.attempt(PASSWORD)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Too Many Failed Attempts. Try Again in 15 Minutes.")
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_lock_expires_with_the_window(self):
        for _ in range(5):
            self.attempt("wrong-password")
        AuditLog.objects.update(timestamp=timezone.now() - timedelta(minutes=16))
        self.assertEqual(self.attempt(PASSWORD).status_code, 302)

    def test_ip_is_locked_after_twenty_failures_across_usernames(self):
        for i in range(20):
            self.attempt("wrong-password", username=f"guess{i}")
        self.assertContains(self.attempt(PASSWORD), "Too Many Failed Attempts")
        # Another address is not affected.
        self.assertEqual(self.attempt(PASSWORD, ip="198.51.100.8").status_code, 302)

    def test_session_expires_after_idle_hours(self):
        self.attempt(PASSWORD)
        self.assertLessEqual(self.client.session.get_expiry_age(), 8 * 3600)
