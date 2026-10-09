import shutil
import tarfile
from decimal import Decimal
from io import StringIO
from pathlib import Path
from unittest import mock

from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.test import TestCase
from django_otp.plugins.otp_static.models import StaticDevice, StaticToken
from django_otp.plugins.otp_totp.models import TOTPDevice

from accounts.models import Team, User
from accounts.tests import current_code
from core.models import (
    AuditLog,
    Cve,
    Host,
    LoadBalancer,
    Perimeter,
    ScanImport,
    VulnerabilityDefinition,
    VulnerabilityFinding,
)
from core.tests_imports import PASSWORD, ImportTestMixin

from . import service
from .models import Backup


class BackupTests(ImportTestMixin, TestCase):
    def login_as(self, role):
        self.client.post("/account/logout/")
        user = User.objects.create_user(f"u-{role}", f"{role}@example.com", PASSWORD, role=role)
        device = TOTPDevice.objects.create(user=user, name="app", confirmed=True)
        self.client.post("/account/login/", {"username": user.username, "password": PASSWORD})
        self.client.post("/account/mfa/verify/", {"token": current_code(device)})
        return user

    def restore(self, backup, confirm="RESTORE"):
        return self.client.post(f"/backups/{backup.pk}/restore/", {"confirm": confirm})

    def test_every_import_is_preceded_by_a_backup(self):
        scan_import = self.full_import()
        backup = Backup.objects.get(kind=Backup.Kind.PRE_IMPORT)
        self.assertEqual(backup.scan_import_id, scan_import.pk)
        self.assertEqual(backup.status, Backup.Status.COMPLETED)
        # Taken before the data went in.
        self.assertEqual(backup.contents["findings"], 0)
        self.assertTrue(service.backup_path(backup).is_file())

    def test_import_stops_if_its_backup_fails(self):
        failed = Backup(kind=Backup.Kind.PRE_IMPORT, status=Backup.Status.FAILED, error_message="disk full")
        with mock.patch("core.tasks.create_backup", return_value=failed):
            scan_import = self.full_import()
        self.assertEqual(scan_import.status, ScanImport.Status.FAILED)
        self.assertIn("disk full", scan_import.error_message)
        self.assertFalse(VulnerabilityFinding.objects.exists())

    def test_undo_import_by_restoring_its_backup(self):
        self.login_as(User.Role.SUPER_ADMIN)
        scan_import = self.full_import()
        self.assertEqual(VulnerabilityFinding.objects.count(), 7)
        backup = Backup.objects.get(kind=Backup.Kind.PRE_IMPORT)

        detail = self.client.get(f"/imports/{scan_import.pk}/")
        self.assertContains(detail, f"/backups/{backup.pk}/restore/")

        response = self.restore(backup)
        self.assertRedirects(response, "/backups/", fetch_redirect_response=False)
        self.assertFalse(VulnerabilityFinding.objects.exists())
        self.assertFalse(Host.objects.exists())
        # The import row existed (running) when the backup was taken.
        scan_import.refresh_from_db()
        self.assertEqual(scan_import.status, ScanImport.Status.FAILED)
        self.assertIn("Rolled Back", scan_import.error_message)

        # The restore itself is undoable, and the backup list survived it.
        safety = Backup.objects.get(kind=Backup.Kind.PRE_RESTORE)
        self.assertEqual(safety.contents["findings"], 7)
        self.assertEqual(Backup.objects.count(), 2)
        backup.refresh_from_db()
        self.assertIsNotNone(backup.restored_at)
        self.assertTrue(AuditLog.objects.filter(action="backup.restored").exists())

        self.restore(safety)
        self.assertEqual(VulnerabilityFinding.objects.count(), 7)

    def test_restore_keeps_users_and_mfa(self):
        admin = self.login_as(User.Role.SUPER_ADMIN)
        self.client.post("/backups/new/", {"note": "baseline"})
        backup = Backup.objects.get(kind=Backup.Kind.MANUAL)
        self.assertEqual(backup.note, "baseline")
        self.restore(backup)
        self.assertTrue(User.objects.filter(pk=admin.pk).exists())
        self.assertTrue(TOTPDevice.objects.filter(user=admin).exists())

    def test_wrong_confirmation_restores_nothing(self):
        self.login_as(User.Role.SUPER_ADMIN)
        self.client.post("/backups/new/")
        backup = Backup.objects.get()
        Host.objects.create(hostname="added-later", ip_address="192.0.2.99")
        response = self.restore(backup, confirm="yes")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(Host.objects.filter(hostname="added-later").exists())
        self.assertEqual(Backup.objects.count(), 1)

    def test_delete_and_download(self):
        self.login_as(User.Role.SUPER_ADMIN)
        self.client.post("/backups/new/")
        backup = Backup.objects.get()
        path = service.backup_path(backup)

        response = self.client.get(f"/backups/{backup.pk}/download/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("attachment", response["Content-Disposition"])
        self.assertTrue(b"".join(response.streaming_content))

        self.client.post(f"/backups/{backup.pk}/delete/")
        self.assertFalse(Backup.objects.exists())
        self.assertFalse(Path(path).exists())

    def test_rename(self):
        self.login_as(User.Role.ADMIN)
        self.client.post("/backups/new/", {"note": "original"})
        backup = Backup.objects.get()

        response = self.client.post(f"/backups/{backup.pk}/rename/", {"note": "before the client demo"})
        self.assertRedirects(response, "/backups/", fetch_redirect_response=False)
        backup.refresh_from_db()
        self.assertEqual(backup.note, "before the client demo")
        entry = AuditLog.objects.get(action="backup.renamed")
        self.assertEqual(entry.details, {"before": "original", "after": "before the client demo"})

        # Saving the same text again writes no extra audit entry.
        self.client.post(f"/backups/{backup.pk}/rename/", {"note": "before the client demo"})
        self.assertEqual(AuditLog.objects.filter(action="backup.renamed").count(), 1)

        # Blank clears the name.
        self.client.post(f"/backups/{backup.pk}/rename/", {"note": "  "})
        backup.refresh_from_db()
        self.assertEqual(backup.note, "")

    def test_rename_is_refused_to_analysts(self):
        # Analyst (the default session of ImportTestMixin): no backups at all.
        backup = service.create_backup(Backup.Kind.MANUAL)
        self.assertEqual(self.client.post(f"/backups/{backup.pk}/rename/", {"note": "x"}).status_code, 403)

    def test_permissions(self):
        # Analyst (the default session of ImportTestMixin): no backups at all.
        self.assertEqual(self.client.post("/backups/delete-all/", {"confirm": "DELETE BACKUPS"}).status_code, 403)
        self.assertEqual(self.client.get("/backups/").status_code, 403)
        self.assertEqual(self.client.post("/backups/new/").status_code, 403)

        # Admin: list and create, but not restore, delete or download.
        self.login_as(User.Role.ADMIN)
        self.assertEqual(self.client.get("/backups/").status_code, 200)
        self.client.post("/backups/new/")
        backup = Backup.objects.get()
        self.assertEqual(self.client.get(f"/backups/{backup.pk}/restore/").status_code, 403)
        self.assertEqual(self.client.post(f"/backups/{backup.pk}/delete/").status_code, 403)
        self.assertEqual(self.client.get(f"/backups/{backup.pk}/download/").status_code, 403)

        # Super Admin: everything.
        self.login_as(User.Role.SUPER_ADMIN)
        self.assertEqual(self.client.get(f"/backups/{backup.pk}/restore/").status_code, 200)

    def test_restore_refused_while_an_import_runs(self):
        user = self.login_as(User.Role.SUPER_ADMIN)
        backup = service.create_backup(Backup.Kind.MANUAL, user)
        ScanImport.objects.create(source=ScanImport.Source.MANUAL, status=ScanImport.Status.PARSING)
        with self.assertRaises(service.BackupError):
            service.restore_backup(backup, user)


class FullBackupTests(ImportTestMixin, TestCase):
    """A full backup bundles the raw Qualys report files (scan_imports) with the database dump."""

    def login_as(self, role):
        self.client.post("/account/logout/")
        user = User.objects.create_user(f"u-{role}", f"{role}@example.com", PASSWORD, role=role)
        device = TOTPDevice.objects.create(user=user, name="app", confirmed=True)
        self.client.post("/account/login/", {"username": user.username, "password": PASSWORD})
        self.client.post("/account/mfa/verify/", {"token": current_code(device)})
        return user

    def setUp(self):
        super().setUp()
        self.boss = self.login_as(User.Role.SUPER_ADMIN)
        self.import1 = self.full_import()

    def test_full_backup_bundles_the_report_files(self):
        backup = service.create_backup(Backup.Kind.MANUAL, self.boss, full=True)
        self.assertEqual(backup.status, Backup.Status.COMPLETED)
        self.assertTrue(backup.full)
        self.assertTrue(backup.file_name.endswith(".tar.gz"))
        self.assertEqual(backup.contents["report_files"], 1)
        with tarfile.open(service.backup_path(backup), "r:gz") as tar:
            names = tar.getnames()
        self.assertIn("data.json.gz", names)
        self.assertTrue(any(n.startswith(f"scan_imports/{self.import1.pk}/") for n in names))
        # No stray dump file left behind next to it.
        self.assertEqual(list(Path(self.backup_root).glob(".*-data.json.gz")), [])

    def test_regular_backup_does_not_bundle_report_files(self):
        backup = service.create_backup(Backup.Kind.MANUAL, self.boss)
        self.assertFalse(backup.full)
        self.assertTrue(backup.file_name.endswith(".json.gz"))
        self.assertNotIn("report_files", backup.contents)

    def test_full_backup_button_in_the_ui(self):
        response = self.client.post("/backups/new-full/", {"note": "before moving servers"})
        self.assertRedirects(response, "/backups/", fetch_redirect_response=False)
        backup = Backup.objects.get(full=True)
        self.assertTrue(backup.full)
        self.assertEqual(backup.note, "before moving servers")
        self.assertTrue(AuditLog.objects.filter(action="backup.created", entity_id=str(backup.pk)).exists())

    def test_full_backup_creation_is_refused_to_readonly(self):
        self.client.post("/account/logout/")
        User.objects.create_user("ro", "ro@example.com", PASSWORD, role=User.Role.READONLY)
        self.client.post("/account/login/", {"username": "ro", "password": PASSWORD})
        self.assertEqual(self.client.post("/backups/new-full/").status_code, 403)

    def test_full_restore_brings_back_deleted_report_files(self):
        backup = service.create_backup(Backup.Kind.MANUAL, self.boss, full=True)
        folder = Path(self.imports_root) / str(self.import1.pk)
        self.assertTrue(folder.is_dir())
        shutil.rmtree(folder)
        self.assertFalse(folder.is_dir())

        service.restore_backup(backup, self.boss)
        self.assertTrue(folder.is_dir())
        self.assertTrue(any(folder.iterdir()))

    def test_full_restore_replaces_report_files_rather_than_merging(self):
        backup = service.create_backup(Backup.Kind.MANUAL, self.boss, full=True)
        extra = Path(self.imports_root) / "not-in-the-backup"
        extra.mkdir()
        (extra / "marker.txt").write_text("x")

        service.restore_backup(backup, self.boss)
        self.assertFalse(extra.exists())
        self.assertTrue((Path(self.imports_root) / str(self.import1.pk)).is_dir())

    def test_safety_backup_before_a_full_restore_is_also_full(self):
        backup = service.create_backup(Backup.Kind.MANUAL, self.boss, full=True)
        safety = service.restore_backup(backup, self.boss)
        self.assertTrue(safety.full)
        self.assertEqual(safety.kind, Backup.Kind.PRE_RESTORE)
        self.assertTrue(safety.contents.get("report_files"))

    def test_corrupt_full_backup_archive_is_refused(self):
        backup = service.create_backup(Backup.Kind.MANUAL, self.boss, full=True)
        service.backup_path(backup).write_bytes(b"not a tar file")
        with self.assertRaises(service.BackupError):
            service.restore_backup(backup, self.boss)
        # Nothing was touched: the report folder is still there.
        self.assertTrue((Path(self.imports_root) / str(self.import1.pk)).is_dir())


class UploadBackupTests(ImportTestMixin, TestCase):
    """Imports > Backup: upload a backup file, taken here or on another install, and restore it."""

    def login_as(self, role):
        self.client.post("/account/logout/")
        user = User.objects.create_user(f"u-{role}", f"{role}@example.com", PASSWORD, role=role)
        device = TOTPDevice.objects.create(user=user, name="app", confirmed=True)
        self.client.post("/account/login/", {"username": user.username, "password": PASSWORD})
        self.client.post("/account/mfa/verify/", {"token": current_code(device)})
        return user

    def setUp(self):
        super().setUp()
        self.boss = self.login_as(User.Role.SUPER_ADMIN)
        self.import1 = self.full_import()

    def upload_backup(self, backup, name="upload.dat"):
        content = service.backup_path(backup).read_bytes()
        return self.client.post("/imports/backup/upload/", {"file": SimpleUploadedFile(name, content)})

    def test_upload_a_full_backup_registers_it(self):
        source = service.create_backup(Backup.Kind.MANUAL, self.boss, full=True)
        response = self.upload_backup(source, "from-other-server.tar.gz")
        uploaded = Backup.objects.get(kind=Backup.Kind.UPLOADED)
        self.assertRedirects(response, f"/backups/{uploaded.pk}/restore/", fetch_redirect_response=False)
        self.assertTrue(uploaded.full)
        self.assertEqual(uploaded.status, Backup.Status.COMPLETED)
        self.assertEqual(uploaded.contents["hosts"], source.contents["hosts"])
        self.assertEqual(uploaded.contents["report_files"], source.contents["report_files"])
        self.assertTrue(AuditLog.objects.filter(action="backup.uploaded").exists())

    def test_upload_a_regular_backup_registers_it(self):
        source = service.create_backup(Backup.Kind.MANUAL, self.boss)
        response = self.upload_backup(source, "from-other-server.json.gz")
        uploaded = Backup.objects.get(kind=Backup.Kind.UPLOADED)
        self.assertRedirects(response, f"/backups/{uploaded.pk}/restore/", fetch_redirect_response=False)
        self.assertFalse(uploaded.full)
        self.assertEqual(uploaded.contents["findings"], source.contents["findings"])
        self.assertNotIn("report_files", uploaded.contents)

    def test_uploading_then_restoring_brings_back_the_other_installation(self):
        source = service.create_backup(Backup.Kind.MANUAL, self.boss, full=True)
        self.upload_backup(source)
        uploaded = Backup.objects.get(kind=Backup.Kind.UPLOADED)
        folder = Path(self.imports_root) / str(self.import1.pk)
        shutil.rmtree(folder)
        VulnerabilityFinding.objects.all().delete()

        response = self.client.post(f"/backups/{uploaded.pk}/restore/", {"confirm": "RESTORE"})
        self.assertRedirects(response, "/backups/", fetch_redirect_response=False)
        self.assertEqual(VulnerabilityFinding.objects.count(), 7)
        self.assertTrue(folder.is_dir())

    def test_garbage_upload_is_refused_and_registers_nothing(self):
        response = self.client.post(
            "/imports/backup/upload/", {"file": SimpleUploadedFile("junk.tar.gz", b"not a backup at all")}
        )
        self.assertRedirects(response, "/imports/backup/", fetch_redirect_response=False)
        self.assertFalse(Backup.objects.filter(kind=Backup.Kind.UPLOADED).exists())

    def test_no_file_is_refused(self):
        response = self.client.post("/imports/backup/upload/")
        self.assertRedirects(response, "/imports/backup/", fetch_redirect_response=False)
        self.assertFalse(Backup.objects.filter(kind=Backup.Kind.UPLOADED).exists())

    def test_page_and_upload_are_refused_to_admins(self):
        self.login_as(User.Role.ADMIN)
        self.assertEqual(self.client.get("/imports/backup/").status_code, 403)
        self.assertEqual(self.client.post("/imports/backup/upload/").status_code, 403)

    def test_backup_tab_only_shows_to_super_admins(self):
        response = self.client.get("/imports/backup/")
        self.assertContains(response, "Upload")
        self.assertContains(response, 'href="/imports/backup/"')

        self.login_as(User.Role.ADMIN)
        response = self.client.get("/imports/")
        self.assertNotContains(response, 'href="/imports/backup/"')


class ResetTests(BackupTests):
    """Reuses BackupTests' helpers; its own tests are not re-run here."""

    def setUp(self):
        super().setUp()
        self.boss = self.login_as(User.Role.SUPER_ADMIN)
        self.full_import()
        Team.objects.create(name="Platform")
        LoadBalancer.objects.create(ip_address="192.0.2.10", name="A10")
        Cve.objects.filter(cve_id="CVE-2021-44228").update(cvss_score="10.0", nvd_status="ok")

    def reset(self, confirm="RESET", delete_files=True):
        data = {"confirm": confirm}
        if delete_files:
            data["delete_files"] = "1"
        return self.client.post("/backups/reset/", data)

    def test_reset_deletes_environment_data_and_keeps_the_rest(self):
        page = self.client.get("/backups/reset/")
        self.assertEqual(page.context["counts"]["VulnerabilityFinding"], 7)
        self.assertEqual(page.context["counts"]["report_files"], 1)

        response = self.reset()
        self.assertRedirects(response, "/backups/", fetch_redirect_response=False)
        for model in (Host, VulnerabilityFinding, ScanImport, VulnerabilityDefinition, LoadBalancer):
            self.assertFalse(model.objects.exists(), model.__name__)
        self.assertFalse(any(Path(self.imports_root).iterdir()))

        # Kept: people, configuration, accountability, the way back, public CVE data.
        self.assertTrue(User.objects.filter(pk=self.boss.pk).exists())
        self.assertTrue(Team.objects.filter(name="Platform").exists())
        self.assertEqual(Perimeter.objects.count(), 2)
        self.assertTrue(AuditLog.objects.filter(action="data.reset").exists())
        self.assertEqual(Cve.objects.get(cve_id="CVE-2021-44228").cvss_score, Decimal("10.0"))
        safety = Backup.objects.get(kind=Backup.Kind.PRE_RESET)
        self.assertEqual(safety.contents["findings"], 7)

        # Undo: restore the backup taken before the reset.
        self.restore(safety)
        self.assertEqual(VulnerabilityFinding.objects.count(), 7)
        self.assertTrue(LoadBalancer.objects.exists())

    def test_report_files_can_be_kept(self):
        self.reset(delete_files=False)
        self.assertTrue(any(Path(self.imports_root).iterdir()))
        self.assertFalse(Host.objects.exists())

    def test_wrong_confirmation_deletes_nothing(self):
        response = self.reset(confirm="reset please")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(VulnerabilityFinding.objects.count(), 7)
        self.assertFalse(Backup.objects.filter(kind=Backup.Kind.PRE_RESET).exists())

    def test_only_super_admins(self):
        self.login_as(User.Role.ADMIN)
        self.assertEqual(self.client.get("/backups/reset/").status_code, 403)
        self.assertEqual(self.reset().status_code, 403)
        self.assertEqual(VulnerabilityFinding.objects.count(), 7)

    def test_refused_while_an_import_runs(self):
        ScanImport.objects.create(source=ScanImport.Source.MANUAL, status=ScanImport.Status.PARSING)
        response = self.reset()
        self.assertContains(response, "An Import Is Running")
        self.assertTrue(Host.objects.exists())

    def test_seed_demo_works_again_after_a_reset(self):
        self.reset()
        call_command("seed_demo", stdout=StringIO())
        self.assertEqual(Host.objects.count(), 10)


# Keep the inherited BackupTests cases from running twice.
for _name in [n for n in dir(BackupTests) if n.startswith("test_")]:
    setattr(ResetTests, _name, None)


def next_code(device):
    """A TOTP code for the next time step: the login already used the current one."""
    import time

    from django_otp.oath import TOTP

    totp = TOTP(device.bin_key, device.step, device.t0, device.digits, device.drift)
    totp.time = time.time() + device.step
    return f"{totp.token():0{device.digits}d}"


class FactoryResetTests(ImportTestMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.full_import()  # as the analyst of ImportTestMixin: data, a pre-import backup, a report file
        Team.objects.create(name="Platform")
        self.client.post("/account/logout/")
        self.boss = User.objects.create_user("boss", "boss@example.com", PASSWORD, role=User.Role.SUPER_ADMIN)
        self.device = TOTPDevice.objects.create(user=self.boss, name="app", confirmed=True)
        self.client.post("/account/login/", {"username": "boss", "password": PASSWORD})
        self.client.post("/account/mfa/verify/", {"token": current_code(self.device)})

    def factory_reset(self, token=None, confirm="DELETE EVERYTHING", **extra):
        self.device.refresh_from_db()
        data = {"token": token if token is not None else next_code(self.device), "confirm": confirm, **extra}
        return self.client.post("/backups/factory-reset/", data)

    def test_everything_goes_but_the_operator(self):
        self.assertTrue(Backup.objects.exists())
        response = self.factory_reset()
        self.assertRedirects(response, "/account/login/", fetch_redirect_response=False)

        for model in (Host, VulnerabilityFinding, ScanImport, VulnerabilityDefinition, Cve, Team, Backup):
            self.assertFalse(model.objects.exists(), model.__name__)
        self.assertFalse(any(Path(self.imports_root).iterdir()))
        self.assertFalse(any(Path(self.backup_root).iterdir()))
        # Like a fresh install: the two default perimeters, one user, one audit entry.
        self.assertEqual(sorted(Perimeter.objects.values_list("slug", flat=True)), ["external", "internal"])
        self.assertEqual(list(User.objects.values_list("username", flat=True)), ["boss"])
        self.assertEqual(list(AuditLog.objects.values_list("action", flat=True)), ["system.factory_reset"])

        # Signed out; the kept account signs in again with its own TOTP.
        self.assertEqual(self.client.get("/").status_code, 302)
        self.client.post("/account/login/", {"username": "boss", "password": PASSWORD})
        verify = self.client.post("/account/mfa/verify/", {"token": next_code(TOTPDevice.objects.get(user__username="boss"))})
        self.assertEqual(verify.status_code, 302)
        self.assertEqual(self.client.get("/").status_code, 200)

    def test_own_account_can_go_too(self):
        self.factory_reset(delete_own_account="1")
        self.assertFalse(User.objects.exists())
        self.assertFalse(TOTPDevice.objects.exists())

    def test_wrong_code_deletes_nothing(self):
        response = self.factory_reset(token="000000")
        self.assertContains(response, "Invalid or Expired Authenticator Code")
        self.assertTrue(Host.objects.exists())
        self.assertTrue(Backup.objects.exists())

    def test_backup_codes_are_not_accepted(self):
        static = StaticDevice.objects.create(user=self.boss, name="backup")
        StaticToken.objects.create(device=static, token="backupcode1")
        self.factory_reset(token="backupcode1")
        self.assertTrue(Host.objects.exists())

    def test_wrong_confirmation_deletes_nothing(self):
        self.factory_reset(confirm="delete everything")
        self.assertTrue(Host.objects.exists())

    def test_only_super_admins(self):
        self.client.post("/account/logout/")
        admin = User.objects.create_user("adm", "adm@example.com", PASSWORD, role=User.Role.ADMIN)
        device = TOTPDevice.objects.create(user=admin, name="app", confirmed=True)
        self.client.post("/account/login/", {"username": "adm", "password": PASSWORD})
        self.client.post("/account/mfa/verify/", {"token": current_code(device)})
        self.assertEqual(self.client.get("/backups/factory-reset/").status_code, 403)
        self.assertEqual(self.client.post("/backups/factory-reset/", {"token": next_code(device), "confirm": "DELETE EVERYTHING"}).status_code, 403)
        self.assertTrue(Host.objects.exists())


class DeleteAllBackupsTests(ImportTestMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.full_import()  # data, a pre-import backup, a report file
        self.client.post("/account/logout/")
        self.boss = User.objects.create_user("boss2", "boss2@example.com", PASSWORD, role=User.Role.SUPER_ADMIN)
        device = TOTPDevice.objects.create(user=self.boss, name="app", confirmed=True)
        self.client.post("/account/login/", {"username": "boss2", "password": PASSWORD})
        self.client.post("/account/mfa/verify/", {"token": current_code(device)})

    def test_backups_go_and_data_stays(self):
        self.assertTrue(Backup.objects.exists())
        response = self.client.post("/backups/delete-all/", {"confirm": "DELETE BACKUPS"})
        self.assertRedirects(response, "/backups/", fetch_redirect_response=False)
        self.assertFalse(Backup.objects.exists())
        self.assertFalse(any(Path(self.backup_root).iterdir()))
        self.assertTrue(Host.objects.exists())
        self.assertTrue(VulnerabilityFinding.objects.exists())
        self.assertTrue(any(Path(self.imports_root).iterdir()))

    def test_needs_the_confirmation_word(self):
        self.client.post("/backups/delete-all/", {"confirm": "no"})
        self.assertTrue(Backup.objects.exists())
