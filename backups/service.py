"""
Create and restore application-level backups.

A backup is `dumpdata` of every PVM table (users, teams, MFA devices, all
vulnerability data, import history, audit log) into one gzip-compressed
JSON file under settings.BACKUP_ROOT. Restoring empties exactly those
tables and loads the file back, inside a single transaction: it either
fully succeeds or changes nothing.

Not included, on purpose: the backups table itself (so the list survives
a restore), sessions, and the rows Django regenerates from migrations
(content types, permissions). Raw Qualys report files are not included
either; they stay on the scan_imports volume - unless `full=True`
(`Backup.full`): a full backup bundles the database dump together with
the whole scan_imports tree in one tar.gz, so a single file (and a single
restore) covers everything Pvm keeps on disk. The code and `.env` are
never included, even in a full backup: secrets (the Qualys password, the
Django secret key, PVM_SSH_KEY_SECRET) are deliberately never written to
a downloadable file. When moving to another server,
keep a copy of `.env` separately.

`register_uploaded_backup` is the other direction: a backup file taken on
one Pvm installation (typically a FULL BACKUP) is uploaded to another one
(Imports > Backup, meant for a fresh install) and registered as an
ordinary `Backup` row, then restored through the same `restore_backup`
and the same confirmation as any local backup - uploading never restores
by itself.
"""

import gzip
import json
import shutil
import tarfile
import tempfile
from pathlib import Path

from django.apps import apps
from django.conf import settings
from django.core.management import call_command
from django.core.management.color import no_style
from django.db import connection, transaction
from django.utils import timezone

from core.models import ScanImport

from .models import Backup

# App labels / models dumped and restored, in this order.
BACKED_UP = ["auth.group", "accounts", "otp_totp", "otp_static", "core", "admin.logentry"]

# Shown in the backup list, so a backup can be chosen by what it contains.
CONTENT_COUNTS = {
    "users": "accounts.User",
    "hosts": "core.Host",
    "findings": "core.VulnerabilityFinding",
    "imports": "core.ScanImport",
}


class BackupError(Exception):
    pass


def backup_root():
    root = Path(settings.BACKUP_ROOT)
    root.mkdir(parents=True, exist_ok=True)
    return root


def backup_path(backup):
    path = (backup_root() / backup.file_name).resolve()
    if backup_root().resolve() not in path.parents:
        raise BackupError("Backup File Path Is Outside the Backup Folder.")
    return path


def create_backup(kind, user=None, scan_import_id=None, note="", full=False):
    """
    Write a new backup file and return its `Backup` row (status failed if
    it did not work). `full` bundles the raw Qualys report files in with
    the database dump, as one tar.gz, instead of the database alone.
    """
    stamp = timezone.now().strftime("%Y%m%d-%H%M%S-%f")
    ext = "tar.gz" if full else "json.gz"
    backup = Backup.objects.create(
        kind=kind,
        full=full,
        file_name=f"pvm-{stamp}-{kind}{'-full' if full else ''}.{ext}",
        created_by=user.username if user else "",
        scan_import_id=scan_import_id,
        note=note[:255],
    )
    path = backup_path(backup)
    dump_path = (backup_root() / f".{stamp}-data.json.gz") if full else path
    try:
        call_command(
            "dumpdata",
            *BACKED_UP,
            natural_foreign=True,
            output=str(dump_path),
            verbosity=0,
        )
        if full:
            with tarfile.open(path, "w:gz") as tar:
                tar.add(dump_path, arcname="data.json.gz")
                imports_root = Path(settings.SCAN_IMPORTS_ROOT)
                if imports_root.is_dir():
                    tar.add(imports_root, arcname="scan_imports")
        backup.size_bytes = path.stat().st_size
        backup.contents = {
            name: apps.get_model(label).objects.count() for name, label in CONTENT_COUNTS.items()
        }
        if full:
            imports_root = Path(settings.SCAN_IMPORTS_ROOT)
            backup.contents["report_files"] = (
                sum(1 for p in imports_root.iterdir() if p.is_dir()) if imports_root.is_dir() else 0
            )
        backup.status = Backup.Status.COMPLETED
    except Exception as exc:
        path.unlink(missing_ok=True)
        backup.status = Backup.Status.FAILED
        backup.error_message = f"{type(exc).__name__}: {exc}"
    finally:
        if full:
            dump_path.unlink(missing_ok=True)
    backup.save()
    return backup


def _model_counts(objects):
    """Row counts of `CONTENT_COUNTS`' models within a parsed dumpdata list."""
    model_to_name = {label.lower(): name for name, label in CONTENT_COUNTS.items()}
    counts = {name: 0 for name in CONTENT_COUNTS}
    for obj in objects:
        name = model_to_name.get(obj.get("model", ""))
        if name:
            counts[name] += 1
    return counts


def register_uploaded_backup(uploaded_file, user, note=""):
    """
    Save an uploaded backup file - typically a FULL BACKUP downloaded from
    another Pvm installation - as a new `Backup` row, so it can be restored
    the normal way afterwards ("Restore" on the backup list, same
    confirmation as any other backup). Whether it is a full backup
    (tar.gz) or a regular one (json.gz) is detected from the file itself,
    not its name. Nothing is restored here, only validated and registered;
    a corrupt or unrecognized file raises `BackupError` and nothing is
    kept on disk.
    """
    stamp = timezone.now().strftime("%Y%m%d-%H%M%S-%f")
    tmp_path = backup_root() / f".upload-{stamp}"
    try:
        with open(tmp_path, "wb") as out:
            for chunk in uploaded_file.chunks():
                out.write(chunk)

        try:
            full = tarfile.is_tarfile(tmp_path)
            if full:
                with tarfile.open(tmp_path, "r:gz") as tar:
                    if "data.json.gz" not in tar.getnames():
                        raise BackupError("This Archive Has No Database Dump (data.json.gz) Inside.")
                    with gzip.GzipFile(fileobj=tar.extractfile("data.json.gz")) as f:
                        objects = json.load(f)
                    report_files = len(
                        {
                            n[len("scan_imports/") :].split("/", 1)[0]
                            for n in tar.getnames()
                            if n.startswith("scan_imports/") and len(n) > len("scan_imports/")
                        }
                    )
            else:
                with gzip.open(tmp_path, "rb") as f:
                    objects = json.load(f)
        except BackupError:
            raise
        except (tarfile.TarError, OSError, json.JSONDecodeError) as exc:
            raise BackupError(f"Not a Pvm Backup File: {exc}") from exc

        contents = _model_counts(objects)
        if full:
            contents["report_files"] = report_files

        ext = "tar.gz" if full else "json.gz"
        backup = Backup.objects.create(
            kind=Backup.Kind.UPLOADED,
            full=full,
            file_name=f"pvm-{stamp}-uploaded{'-full' if full else ''}.{ext}",
            created_by=user.username if user else "",
            note=note[:255],
            size_bytes=tmp_path.stat().st_size,
            contents=contents,
            status=Backup.Status.COMPLETED,
        )
        tmp_path.rename(backup_path(backup))
        return backup
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise


def _backed_up_tables():
    tables = []
    for label in BACKED_UP:
        if "." in label:
            models = [apps.get_model(label)]
        else:
            models = list(apps.get_app_config(label).get_models())
        for model in models:
            tables.append(model._meta.db_table)
            # Many-to-many join tables (user groups, CVE links, import hosts...).
            tables += [f.remote_field.through._meta.db_table for f in model._meta.local_many_to_many]
    return list(dict.fromkeys(tables))


def _empty_tables(tables):
    """Delete every row of `tables` (TRUNCATE on Postgres); call inside a transaction."""
    sql = connection.ops.sql_flush(no_style(), tables)
    if connection.vendor == "postgresql":
        # TRUNCATE refuses tables with pending deferred FK checks from
        # earlier writes in the same transaction; run those checks now,
        # then defer again so rows can be inserted afterwards in any order.
        with connection.cursor() as cursor:
            cursor.execute("SET CONSTRAINTS ALL IMMEDIATE")
            connection.ops.execute_sql_flush(sql)
            cursor.execute("SET CONSTRAINTS ALL DEFERRED")
    else:
        connection.ops.execute_sql_flush(sql)


def restore_backup(backup, user):
    """
    Replace all PVM data with the content of `backup` - and, for a full
    backup, the raw Qualys report files too. A backup of the current
    state is taken first, in the same scope, so the restore itself can be
    undone. Returns that safety backup.
    """
    if backup.status != Backup.Status.COMPLETED:
        raise BackupError("Only a Completed Backup Can Be Restored.")
    path = backup_path(backup)
    if not path.is_file():
        raise BackupError(f"The Backup File {backup.file_name} Is Missing.")
    if ScanImport.objects.filter(status__in=[ScanImport.Status.PARSING, ScanImport.Status.DOWNLOADING]).exists():
        raise BackupError("An Import Is Running. Wait for It to Finish, Then Restore.")

    extract_dir = None
    if backup.full:
        # Fail early on a corrupt archive, before touching anything.
        try:
            with tarfile.open(path, "r:gz") as tar:
                if "data.json.gz" not in tar.getnames():
                    raise BackupError("This Full Backup's Archive Has No Database Dump Inside.")
                extract_dir = Path(tempfile.mkdtemp(prefix="pvm-restore-", dir=backup_root()))
                tar.extractall(extract_dir, filter="data")
        except tarfile.TarError as exc:
            raise BackupError(f"Corrupt Backup Archive: {exc}") from exc
        dump_path = extract_dir / "data.json.gz"
    else:
        # Fail early on a corrupt file, before touching anything.
        with gzip.open(path, "rb") as f:
            while f.read(1 << 20):
                pass
        dump_path = path

    try:
        safety = create_backup(
            Backup.Kind.PRE_RESTORE, user, note=f"Automatic, Before Restoring Backup #{backup.pk}", full=backup.full
        )
        if safety.status != Backup.Status.COMPLETED:
            raise BackupError(
                f"Could Not Back Up the Current State First, Nothing Was Restored: {safety.error_message}"
            )

        with transaction.atomic():
            _empty_tables(_backed_up_tables())
            call_command("loaddata", str(dump_path), verbosity=0)
            # Imports that were running when the backup was taken can never
            # finish now; this is also what "undo import" leaves behind.
            ScanImport.objects.filter(status__in=[ScanImport.Status.PARSING, ScanImport.Status.DOWNLOADING]).update(
                status=ScanImport.Status.FAILED,
                error_message=f"Rolled Back: The Database Was Restored from Backup #{backup.pk}.",
            )
        if backup.full:
            extracted_imports = extract_dir / "scan_imports"
            _clear_folder(settings.SCAN_IMPORTS_ROOT)
            if extracted_imports.is_dir():
                imports_root = Path(settings.SCAN_IMPORTS_ROOT)
                imports_root.mkdir(parents=True, exist_ok=True)
                for item in extracted_imports.iterdir():
                    shutil.move(str(item), str(imports_root / item.name))
        Backup.objects.filter(pk=backup.pk).update(restored_at=timezone.now(), restored_by=user.username)
    finally:
        if extract_dir:
            shutil.rmtree(extract_dir, ignore_errors=True)
    return safety


def delete_backup(backup):
    if backup.file_name:
        backup_path(backup).unlink(missing_ok=True)
    backup.delete()


def delete_all_backups():
    """Delete every backup (rows and files); the data stays untouched. Returns how many."""
    count = Backup.objects.count()
    with transaction.atomic():
        Backup.objects.all().delete()
    _clear_folder(settings.BACKUP_ROOT)
    return count


# "Reset data": everything PVM knows about the environment. Kept: users and
# MFA devices, teams, perimeters, SLA policies (configuration), the audit
# log and the backup list (accountability, and the way back), and the CVE
# cache (public NVD / Ubuntu data, slow to fetch again).
RESET_MODELS = [
    "core.CsamProposal",
    "core.CsamSearch",
    "core.PmSearch",
    # History of past days: it describes findings and imports that are going.
    "core.FindingState",
    "core.Snapshot",
    "core.ScanDetectionEvent",
    "core.PatchCheck",
    "core.DistroPatchVerification",
    "core.VulnerabilityFinding",
    "core.InstalledPackage",
    "core.HostPrivateIp",
    "core.ScanImport",
    "core.Host",
    "core.VulnerabilityDefinition",
    "core.LoadBalancer",
]


def reset_counts():
    """What a reset would delete, by model, plus the archived report folders."""
    counts = {label.split(".")[1]: apps.get_model(label).objects.count() for label in RESET_MODELS}
    root = Path(settings.SCAN_IMPORTS_ROOT)
    counts["report_files"] = sum(1 for p in root.iterdir() if p.is_dir()) if root.is_dir() else 0
    return counts


def reset_data(user, delete_report_files):
    """
    Delete all environment data (see RESET_MODELS), after a full backup so
    it can be undone by restoring that backup. Returns (counts, backup).
    """
    if ScanImport.objects.filter(status__in=[ScanImport.Status.PARSING, ScanImport.Status.DOWNLOADING]).exists():
        raise BackupError("An Import Is Running. Wait for It to Finish, Then Reset.")
    counts = reset_counts()
    safety = create_backup(Backup.Kind.PRE_RESET, user, note="Automatic, Before Deleting All Data")
    if safety.status != Backup.Status.COMPLETED:
        raise BackupError(f"Could Not Back Up the Data First, Nothing Was Deleted: {safety.error_message}")

    tables = []
    for label in RESET_MODELS:
        model = apps.get_model(label)
        tables.append(model._meta.db_table)
        tables += [f.remote_field.through._meta.db_table for f in model._meta.local_many_to_many]
    with transaction.atomic():
        _empty_tables(tables)

    if delete_report_files:
        root = Path(settings.SCAN_IMPORTS_ROOT)
        if root.is_dir():
            for folder in root.iterdir():
                if folder.is_dir():
                    shutil.rmtree(folder, ignore_errors=True)
    else:
        counts["report_files"] = 0
    return counts, safety


FACTORY_RESET_KEEPS = {"contenttypes", "auth.permission"}


def _all_tables():
    """Every table of every installed model except those Django derives from the code."""
    tables = []
    for model in apps.get_models(include_auto_created=True):
        if model._meta.app_label in FACTORY_RESET_KEEPS or model._meta.label_lower in FACTORY_RESET_KEEPS:
            continue
        tables.append(model._meta.db_table)
    return list(dict.fromkeys(tables))


def _clear_folder(root):
    root = Path(root)
    if not root.is_dir():
        return
    for item in root.iterdir():
        if item.is_dir():
            shutil.rmtree(item, ignore_errors=True)
        else:
            item.unlink(missing_ok=True)


def factory_reset(user, keep_user=True):
    """
    Empty PVM completely, as a fresh installation: all data, all backups
    (rows and files), uploaded reports, users, teams, audit log, CVE cache.
    `user` (who runs it) is kept, with their MFA devices, unless keep_user
    is False; then nobody can sign in until `createsuperuser` is run.
    Cannot be undone.
    """
    from django.core import serializers
    from django_otp.plugins.otp_static.models import StaticDevice, StaticToken
    from django_otp.plugins.otp_totp.models import TOTPDevice

    from core.defaults import create_default_perimeters, create_default_sla_policies

    if ScanImport.objects.filter(status__in=[ScanImport.Status.PARSING, ScanImport.Status.DOWNLOADING]).exists():
        raise BackupError("An Import Is Running. Wait for It to Finish, Then Reset.")

    kept = []
    if keep_user:
        # The account survives as a standalone Super Admin: no team, no groups.
        kept = serializers.serialize(
            "python",
            [user]
            + list(TOTPDevice.objects.filter(user=user))
            + list(StaticDevice.objects.filter(user=user))
            + list(StaticToken.objects.filter(device__user=user)),
        )

    with transaction.atomic():
        _empty_tables(_all_tables())
        create_default_perimeters()
        create_default_sla_policies()
        for obj in serializers.deserialize("python", kept):
            if hasattr(obj.object, "team_id"):
                obj.object.team_id = None
                obj.m2m_data = {}
            obj.save()

    _clear_folder(settings.BACKUP_ROOT)
    _clear_folder(settings.SCAN_IMPORTS_ROOT)
