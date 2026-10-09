import logging

from django.contrib import messages
from django.contrib.auth import logout
from django.http import FileResponse, Http404
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from django_otp.plugins.otp_totp.models import TOTPDevice

from accounts.models import User
from accounts.permissions import can_manage_backups, is_super_admin, require
from core import audit
from core.sorting import sort_rows, sorting
from core.models import ScanImport

from . import service
from .models import Backup

logger = logging.getLogger(__name__)

RESTORE_CONFIRMATION = "RESTORE"
RESET_CONFIRMATION = "RESET"
FACTORY_RESET_CONFIRMATION = "DELETE EVERYTHING"
DELETE_ALL_CONFIRMATION = "DELETE BACKUPS"


# Backup columns: (query key, header, value sorted on, first-click direction,
# numeric). Sorted in Python: the contents column is built from other rows.
BACKUP_COLUMNS = [
    ("number", "#", lambda b: b.pk, "desc", False),
    ("created", "Created", lambda b: b.created_at, "desc", False),
    ("kind", "Type", lambda b: b.get_kind_display(), "asc", False),
    ("by", "By", lambda b: b.created_by, "asc", False),
    ("contents", "Contents", lambda b: b.note or b.import_name, "asc", False),
    ("size", "Size", lambda b: b.size_bytes, "desc", True),
    ("status", "Status", lambda b: b.get_status_display(), "asc", False),
    ("actions", "", None, "asc", False),
]


@require(can_manage_backups)
def backup_list(request):
    backups = list(Backup.objects.all())
    # Backups have no foreign keys (see the model), so look the names up.
    import_names = dict(
        ScanImport.objects.filter(pk__in=[b.scan_import_id for b in backups if b.scan_import_id]).values_list("pk", "name")
    )
    for b in backups:
        b.file_present = b.status == Backup.Status.COMPLETED and service.backup_path(b).is_file()
        b.import_name = import_names.get(b.scan_import_id, "")
    value, direction, sort, headers = sorting(request, BACKUP_COLUMNS, "created")
    return render(
        request,
        "backups/list.html",
        {"backups": sort_rows(backups, value, direction), "headers": headers, "sort": sort, "dir": direction},
    )


@require(can_manage_backups)
@require_POST
def backup_create(request):
    backup = service.create_backup(Backup.Kind.MANUAL, request.user, note=request.POST.get("note", "").strip())
    if backup.status == Backup.Status.COMPLETED:
        audit.log(request.user, "backup.created", backup)
        messages.success(request, f"Backup #{backup.pk} Created.")
    else:
        messages.error(request, f"Backup Failed: {backup.error_message}")
    return redirect("backups:list")


@require(can_manage_backups)
@require_POST
def backup_create_full(request):
    """Database dump plus the raw Qualys report files, bundled in one tar.gz (see backups/service.py)."""
    backup = service.create_backup(
        Backup.Kind.MANUAL, request.user, note=request.POST.get("note", "").strip(), full=True
    )
    if backup.status == Backup.Status.COMPLETED:
        audit.log(request.user, "backup.created", backup, full=True)
        messages.success(request, f"Full Backup #{backup.pk} Created.")
    else:
        messages.error(request, f"Full Backup Failed: {backup.error_message}")
    return redirect("backups:list")


@require(can_manage_backups)
@require_POST
def backup_rename(request, pk):
    backup = get_object_or_404(Backup, pk=pk)
    note = request.POST.get("note", "").strip()[:255]
    if note != backup.note:
        before = backup.note
        backup.note = note
        backup.save(update_fields=["note"])
        audit.log(request.user, "backup.renamed", backup, before=before, after=note)
    return redirect("backups:list")


@require(is_super_admin)
def backup_restore(request, pk):
    backup = get_object_or_404(Backup, pk=pk, status=Backup.Status.COMPLETED)
    error = ""
    if request.method == "POST":
        if request.POST.get("confirm", "").strip() != RESTORE_CONFIRMATION:
            error = f"Type {RESTORE_CONFIRMATION} to Confirm."
        else:
            try:
                safety = service.restore_backup(backup, request.user)
            except service.BackupError as exc:
                error = str(exc)
            else:
                # Written after the restore, so it survives it.
                audit.log(request.user, "backup.restored", backup, safety_backup=safety.pk)
                messages.success(
                    request,
                    f"Restored Backup #{backup.pk}. The State Just Before the Restore Was Saved as Backup #{safety.pk}.",
                )
                return redirect("backups:list")

    return render(
        request,
        "backups/restore.html",
        {
            "backup": backup,
            "error": error,
            "confirmation": RESTORE_CONFIRMATION,
            "later_imports": ScanImport.objects.filter(started_at__gte=backup.created_at).order_by("started_at"),
        },
    )


@require(is_super_admin)
@require_POST
def backup_delete(request, pk):
    backup = get_object_or_404(Backup, pk=pk)
    audit.log(request.user, "backup.deleted", backup, file_name=backup.file_name)
    service.delete_backup(backup)
    messages.info(request, f"Backup #{pk} Deleted.")
    return redirect("backups:list")


@require(is_super_admin)
def backup_download(request, pk):
    backup = get_object_or_404(Backup, pk=pk, status=Backup.Status.COMPLETED)
    path = service.backup_path(backup)
    if not path.is_file():
        raise Http404("Backup file missing.")
    audit.log(request.user, "backup.downloaded", backup)
    return FileResponse(open(path, "rb"), as_attachment=True, filename=backup.file_name)


@require(is_super_admin)
def reset(request):
    """Delete all hosts, findings and import history, after a backup that can undo it."""
    error = ""
    if request.method == "POST":
        if request.POST.get("confirm", "").strip() != RESET_CONFIRMATION:
            error = f"Type {RESET_CONFIRMATION} to Confirm."
        else:
            try:
                counts, safety = service.reset_data(request.user, bool(request.POST.get("delete_files")))
            except service.BackupError as exc:
                error = str(exc)
            else:
                audit.log(request.user, "data.reset", safety, deleted=counts, safety_backup=safety.pk)
                messages.success(
                    request,
                    f"All Data Deleted ({counts['Host']} Hosts, {counts['VulnerabilityFinding']} Findings, "
                    f"{counts['ScanImport']} Imports). To Undo, Restore Backup #{safety.pk}.",
                )
                return redirect("backups:list")
    return render(
        request,
        "backups/reset.html",
        {"counts": service.reset_counts(), "error": error, "confirmation": RESET_CONFIRMATION},
    )


@require(is_super_admin)
def delete_all(request):
    """Delete every backup, keeping the current data."""
    error = ""
    if request.method == "POST":
        if request.POST.get("confirm", "").strip() != DELETE_ALL_CONFIRMATION:
            error = f"Type {DELETE_ALL_CONFIRMATION} to Confirm."
        else:
            count = service.delete_all_backups()
            audit.log(request.user, "backup.deleted_all", request.user, deleted=count)
            messages.success(request, f"{count} Backup{'s' if count != 1 else ''} Deleted. Current Data Kept.")
            return redirect("backups:list")
    return render(
        request,
        "backups/delete_all.html",
        {
            "error": error,
            "confirmation": DELETE_ALL_CONFIRMATION,
            "backups": Backup.objects.all(),
            "total_size": sum(b.size_bytes or 0 for b in Backup.objects.all()),
        },
    )


@require(is_super_admin)
def factory_reset(request):
    """Delete everything, backups included, after a fresh TOTP code."""
    error = ""
    if request.method == "POST":
        token = "".join(request.POST.get("token", "").split())
        devices = TOTPDevice.objects.devices_for_user(request.user, confirmed=True)
        if request.POST.get("confirm", "").strip() != FACTORY_RESET_CONFIRMATION:
            error = f"Type {FACTORY_RESET_CONFIRMATION} to Confirm."
        # Only the authenticator app: backup codes are not accepted here.
        elif not token or not any(d.verify_token(token) for d in devices):
            error = "Invalid or Expired Authenticator Code."
        else:
            keep_user = not request.POST.get("delete_own_account")
            user = request.user
            try:
                service.factory_reset(user, keep_user=keep_user)
            except service.BackupError as exc:
                error = str(exc)
            else:
                logger.warning("Factory reset by %s (own account kept: %s)", user.username, keep_user)
                if keep_user:
                    # The audit log starts again with who emptied it.
                    audit.log(User.objects.get(pk=user.pk), "system.factory_reset", User.objects.get(pk=user.pk))
                logout(request)
                messages.success(
                    request,
                    "Factory Reset Done: Pvm Is Empty. Sign In Again."
                    if keep_user
                    else "Factory Reset Done: Pvm Is Empty and Has No Users; Run createsuperuser on the Server.",
                )
                return redirect("accounts:login")
    return render(
        request,
        "backups/factory_reset.html",
        {
            "error": error,
            "confirmation": FACTORY_RESET_CONFIRMATION,
            "backup_count": Backup.objects.count(),
            "user_count": User.objects.count(),
            "counts": service.reset_counts(),
        },
    )
