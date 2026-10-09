"""
Manual report upload: upload -> choose columns -> background processing.

The file is archived before anything else happens, then analyzed so the
user can pick which columns to import; the confirmed mapping is processed
by a Celery task (core.tasks) through the shared import pipeline.
"""

import logging
import shutil
from datetime import datetime, time
from pathlib import Path

from django import forms
from django.conf import settings
from django.contrib import messages
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import F, Q
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.utils.text import get_valid_filename
from django.views.decorators.http import require_POST

from accounts.models import User
from accounts.permissions import editor_required, is_super_admin, require
from backups import service as backup_service
from backups.models import Backup

from . import audit, tags
from .importers import qualys_csv
from .models import Host, Perimeter, ScanImport, Tag
from .sorting import sorting
from .tasks import process_scan_import

logger = logging.getLogger(__name__)
Status = ScanImport.Status


class UploadForm(forms.Form):
    report = forms.FileField(help_text="Qualys CSV Export (Scan Report or Vulnerability List).")
    name = forms.CharField(
        max_length=100,
        required=False,
        help_text="Optional, to Find the Import in the History.",
    )
    scan_date = forms.DateField(
        initial=timezone.localdate,
        widget=forms.DateInput(attrs={"type": "date"}),
        help_text="When the Scan Ran; Used as the Detection Date for Every Finding in the File.",
    )

    def clean_report(self):
        report = self.cleaned_data["report"]
        if not report.name.lower().endswith((".csv", ".txt")):
            raise forms.ValidationError("Upload the Report as a .csv File.")
        return report

    def clean_scan_date(self):
        scan_date = self.cleaned_data["scan_date"]
        if scan_date > timezone.localdate():
            raise forms.ValidationError("The Scan Date Cannot Be in the Future.")
        return scan_date


# History columns: (query key, header, sorted field, first-click direction,
# numeric). Numbers and dates start from the highest / most recent.
IMPORT_COLUMNS = [
    ("number", "#", "pk", "desc", False),
    ("name", "Name", "name", "asc", False),
    ("started", "Started", "started_at", "desc", False),
    ("perimeter", "Perimeter", "perimeter__name", "asc", False),
    ("source", "Source", "source", "asc", False),
    ("file", "File", "original_filename", "asc", False),
    ("scan_date", "Scan Date", "scanned_at", "desc", False),
    ("by", "By", "triggered_by__username", "asc", False),
    ("status", "Status", "status", "asc", False),
    ("findings", "Findings", "findings_count", "desc", True),
]


def import_list(request):
    imports = ScanImport.objects.select_related("triggered_by", "perimeter")
    perimeter = request.GET.get("perimeter", "")
    if perimeter:
        imports = imports.filter(perimeter__slug=perimeter)
    q = request.GET.get("q", "").strip()
    if q:
        imports = imports.filter(Q(name__icontains=q) | Q(original_filename__icontains=q))
    field, direction, sort, headers = sorting(request, IMPORT_COLUMNS, "started")
    order = F(field).asc(nulls_last=True) if direction == "asc" else F(field).desc(nulls_last=True)
    # Newest first within equal values, so a sorted page stays readable.
    imports = imports.order_by(order, "-started_at", "-pk")
    page = Paginator(imports, 25).get_page(request.GET.get("page"))
    return render(
        request,
        "core/imports/list.html",
        {
            "page": page,
            "perimeters": Perimeter.objects.all(),
            "perimeter": perimeter,
            "q": q,
            "headers": headers,
            "sort": request.GET.get("sort", ""),
            "dir": direction,
        },
    )


@require(is_super_admin)
def import_backup(request):
    """
    Imports > Backup: upload a backup file (typically a FULL BACKUP taken
    on another Pvm installation, from that server's Backups page) so it
    can be restored here - meant for a fresh installation, to bring it to
    a state captured elsewhere. Uploading only registers the file as an
    ordinary Backup row; the actual restore is the existing, confirmed
    "Restore" step, shown right after a successful upload.
    """
    return render(
        request,
        "core/imports/backup.html",
        {
            "host_count": Host.objects.count(),
            "user_count": User.objects.count(),
            "uploaded": Backup.objects.filter(kind=Backup.Kind.UPLOADED).order_by("-created_at")[:10],
        },
    )


@require(is_super_admin)
@require_POST
def import_backup_upload(request):
    upload = request.FILES.get("file")
    if not upload:
        messages.error(request, "Choose a Backup File First.")
        return redirect("core:import_backup")
    try:
        backup = backup_service.register_uploaded_backup(upload, request.user, note=upload.name[:255])
    except backup_service.BackupError as exc:
        messages.error(request, str(exc))
        return redirect("core:import_backup")
    audit.log(request.user, "backup.uploaded", backup, file_name=upload.name, full=backup.full)
    messages.success(
        request,
        f"Uploaded {'a Full ' if backup.full else 'a '}Backup as #{backup.pk}. Nothing Has Changed Yet - Restore It Below to Apply It.",
    )
    return redirect("backups:restore", backup.pk)


@editor_required
@require_POST
def import_rename(request, pk):
    scan_import = get_object_or_404(ScanImport, pk=pk)
    old = scan_import.name
    scan_import.name = request.POST.get("name", "").strip()[:100]
    scan_import.save(update_fields=["name"])
    audit.log(request.user, "import.renamed", scan_import, old=old, new=scan_import.name)
    messages.success(request, "Import Name Saved.")
    return redirect("core:import_detail", pk)


@editor_required
def import_upload(request):
    form = UploadForm(request.POST or None, request.FILES or None)
    if request.method == "POST" and form.is_valid():
        report = form.cleaned_data["report"]
        scan_import = ScanImport.objects.create(
            source=ScanImport.Source.MANUAL,
            status=Status.PENDING,
            triggered_by=request.user,
            original_filename=report.name[:255],
            name=form.cleaned_data["name"].strip(),
            scanned_at=_scan_datetime(form.cleaned_data["scan_date"]),
        )
        # Archive the raw file first, so it is kept even if parsing fails.
        folder = Path(settings.SCAN_IMPORTS_ROOT) / str(scan_import.pk)
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / (get_valid_filename(report.name) or "report.csv")
        with open(path, "wb") as f:
            for chunk in report.chunks():
                f.write(chunk)
        scan_import.raw_file_path = str(path)
        audit.log(request.user, "import.uploaded", scan_import, filename=report.name)

        try:
            scan_import.summary = {"file": qualys_csv.analyze(path)}
        except Exception as exc:
            scan_import.status = Status.FAILED
            scan_import.error_message = (
                str(exc) if isinstance(exc, qualys_csv.ReportError) else f"Could Not Read the File: {exc}"
            )
            scan_import.save()
            return redirect("core:import_detail", scan_import.pk)
        scan_import.save()
        return redirect("core:import_mapping", scan_import.pk)

    return render(request, "core/imports/upload.html", {"form": form})


@editor_required
def import_mapping(request, pk):
    scan_import = get_object_or_404(ScanImport, pk=pk)
    if scan_import.status != Status.PENDING or "file" not in scan_import.summary:
        return redirect("core:import_detail", pk)

    file_info = scan_import.summary["file"]
    columns = file_info["columns"]
    mapping = _default_mapping(columns)
    perimeter = None
    errors = []
    # Pre-ticked: what the last import with the same name had ("Internal Alpha" -> Alpha).
    selected_tags = {t.pk for t in tags.suggested_for(scan_import)}
    new_tags = ""

    if request.method == "POST":
        selected_tags = {int(i) for i in request.POST.getlist("tag") if i.isdigit()}
        new_tags = request.POST.get("new_tags", "")
        mapping = {c: request.POST.get(f"col-{i}", qualys_csv.DONT_IMPORT) for i, c in enumerate(columns)}
        errors = qualys_csv.validate_mapping(mapping, columns)
        # No default: whoever imports must say where the scan looked from.
        perimeter = Perimeter.objects.filter(slug=request.POST.get("perimeter", "")).first()
        if perimeter is None:
            errors.insert(0, "Choose the Perimeter This Scan Was Run From.")
        if not errors:
            scan_import.column_mapping = mapping
            scan_import.perimeter = perimeter
            scan_import.status = Status.PARSING
            scan_import.save(update_fields=["column_mapping", "perimeter", "status"])
            chosen = tags.from_form(request.POST)
            scan_import.tags.set(chosen)
            audit.log(
                request.user, "import.started", scan_import,
                columns=[c for c, v in mapping.items() if v], tags=[t.name for t in chosen],
            )
            transaction.on_commit(lambda: _enqueue(scan_import.pk))
            return redirect("core:import_detail", pk)

    rows = [
        {"index": i, "name": c, "samples": file_info["samples"].get(c, []), "value": mapping.get(c, "")}
        for i, c in enumerate(columns)
    ]
    return render(
        request,
        "core/imports/mapping.html",
        {
            "scan_import": scan_import,
            "file": file_info,
            "rows": rows,
            "fields": [(key, label, required) for key, label, required, _ in qualys_csv.FIELDS],
            "extra": qualys_csv.EXTRA,
            "errors": errors,
            "skipped_types": sorted(qualys_csv.SKIPPED_TYPES),
            "perimeters": Perimeter.objects.all(),
            "selected_perimeter": perimeter,
            "all_tags": Tag.objects.all(),
            "selected_tags": selected_tags,
            "new_tags": new_tags,
        },
    )


RUNNING_STATUSES = [Status.DOWNLOADING, Status.PARSING]


@editor_required
@require_POST
def import_stop(request, pk):
    """
    Stop an import that is downloading or being processed. The row is marked
    failed at once, so a task killed by a restart stops blocking the page
    too; the task itself, if still alive, sees `stop_requested` at its next
    step and rolls its transaction back, so nothing is half-imported.
    """
    scan_import = get_object_or_404(ScanImport, pk=pk, status__in=RUNNING_STATUSES)
    ScanImport.objects.filter(pk=pk).update(stop_requested=True)
    if scan_import.task_id:
        try:
            from pvm.celery import app

            app.control.revoke(scan_import.task_id)
        except Exception as exc:  # the broker is not reachable: the flag alone has to do
            logger.warning("Could not revoke the task of import %s: %s", pk, exc)
    ScanImport.objects.filter(pk=pk, status__in=RUNNING_STATUSES).update(
        status=Status.FAILED,
        error_message=f"Stopped by {request.user.username} Before It Finished: Nothing Was Imported.",
        completed_at=timezone.now(),
    )
    audit.log(request.user, "import.stopped", scan_import, was=scan_import.status, name=scan_import.name)
    messages.info(request, f"Import #{pk} Stopped. Nothing It Had Started to Write Was Kept.")
    if request.POST.get("from") == "list":
        return redirect("core:import_list")
    return redirect("core:import_detail", pk)


@editor_required
@require_POST
def import_discard(request, pk):
    scan_import = get_object_or_404(ScanImport, pk=pk, status__in=[Status.PENDING, Status.FAILED])
    if scan_import.raw_file_path:
        shutil.rmtree(Path(scan_import.raw_file_path).parent, ignore_errors=True)
    audit.log(request.user, "import.discarded", scan_import, filename=scan_import.original_filename)
    scan_import.delete()
    messages.info(request, "Import Discarded.")
    return redirect("core:import_list")


def import_detail(request, pk):
    scan_import = get_object_or_404(ScanImport.objects.select_related("triggered_by", "perimeter"), pk=pk)
    context = {
        "scan_import": scan_import,
        "result": scan_import.summary.get("result"),
        "skipped": scan_import.summary.get("skipped", {}),
        "skipped_total": sum(scan_import.summary.get("skipped", {}).values()),
        "file": scan_import.summary.get("file"),
        "running": scan_import.status in (Status.PARSING, Status.DOWNLOADING),
        "pre_import_backup": Backup.objects.filter(
            kind=Backup.Kind.PRE_IMPORT, scan_import_id=scan_import.pk, status=Backup.Status.COMPLETED
        ).first(),
    }
    if request.headers.get("HX-Request") == "true":
        return render(request, "core/imports/partials/status.html", context)
    context["tags"] = scan_import.tags.all()
    context["other_tags"] = Tag.objects.exclude(scan_imports=scan_import)
    return render(request, "core/imports/detail.html", context)


@editor_required
@require_POST
def import_add_tags(request, pk):
    """Add tags to an import afterwards; a completed import gives them to its hosts at once."""
    scan_import = get_object_or_404(ScanImport, pk=pk)
    added = tags.from_form(request.POST)
    if added:
        scan_import.tags.add(*added)
        hosts = list(scan_import.hosts.all()) if scan_import.status == Status.COMPLETED else []
        tags.apply(added, hosts)
        audit.log(request.user, "import.tagged", scan_import, tags=[t.name for t in added], hosts=len(hosts))
        messages.success(request, f"Tags Added to This Import and to Its {len(hosts)} Host{'s' if len(hosts) != 1 else ''}.")
    return redirect("core:import_detail", pk)


def _enqueue(pk):
    try:
        result = process_scan_import.delay(pk)
        # Kept so "Stop Import" can revoke the task before a worker starts it.
        ScanImport.objects.filter(pk=pk).update(task_id=result.id)
    except Exception as exc:  # broker unreachable: fail visibly instead of hanging
        ScanImport.objects.filter(pk=pk).update(
            status=Status.FAILED, error_message=f"Could Not Queue the Import (Is the Celery Worker Running?): {exc}"
        )


def _scan_datetime(scan_date):
    if scan_date == timezone.localdate():
        return timezone.now()
    return timezone.make_aware(datetime.combine(scan_date, time(12)))


def _default_mapping(columns):
    """Name-based suggestion, overridden by the choices made on the last import with the same columns."""
    mapping = qualys_csv.suggest_mapping(columns)
    previous = (
        ScanImport.objects.filter(status=Status.COMPLETED)
        .exclude(column_mapping={})
        .order_by("-started_at")
        .values_list("column_mapping", flat=True)
        .first()
    )
    if previous:
        mapping.update({c: v for c, v in previous.items() if c in mapping})
    return mapping
