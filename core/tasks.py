import logging
import time

import redis
from celery import shared_task
from django.conf import settings

from backups.models import Backup
from backups.service import create_backup

from django.db.models import Q
from django.utils import timezone

from . import epss, history, kev, nvd, patchcheck, priority, rocky, rocky_check, ubuntu
from .importers import pipeline, qualys_csv
from .models import Cve, Host, KevEntry, ScanImport, Snapshot

logger = logging.getLogger(__name__)


def stop_asked(scan_import_id):
    """True when someone clicked "Stop Import" (core/import_views.py)."""
    return ScanImport.objects.filter(pk=scan_import_id, stop_requested=True).exists()


def mark_stopped(scan_import_id):
    """Record that the import was stopped; whatever it had written is rolled back with its transaction."""
    # The button already wrote who stopped it: keep that message if it is there.
    said = ScanImport.objects.filter(pk=scan_import_id).values_list("error_message", flat=True).first() or ""
    ScanImport.objects.filter(pk=scan_import_id).update(
        status=ScanImport.Status.FAILED,
        error_message=said if said.startswith("Stopped") else "Stopped Before It Finished: Nothing Was Imported.",
        completed_at=timezone.now(),
        stop_requested=False,
        task_id="",
    )
    logger.info("Scan import %s stopped on request", scan_import_id)


@shared_task(bind=True)
def process_scan_import(self, scan_import_id):
    """Parse an uploaded report with its confirmed column mapping and apply it."""
    scan_import = ScanImport.objects.get(pk=scan_import_id)
    if self.request.id:
        ScanImport.objects.filter(pk=scan_import_id).update(task_id=self.request.id)
    if stop_asked(scan_import_id):
        mark_stopped(scan_import_id)
        return

    # Never import without a way back: back up first, and stop if that fails.
    backup = create_backup(
        Backup.Kind.PRE_IMPORT,
        scan_import.triggered_by,
        scan_import_id=scan_import.pk,
        note=f"Automatic, Before Import #{scan_import.pk} ({scan_import.name or scan_import.original_filename})",
    )
    if backup.status != Backup.Status.COMPLETED:
        ScanImport.objects.filter(pk=scan_import_id).update(
            status=ScanImport.Status.FAILED,
            error_message=f"Not Imported: The Backup Before Import Failed ({backup.error_message}).",
        )
        return

    if stop_asked(scan_import_id):
        mark_stopped(scan_import_id)
        return

    try:
        detections, skipped = qualys_csv.read_detections(scan_import.raw_file_path, scan_import.column_mapping)
        pipeline.run(scan_import, detections, skipped, should_stop=lambda: stop_asked(scan_import_id))
    except pipeline.Stopped:
        mark_stopped(scan_import_id)
        return
    except Exception as exc:
        logger.exception("Scan import %s failed", scan_import_id)
        ScanImport.objects.filter(pk=scan_import_id).update(
            status=ScanImport.Status.FAILED, error_message=f"{type(exc).__name__}: {exc}"
        )
        return
    # CVEs first seen in this report get their NVD score in the background.
    if settings.NVD_ENABLED:
        refresh_nvd.delay()
    # First import ever: fetch the CISA KEV catalog now rather than tonight.
    if settings.KEV_ENABLED and not KevEntry.objects.exists():
        refresh_kev.delay()
    # EPSS for CVEs first seen in this report.
    if settings.EPSS_ENABLED:
        refresh_epss.delay(only_new=True)
    # What the situation looks like now that this scan is in, so the day can be
    # answered exactly later (core/history.py, "As Of").
    take_snapshot(Snapshot.Reason.IMPORT, scan_import_id)


def _moved_to_background(task, *args, **kwargs):
    """
    True (and the task re-queued) if a background task was delivered to the
    interactive worker: queued by an older version before the two queues
    existed, or sent without routing. Run directly or eagerly: never moved.
    """
    request = task.request
    if request.is_eager or request.called_directly:
        return False
    if (request.delivery_info or {}).get("routing_key") == settings.BACKGROUND_QUEUE:
        return False
    task.apply_async(args=args, kwargs=kwargs, queue=settings.BACKGROUND_QUEUE)
    logger.info("Moved %s to the %s queue", task.name, settings.BACKGROUND_QUEUE)
    return True


@shared_task(bind=True, max_retries=None)
def refresh_nvd(self, cve_ids=None, force=False):
    """
    Fetch CVSS from NVD for CVEs that are due (never fetched, failed, or
    older than NVD_REFRESH_DAYS), or for `cve_ids`. One refresh at a time:
    two in parallel would break NVD's rate limit.
    """
    if not settings.NVD_ENABLED:
        return None
    if _moved_to_background(self, cve_ids=cve_ids, force=force):
        return None
    lock = _nvd_lock()
    if lock is False:
        raise self.retry(countdown=300)
    try:
        cves = nvd.due_for_refresh() if not (cve_ids or force) else Cve.objects.all()
        if cve_ids:
            cves = cves.filter(cve_id__in=cve_ids)
        counts = nvd.refresh(list(cves), heartbeat=lock.reacquire if lock else None)
        priority.recompute()
        logger.info("NVD refresh: %s", counts)
        return counts
    finally:
        if lock:
            try:
                lock.release()
            except redis.RedisError:
                pass  # already expired: nothing to release


# Short, and renewed before every NVD request while the refresh runs: if the
# worker is stopped mid-refresh, the lock frees itself within minutes
# instead of blocking the next refreshes.
NVD_LOCK_SECONDS = 600


def _nvd_lock():
    """A Redis lock, None if Redis is unreachable (run unlocked), False if already held."""
    try:
        lock = redis.Redis.from_url(settings.CELERY_BROKER_URL).lock("pvm:nvd-refresh", timeout=NVD_LOCK_SECONDS)
        return lock if lock.acquire(blocking=False) else False
    except redis.RedisError:
        return None


def _check_progress(host_id, every_seconds=2):
    """A progress callback for ubuntu.refresh that records it on the host, at most every few seconds."""
    last = [None]

    def progress(done, total):
        now = time.monotonic()
        if done == total or last[0] is None or now - last[0] >= every_seconds:
            last[0] = now
            Host.objects.filter(pk=host_id).update(patch_check_done=done, patch_check_total=total)

    return progress


@shared_task
def check_host_patches(host_id, retry_errors=False):
    """
    Refresh tracker/errata data for the host's CVEs, then re-check its
    findings against whichever source applies to its OS: the Ubuntu
    security tracker (core.patchcheck) or Rocky Linux's own errata
    (core.rocky_check). A host is one or the other, never both.
    """
    host = Host.objects.get(pk=host_id)
    try:
        if host.ubuntu_release:
            if settings.UBUNTU_TRACKER_ENABLED:
                cves = Cve.objects.filter(vulnerability_definitions__findings__in=patchcheck.findings_to_check(host))
                due = list(ubuntu.due_for_refresh(cves.distinct(), retry_errors=retry_errors))
                Host.objects.filter(pk=host_id).update(patch_check_done=0, patch_check_total=len(due))
                ubuntu.refresh(due, progress=_check_progress(host_id))
            patchcheck.check_host(host)
        elif host.rocky_release:
            if settings.ROCKY_TRACKER_ENABLED:
                cves = Cve.objects.filter(vulnerability_definitions__findings__in=patchcheck.findings_to_check(host))
                due = list(rocky.due_for_refresh(cves.distinct(), retry_errors=retry_errors))
                Host.objects.filter(pk=host_id).update(patch_check_done=0, patch_check_total=len(due))
                rocky.refresh(due, progress=_check_progress(host_id))
            rocky_check.check_host(host)
        priority.recompute(host.findings.all())
    except Exception as exc:
        logger.exception("Patch check failed for host %s", host_id)
        Host.objects.filter(pk=host_id).update(patch_check_state="failed", patch_check_error=str(exc)[:255])
        return
    Host.objects.filter(pk=host_id).update(patch_check_state="done", patch_checked_at=timezone.now(), patch_check_error="")


def resume_interrupted_checks():
    """Queue again the checks of hosts left "running" (see pvm/celery.py); returns how many."""
    hosts = list(Host.objects.filter(patch_check_state="running").values_list("pk", flat=True))
    for host_id in hosts:
        check_host_patches.delay(host_id)
    if hosts:
        logger.info("Queued again %d interrupted host check(s)", len(hosts))
    return len(hosts)


@shared_task(bind=True)
def check_all_patches(self):
    """Nightly: the tracker changes (a "needed" CVE gets a fix), so re-check every host that can be checked."""
    if _moved_to_background(self):
        return
    hosts = Host.objects.filter(Q(ubuntu_release__gt="") | Q(rocky_release__gt="")).filter(packages__isnull=False).distinct()
    for host_id in hosts.values_list("pk", flat=True):
        check_host_patches(host_id)


@shared_task(bind=True)
def refresh_kev(self):
    """Replace the local copy of the CISA Known Exploited Vulnerabilities catalog."""
    if not settings.KEV_ENABLED:
        return None
    if _moved_to_background(self):
        return None
    try:
        return kev.refresh()
    except kev.KevError as exc:
        logger.warning("CISA KEV refresh failed: %s", exc)
        return None


@shared_task(bind=True)
def refresh_epss(self, only_new=False):
    """EPSS for every CVE (nightly: scores change daily) or, after an import, for CVEs never fetched."""
    if not settings.EPSS_ENABLED:
        return None
    if _moved_to_background(self, only_new=only_new):
        return None
    cves = epss.never_fetched() if only_new else Cve.objects.all()
    try:
        scored = epss.refresh(cves)
    except epss.EpssError as exc:
        logger.warning("EPSS refresh failed: %s", exc)
        return None
    priority.recompute()
    return scored


@shared_task(bind=True)
def refresh_priorities(self):
    """Nightly: due dates pass and findings age, so priorities move with the calendar."""
    if _moved_to_background(self):
        return None
    return priority.recompute()


@shared_task
def take_snapshot(reason=Snapshot.Reason.NIGHTLY, scan_import_id=None):
    """
    Record the state of every finding now (core/history.py). Run after every
    completed import and every night, so "As Of <date>" can answer from what
    was really there instead of reconstructing it from the scans.
    """
    scan_import = ScanImport.objects.filter(pk=scan_import_id).first() if scan_import_id else None
    snapshot = history.take(reason, scan_import=scan_import)
    logger.info("Snapshot %s taken: %s findings, %s open", snapshot.pk, snapshot.findings_total, snapshot.findings_open)
    return {"snapshot": snapshot.pk, "findings": snapshot.findings_total, "open": snapshot.findings_open}


@shared_task
def ask_server(host_id, user_id=None):
    """
    Read the host's inventory over SSH (core.ssh), store it as a complete
    package list, then re-check its findings against the Ubuntu tracker.
    """
    from accounts.models import User

    from . import audit, inventory, ssh
    from .models import InstalledPackage

    host = Host.objects.get(pk=host_id)
    user = User.objects.filter(pk=user_id).first()
    address, port, username = ssh.target(host)
    try:
        result = ssh.collect(host)
    except ssh.HostKeyUnknown as exc:
        Host.objects.filter(pk=host_id).update(
            ssh_state="host_key", ssh_pending_host_key=exc.key, ssh_error=str(exc)[:255], ssh_checked_at=timezone.now()
        )
        return "host_key"
    except ssh.SshError as exc:
        logger.warning("Ask Server failed for host %s: %s", host_id, exc)
        Host.objects.filter(pk=host_id).update(ssh_state="failed", ssh_error=str(exc)[:255], ssh_checked_at=timezone.now())
        if user:
            audit.log(user, "inventory.ssh_failed", host, target=f"{username}@{address}:{port}", error=str(exc)[:255])
        return "failed"

    release = ssh.ubuntu_release(result["os"])
    created, removed = inventory.store(host, result["entries"], user, InstalledPackage.Source.SSH, replace=True)
    note = ""
    if not release:
        note = f"Not a Supported Ubuntu Release ({result['os'].get('PRETTY_NAME', 'Unknown OS')}): Packages Saved, No Tracker Check."
    elif result["errors"]:
        note = f"{len(result['errors'])} Package Line{'s' if len(result['errors']) != 1 else ''} Not Understood."
    Host.objects.filter(pk=host_id).update(
        ubuntu_release=release or host.ubuntu_release,
        running_kernel=result["kernel"][:128],
        ssh_state="done",
        ssh_error=note[:255],
        ssh_checked_at=timezone.now(),
        ssh_pending_host_key="",
    )
    if user:
        audit.log(
            user, "inventory.ssh", host, target=f"{username}@{address}:{port}",
            packages=len(result["entries"]), new=created, removed=removed, release=release, kernel=result["kernel"],
        )
    if release and result["entries"]:
        Host.objects.filter(pk=host_id).update(patch_check_state="running", patch_check_error="", patch_check_done=0, patch_check_total=0)
        check_host_patches(host_id)
    return "done"


# --- Qualys API imports (core.qualys) ---------------------------------------


def start_qualys_import(scan, perimeter, tags, user, source, name="", rule=None):
    """
    Create the import of Qualys scan `scan` (a dict from qualys.list_scans)
    and queue it once the transaction commits. Returns the ScanImport, or
    None if that scan was already imported.
    """
    from django.db import IntegrityError, transaction

    try:
        with transaction.atomic():
            scan_import = ScanImport.objects.create(
                source=source,
                status=ScanImport.Status.DOWNLOADING,
                name=(name or scan["title"])[:100],
                perimeter=perimeter,
                triggered_by=user,
                original_filename=f"{scan['title']} ({scan['ref']})"[:255],
                scanned_at=scan["launched_at"],
                qualys_scan_ref=scan["ref"],
                rule=rule,
                summary={"qualys": {k: scan[k] for k in ("ref", "title", "type", "duration", "option_profile", "target_count")}},
            )
            scan_import.tags.set(tags)
    except IntegrityError:
        return None

    def enqueue():
        try:
            result = import_qualys_scan.delay(scan_import.pk)
            ScanImport.objects.filter(pk=scan_import.pk).update(task_id=result.id)
        except Exception as exc:  # broker unreachable
            ScanImport.objects.filter(pk=scan_import.pk).update(
                status=ScanImport.Status.FAILED, error_message=f"Could Not Queue the Import: {exc}"
            )

    transaction.on_commit(enqueue)
    return scan_import


@shared_task(bind=True)
def import_qualys_scan(self, scan_import_id):
    """
    Fetch a Qualys scan's results, archive them (JSON as received, CSV as
    converted), then import them exactly like an uploaded report.
    """
    from pathlib import Path

    from . import qualys
    from .import_views import _default_mapping

    scan_import = ScanImport.objects.get(pk=scan_import_id)
    if self.request.id:
        ScanImport.objects.filter(pk=scan_import_id).update(task_id=self.request.id)
    if stop_asked(scan_import_id):
        mark_stopped(scan_import_id)
        return
    try:
        header, rows, body = qualys.fetch_scan(scan_import.qualys_scan_ref)
        folder = Path(settings.SCAN_IMPORTS_ROOT) / str(scan_import.pk)
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "qualys_scan.json").write_bytes(body)
        csv_path = folder / "qualys_scan.csv"
        csv_path.write_text(qualys.rows_to_csv(rows), encoding="utf-8")
        info = qualys_csv.analyze(csv_path)
        mapping = _default_mapping(info["columns"])
        errors = qualys_csv.validate_mapping(mapping, info["columns"])
        if errors:
            raise qualys_csv.ReportError(" ".join(errors))
    except (qualys.QualysError, qualys_csv.ReportError, OSError) as exc:
        logger.warning("Qualys import %s failed: %s", scan_import_id, exc)
        ScanImport.objects.filter(pk=scan_import_id).update(status=ScanImport.Status.FAILED, error_message=str(exc)[:2000])
        return

    detected = qualys.perimeter_from_header(header)
    summary = dict(scan_import.summary)
    summary["file"] = info
    summary["qualys"] = {
        **summary.get("qualys", {}),
        "scanner": header.get("scanner_appliance"),
        "active_hosts": header.get("active_hosts"),
        "total_hosts": header.get("total_hosts"),
        "detected_perimeter": detected,
    }
    if detected and scan_import.perimeter and detected != scan_import.perimeter.slug:
        summary["qualys"]["perimeter_warning"] = (
            f"The Scan Ran from an {detected.title()} Scanner, but the Import Was Assigned to {scan_import.perimeter.name}."
        )
    if stop_asked(scan_import_id):
        mark_stopped(scan_import_id)
        return
    ScanImport.objects.filter(pk=scan_import_id).update(
        raw_file_path=str(csv_path), column_mapping=mapping, summary=summary, status=ScanImport.Status.PARSING
    )
    process_scan_import(scan_import_id)


@shared_task
def run_qualys_rules():
    """Every 15 minutes: each due rule imports the latest finished run of its scan, if new."""
    from django.utils import timezone as tz

    from . import qualys
    from .models import QualysImportRule

    now = tz.now()
    due = list(QualysImportRule.objects.filter(enabled=True, next_run_at__lte=now).prefetch_related("tags"))
    if not due:
        return 0
    try:
        scans = qualys.list_scans(days=40)
        failure = ""
    except qualys.QualysError as exc:
        scans, failure = [], f"Failed: {exc}"[:255]
    for rule in due:
        rule.last_run_at, rule.next_run_at = now, qualys.next_run(rule, now)
        runs = [s for s in scans if s["title"] == rule.scan_title]
        if failure:
            rule.last_result = failure
        elif not runs:
            rule.last_result = "No Finished Run of This Scan in the Last 40 Days."
        else:
            latest = runs[0]
            when = latest["launched_at"].strftime("%Y-%m-%d") if latest["launched_at"] else "?"
            started = start_qualys_import(
                latest, rule.perimeter, list(rule.tags.all()), rule.created_by, ScanImport.Source.API, rule.scan_title, rule
            )
            rule.last_result = (
                f"Import #{started.pk} Started for the Run of {when}." if started
                else f"Nothing New: the Run of {when} Is Already Imported."
            )
        rule.save(update_fields=["last_run_at", "next_run_at", "last_result"])
    return len(due)


@shared_task
def search_csam(search_id):
    """Read Qualys CSAM and store what it knows about PVM's hosts as proposals (core.csam)."""
    from django.utils import timezone as tz

    from . import csam
    from .models import CsamSearch

    search = CsamSearch.objects.get(pk=search_id)
    try:
        csam.run_search(search)
    except Exception as exc:  # the page must show why, whatever it was
        logger.warning("CSAM search %s failed: %s", search_id, exc)
        CsamSearch.objects.filter(pk=search_id).update(state=CsamSearch.State.FAILED, error=str(exc)[:2000], finished_at=tz.now())
        return
    search.state, search.finished_at = CsamSearch.State.DONE, tz.now()
    search.save()


@shared_task
def search_pm(search_id):
    """Check PVM's Windows findings against Qualys Patch Management (core.qualys_pm)."""
    from django.utils import timezone as tz

    from . import qualys_pm
    from .models import PmSearch

    search = PmSearch.objects.get(pk=search_id)
    try:
        qualys_pm.run_search(search)
    except Exception as exc:  # the page must show why, whatever it was
        logger.warning("Patch Management search %s failed: %s", search_id, exc)
        PmSearch.objects.filter(pk=search_id).update(state=PmSearch.State.FAILED, error=str(exc)[:2000], finished_at=tz.now())
        return
    search.state, search.finished_at = PmSearch.State.DONE, tz.now()
    search.save()
