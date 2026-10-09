from django.db import models


class Backup(models.Model):
    """
    One application-level backup file (all PVM data, gzip-compressed JSON).

    Deliberately has no foreign keys: this table is left out of backups and
    restores so the list of backups survives restoring any of them, and a
    restore that truncates users or imports must not cascade into it.
    """

    class Kind(models.TextChoices):
        MANUAL = "manual", "Manual"
        PRE_IMPORT = "pre_import", "Before Import"
        PRE_RESTORE = "pre_restore", "Before Restore"
        PRE_RESET = "pre_reset", "Before Data Reset"
        PRE_MAPPING = "pre_mapping", "Before Mapping"
        UPLOADED = "uploaded", "Uploaded From Another Server"

    class Status(models.TextChoices):
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"

    created_at = models.DateTimeField(auto_now_add=True)
    kind = models.CharField(max_length=16, choices=Kind.choices)
    # A regular backup is the database alone (dumpdata/loaddata JSON). A
    # full backup bundles that together with the raw Qualys report files
    # (SCAN_IMPORTS_ROOT, kept for audit but never part of the database),
    # so a single file/restore covers everything Pvm keeps on disk - not
    # the code or .env (secrets are deliberately never written to a
    # downloadable file; keep a copy of .env separately).
    full = models.BooleanField(default=False, help_text="Also includes the raw Qualys report files (scan imports)")
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.COMPLETED)
    file_name = models.CharField(max_length=255, blank=True)
    size_bytes = models.PositiveBigIntegerField(default=0)
    created_by = models.CharField(max_length=150, blank=True, help_text="Username, Kept as Text on Purpose")
    scan_import_id = models.PositiveBigIntegerField(null=True, blank=True, help_text="For Pre-Import Backups")
    note = models.CharField(max_length=255, blank=True)
    # Row counts at backup time (hosts, findings, imports, users...).
    contents = models.JSONField(default=dict, blank=True)
    error_message = models.TextField(blank=True)
    restored_at = models.DateTimeField(null=True, blank=True)
    restored_by = models.CharField(max_length=150, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        kind = f"Full {self.get_kind_display()}" if self.full else self.get_kind_display()
        return f"Backup #{self.pk} ({kind}, {self.created_at:%Y-%m-%d %H:%M})"
