from django.contrib import admin

from . import audit, priority, sla

from .models import (
    AuditLog,
    Cve,
    DistroPatchVerification,
    Host,
    InstalledPackage,
    KevEntry,
    LoadBalancer,
    Perimeter,
    ScanDetectionEvent,
    ScanImport,
    SLAPolicy,
    Snapshot,
    VulnerabilityDefinition,
    VulnerabilityFinding,
)


@admin.register(KevEntry)
class KevEntryAdmin(admin.ModelAdmin):
    list_display = ("cve_id", "vendor", "product", "date_added", "due_date", "ransomware")
    list_filter = ("ransomware",)
    search_fields = ("cve_id", "vendor", "product", "name")


@admin.register(LoadBalancer)
class LoadBalancerAdmin(admin.ModelAdmin):
    list_display = ("ip_address", "name", "created_at")
    search_fields = ("ip_address", "name")


@admin.register(Perimeter)
class PerimeterAdmin(admin.ModelAdmin):
    list_display = ("name", "slug", "internet_facing", "description")
    prepopulated_fields = {"slug": ("name",)}


@admin.register(Host)
class HostAdmin(admin.ModelAdmin):
    list_display = ("hostname", "ip_address", "private_ip", "os_version", "environment", "is_active", "last_scanned_at")
    list_filter = ("environment", "is_active")
    search_fields = ("hostname", "ip_address", "private_ip", "qualys_host_id")


@admin.register(InstalledPackage)
class InstalledPackageAdmin(admin.ModelAdmin):
    list_display = ("package_name", "installed_version", "host", "source", "detected_at")
    list_filter = ("source",)
    search_fields = ("package_name", "host__hostname")


@admin.register(Cve)
class CveAdmin(admin.ModelAdmin):
    list_display = ("cve_id", "cvss_score", "cvss_version", "cvss_severity", "cvss_source", "nvd_status", "nvd_fetched_at")
    list_filter = ("nvd_status", "cvss_version", "cvss_severity")
    search_fields = ("cve_id",)
    readonly_fields = (
        "cvss_score",
        "cvss_version",
        "cvss_severity",
        "cvss_vector",
        "cvss_source",
        "nvd_published_at",
        "nvd_last_modified_at",
        "nvd_status",
        "nvd_fetched_at",
        "nvd_error",
    )


@admin.register(VulnerabilityDefinition)
class VulnerabilityDefinitionAdmin(admin.ModelAdmin):
    list_display = ("qid", "title", "severity", "qualys_severity", "cvss_score")
    list_filter = ("severity", "qualys_severity")
    search_fields = ("qid", "title", "cves__cve_id")
    filter_horizontal = ("cves",)


@admin.register(SLAPolicy)
class SLAPolicyAdmin(admin.ModelAdmin):
    """Every change is re-applied at once to open findings whose due date follows the policy."""

    list_display = ("severity", "target_days")

    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        updated = sla.recompute()
        priority.recompute()
        audit.log(request.user, "sla.policy_changed", obj, severity=obj.severity, target_days=obj.target_days, findings_updated=updated)

    def delete_model(self, request, obj):
        super().delete_model(request, obj)
        sla.recompute()
        priority.recompute()

    def delete_queryset(self, request, queryset):
        super().delete_queryset(request, queryset)
        sla.recompute()
        priority.recompute()


@admin.register(VulnerabilityFinding)
class VulnerabilityFindingAdmin(admin.ModelAdmin):
    list_display = (
        "vulnerability_definition",
        "host",
        "priority_score",
        "perimeter",
        "status",
        "assigned_team",
        "due_date",
        "last_detected_at",
    )
    list_filter = ("perimeter", "status", "assigned_team")
    search_fields = ("host__hostname", "vulnerability_definition__qid")
    # Triage happens in Pvm (Vulnerabilities / host page), where every change
    # is written to the audit log; here these fields are shown only.
    readonly_fields = (
        "status",
        "assigned_team",
        "due_date",
        "due_date_manual",
        "sla_started_at",
        "resolved_at",
        "first_detected_at",
        "last_detected_at",
        "priority_score",
        "priority_factors",
    )


@admin.register(ScanImport)
class ScanImportAdmin(admin.ModelAdmin):
    list_display = ("id", "perimeter", "source", "status", "started_at", "completed_at", "findings_count")
    list_filter = ("perimeter", "source", "status")


@admin.register(ScanDetectionEvent)
class ScanDetectionEventAdmin(admin.ModelAdmin):
    list_display = ("scan_import", "vulnerability_finding", "detected_at")


@admin.register(DistroPatchVerification)
class DistroPatchVerificationAdmin(admin.ModelAdmin):
    list_display = ("vulnerability_finding", "verdict", "verified_by", "verified_at")
    list_filter = ("verdict",)


@admin.register(Snapshot)
class SnapshotAdmin(admin.ModelAdmin):
    """The "As Of" history (core/history.py): a record, so nothing here is editable."""

    list_display = ("taken_at", "reason", "scan_import", "findings_total", "findings_open")
    list_filter = ("reason",)
    readonly_fields = [f.name for f in Snapshot._meta.fields]

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ("timestamp", "user", "action", "entity_type", "entity_id")
    list_filter = ("action", "entity_type")
    readonly_fields = [f.name for f in AuditLog._meta.fields]

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False
