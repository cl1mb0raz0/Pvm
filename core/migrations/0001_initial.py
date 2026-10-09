import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("accounts", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="Cve",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("cve_id", models.CharField(help_text="e.g. CVE-2024-3094", max_length=32, unique=True)),
            ],
            options={
                "verbose_name": "CVE",
                "verbose_name_plural": "CVEs",
                "ordering": ["cve_id"],
            },
        ),
        migrations.CreateModel(
            name="Host",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("qualys_host_id", models.CharField(max_length=64, unique=True)),
                ("hostname", models.CharField(max_length=255)),
                ("ip_address", models.GenericIPAddressField()),
                ("os_name", models.CharField(blank=True, max_length=100)),
                (
                    "os_version",
                    models.CharField(
                        blank=True, help_text="Distro and release, e.g. 'Ubuntu 20.04'", max_length=100
                    ),
                ),
                (
                    "environment",
                    models.CharField(
                        choices=[("production", "Production"), ("staging", "Staging"), ("dev", "Development")],
                        default="production",
                        max_length=16,
                    ),
                ),
                ("first_seen_at", models.DateTimeField(auto_now_add=True)),
                ("last_scanned_at", models.DateTimeField(blank=True, null=True)),
                ("is_active", models.BooleanField(default=True)),
            ],
            options={
                "ordering": ["hostname"],
            },
        ),
        migrations.CreateModel(
            name="VulnerabilityDefinition",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("qid", models.CharField(help_text="Qualys QID", max_length=32, unique=True)),
                ("title", models.CharField(max_length=500)),
                ("description", models.TextField(blank=True)),
                (
                    "severity",
                    models.CharField(
                        choices=[
                            ("critical", "Critical"),
                            ("high", "High"),
                            ("medium", "Medium"),
                            ("low", "Low"),
                        ],
                        max_length=16,
                    ),
                ),
                ("cvss_score", models.DecimalField(blank=True, decimal_places=1, max_digits=3, null=True)),
                ("solution_text", models.TextField(blank=True)),
                ("cves", models.ManyToManyField(blank=True, related_name="vulnerability_definitions", to="core.cve")),
            ],
            options={
                "ordering": ["qid"],
            },
        ),
        migrations.CreateModel(
            name="SLAPolicy",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                (
                    "severity",
                    models.CharField(
                        choices=[
                            ("critical", "Critical"),
                            ("high", "High"),
                            ("medium", "Medium"),
                            ("low", "Low"),
                        ],
                        max_length=16,
                        unique=True,
                    ),
                ),
                ("target_days", models.PositiveIntegerField()),
            ],
            options={
                "verbose_name": "SLA policy",
                "verbose_name_plural": "SLA policies",
                "ordering": ["severity"],
            },
        ),
        migrations.CreateModel(
            name="InstalledPackage",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("package_name", models.CharField(max_length=255)),
                (
                    "installed_version",
                    models.CharField(
                        help_text="Full version string, including distro revision", max_length=255
                    ),
                ),
                (
                    "source",
                    models.CharField(
                        choices=[("manual", "Manual entry"), ("import", "Scan import")],
                        default="import",
                        max_length=16,
                    ),
                ),
                ("detected_at", models.DateTimeField()),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "created_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="+",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "host",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, related_name="packages", to="core.host"
                    ),
                ),
            ],
            options={
                "ordering": ["host", "package_name"],
            },
        ),
        migrations.CreateModel(
            name="VulnerabilityFinding",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("service_port", models.CharField(blank=True, default="", max_length=32)),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("new", "New"),
                            ("still_open", "Still open"),
                            ("needs_review", "Needs review"),
                            ("resolved", "Resolved"),
                        ],
                        default="new",
                        max_length=16,
                    ),
                ),
                ("due_date", models.DateField(blank=True, null=True)),
                ("first_detected_at", models.DateTimeField()),
                ("last_detected_at", models.DateTimeField()),
                ("resolved_at", models.DateTimeField(blank=True, null=True)),
                (
                    "assigned_team",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="findings",
                        to="accounts.team",
                    ),
                ),
                (
                    "host",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, related_name="findings", to="core.host"
                    ),
                ),
                (
                    "related_package",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="findings",
                        to="core.installedpackage",
                    ),
                ),
                (
                    "vulnerability_definition",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="findings",
                        to="core.vulnerabilitydefinition",
                    ),
                ),
            ],
            options={
                "ordering": ["-last_detected_at"],
            },
        ),
        migrations.CreateModel(
            name="ScanImport",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                (
                    "source",
                    models.CharField(
                        choices=[("manual", "Manual upload"), ("api", "Automatic (API)")], max_length=16
                    ),
                ),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("pending", "Pending"),
                            ("downloading", "Downloading"),
                            ("parsing", "Parsing"),
                            ("completed", "Completed"),
                            ("failed", "Failed"),
                        ],
                        default="pending",
                        max_length=16,
                    ),
                ),
                ("started_at", models.DateTimeField(auto_now_add=True)),
                ("completed_at", models.DateTimeField(blank=True, null=True)),
                (
                    "raw_file_path",
                    models.CharField(
                        blank=True,
                        help_text="Where the original report is archived, for re-processing",
                        max_length=500,
                    ),
                ),
                ("findings_count", models.PositiveIntegerField(default=0)),
                ("error_message", models.TextField(blank=True)),
                (
                    "triggered_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="scan_imports",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "ordering": ["-started_at"],
            },
        ),
        migrations.CreateModel(
            name="ScanDetectionEvent",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("detected_at", models.DateTimeField()),
                (
                    "scan_import",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="detection_events",
                        to="core.scanimport",
                    ),
                ),
                (
                    "vulnerability_finding",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="detection_events",
                        to="core.vulnerabilityfinding",
                    ),
                ),
            ],
            options={
                "ordering": ["-detected_at"],
            },
        ),
        migrations.CreateModel(
            name="DistroPatchVerification",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("verified_at", models.DateTimeField(auto_now_add=True)),
                ("note", models.TextField()),
                ("reference_url", models.URLField(blank=True)),
                (
                    "verdict",
                    models.CharField(
                        choices=[
                            ("likely_false_positive", "Likely false positive"),
                            ("confirmed_vulnerable", "Confirmed vulnerable"),
                            ("confirmed_fixed", "Confirmed fixed"),
                        ],
                        max_length=32,
                    ),
                ),
                (
                    "verified_by",
                    models.ForeignKey(
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="distro_verifications",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "vulnerability_finding",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="distro_verification",
                        to="core.vulnerabilityfinding",
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="AuditLog",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("action", models.CharField(max_length=100)),
                ("entity_type", models.CharField(max_length=100)),
                ("entity_id", models.CharField(max_length=64)),
                ("timestamp", models.DateTimeField(auto_now_add=True)),
                ("details", models.JSONField(blank=True, default=dict)),
                (
                    "user",
                    models.ForeignKey(
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="audit_logs",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "ordering": ["-timestamp"],
            },
        ),
        migrations.AddConstraint(
            model_name="installedpackage",
            constraint=models.UniqueConstraint(fields=("host", "package_name"), name="unique_package_per_host"),
        ),
        migrations.AddConstraint(
            model_name="vulnerabilityfinding",
            constraint=models.UniqueConstraint(
                fields=("host", "vulnerability_definition", "service_port"),
                name="unique_finding_per_host_vuln_port",
            ),
        ),
        migrations.AddConstraint(
            model_name="scandetectionevent",
            constraint=models.UniqueConstraint(
                fields=("scan_import", "vulnerability_finding"), name="unique_detection_per_scan"
            ),
        ),
    ]
