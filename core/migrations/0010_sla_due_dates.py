from datetime import timedelta

from django.db import migrations, models

SLA_TARGET_DAYS = {"critical": 7, "high": 30, "medium": 90, "low": 180}


def apply_sla(apps, schema_editor):
    SLAPolicy = apps.get_model("core", "SLAPolicy")
    Finding = apps.get_model("core", "VulnerabilityFinding")
    for severity, days in SLA_TARGET_DAYS.items():
        SLAPolicy.objects.get_or_create(severity=severity, defaults={"target_days": days})
    targets = dict(SLAPolicy.objects.values_list("severity", "target_days"))
    changed = []
    for f in Finding.objects.select_related("vulnerability_definition"):
        f.sla_started_at = f.first_detected_at.date()
        if f.due_date is not None:
            # Set before PVM computed due dates: someone chose it.
            f.due_date_manual = True
        elif f.status != "resolved" and f.vulnerability_definition.severity in targets:
            f.due_date = f.sla_started_at + timedelta(days=targets[f.vulnerability_definition.severity])
        changed.append(f)
    Finding.objects.bulk_update(changed, ["sla_started_at", "due_date", "due_date_manual"], batch_size=500)


class Migration(migrations.Migration):
    dependencies = [("core", "0009_cisa_kev")]

    operations = [
        migrations.AddField(
            model_name="vulnerabilityfinding",
            name="sla_started_at",
            field=models.DateField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="vulnerabilityfinding",
            name="due_date_manual",
            field=models.BooleanField(default=False),
        ),
        migrations.AddIndex(
            model_name="auditlog",
            index=models.Index(fields=["action", "timestamp"], name="auditlog_action_time"),
        ),
        migrations.RunPython(apply_sla, migrations.RunPython.noop),
    ]
