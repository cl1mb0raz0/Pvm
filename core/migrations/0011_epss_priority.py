from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("core", "0010_sla_due_dates")]

    operations = [
        migrations.AddField(
            model_name="cve",
            name="epss_score",
            field=models.DecimalField(blank=True, decimal_places=5, max_digits=6, null=True),
        ),
        migrations.AddField(
            model_name="cve",
            name="epss_percentile",
            field=models.DecimalField(blank=True, decimal_places=5, max_digits=6, null=True),
        ),
        migrations.AddField(model_name="cve", name="epss_date", field=models.DateField(blank=True, null=True)),
        migrations.AddField(model_name="cve", name="epss_fetched_at", field=models.DateTimeField(blank=True, null=True)),
        migrations.AddField(
            model_name="vulnerabilityfinding",
            name="priority_score",
            field=models.PositiveSmallIntegerField(db_index=True, default=0),
        ),
        migrations.AddField(
            model_name="vulnerabilityfinding",
            name="priority_factors",
            field=models.JSONField(blank=True, default=list),
        ),
    ]
