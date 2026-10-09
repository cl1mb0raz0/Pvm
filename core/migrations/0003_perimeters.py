import django.db.models.deletion
from django.db import migrations, models

PERIMETERS = [
    {
        "name": "Internal",
        "slug": "internal",
        "description": "Scanned by the Qualys scanner appliance inside the network",
        "internet_facing": False,
    },
    {
        "name": "External",
        "slug": "external",
        "description": "Scanned from the internet by Qualys",
        "internet_facing": True,
    },
]


def create_perimeters(apps, schema_editor):
    Perimeter = apps.get_model("core", "Perimeter")
    for values in PERIMETERS:
        Perimeter.objects.get_or_create(slug=values["slug"], defaults=values)


def assign_existing_to_internal(apps, schema_editor):
    # Data imported before perimeters existed: assumed internal; an admin
    # can move an import's findings from the Django admin if it was not.
    internal = apps.get_model("core", "Perimeter").objects.get(slug="internal")
    apps.get_model("core", "VulnerabilityFinding").objects.update(perimeter=internal)
    apps.get_model("core", "ScanImport").objects.exclude(status="pending").update(perimeter=internal)


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0002_scan_import_upload"),
    ]

    operations = [
        migrations.CreateModel(
            name="Perimeter",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=50, unique=True)),
                ("slug", models.SlugField(unique=True)),
                ("description", models.CharField(blank=True, max_length=255)),
                ("internet_facing", models.BooleanField(default=False)),
            ],
            options={
                "ordering": ["internet_facing", "name"],
            },
        ),
        migrations.RunPython(create_perimeters, migrations.RunPython.noop),
        migrations.AddField(
            model_name="scanimport",
            name="perimeter",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                related_name="scan_imports",
                to="core.perimeter",
            ),
        ),
        migrations.AddField(
            model_name="vulnerabilityfinding",
            name="perimeter",
            field=models.ForeignKey(
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                related_name="findings",
                to="core.perimeter",
            ),
        ),
        migrations.RunPython(assign_existing_to_internal, migrations.RunPython.noop),
        migrations.AlterField(
            model_name="vulnerabilityfinding",
            name="perimeter",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.PROTECT,
                related_name="findings",
                to="core.perimeter",
            ),
        ),
        migrations.RemoveConstraint(
            model_name="vulnerabilityfinding",
            name="unique_finding_per_host_vuln_port",
        ),
        migrations.AddConstraint(
            model_name="vulnerabilityfinding",
            constraint=models.UniqueConstraint(
                fields=("host", "vulnerability_definition", "service_port", "perimeter"),
                name="unique_finding_per_host_vuln_port_perimeter",
            ),
        ),
    ]
