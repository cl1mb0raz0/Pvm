import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0019_stop_import_and_balancer_servers'),
    ]

    operations = [
        migrations.CreateModel(
            name='Snapshot',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('taken_at', models.DateTimeField(db_index=True)),
                ('reason', models.CharField(choices=[('import', 'After an Import'), ('nightly', 'Nightly'), ('manual', 'On Request')], max_length=16)),
                ('findings_total', models.PositiveIntegerField(default=0)),
                ('findings_open', models.PositiveIntegerField(default=0)),
                ('counts', models.JSONField(blank=True, default=dict)),
                ('scan_import', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='snapshots', to='core.scanimport')),
            ],
            options={
                'ordering': ['-taken_at'],
            },
        ),
        migrations.CreateModel(
            name='FindingState',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('status', models.CharField(max_length=16)),
                ('severity', models.CharField(max_length=16)),
                ('priority_score', models.PositiveSmallIntegerField(default=0)),
                ('patch_verdict', models.CharField(blank=True, max_length=32)),
                ('team', models.CharField(blank=True, max_length=100)),
                ('due_date', models.DateField(blank=True, null=True)),
                ('finding', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='states', to='core.vulnerabilityfinding')),
                ('snapshot', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='states', to='core.snapshot')),
            ],
        ),
        migrations.AddConstraint(
            model_name='findingstate',
            constraint=models.UniqueConstraint(fields=('snapshot', 'finding'), name='unique_state_per_snapshot'),
        ),
    ]
