from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0018_patch_check_progress'),
    ]

    operations = [
        migrations.AddField(
            model_name='scanimport',
            name='stop_requested',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='scanimport',
            name='task_id',
            field=models.CharField(blank=True, max_length=64),
        ),
        migrations.AddField(
            model_name='balancerconfig',
            name='servers',
            field=models.JSONField(blank=True, default=dict),
        ),
    ]
