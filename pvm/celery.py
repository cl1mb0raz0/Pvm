import os

from celery import Celery, signals

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "pvm.settings")

app = Celery("pvm")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()


@signals.worker_init.connect
@signals.beat_init.connect
def _check_settings(**kwargs):
    from pvm.startup import require_real_secret_key

    require_real_secret_key()


@signals.worker_ready.connect
def _resume_interrupted_checks(sender=None, **kwargs):
    """
    A host check running when the interactive worker stopped (e.g. a
    rebuild) is lost, and its host would show "Checking…" for ever without
    a "Check Now" button: queue it again. Duplicates of checks still waiting
    in the queue are harmless (the tracker records are then cached).
    """
    if sender is not None and str(getattr(sender, "hostname", "")).startswith("background@"):
        return
    from core.tasks import resume_interrupted_checks

    resume_interrupted_checks()
