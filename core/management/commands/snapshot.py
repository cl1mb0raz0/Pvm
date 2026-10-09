from django.core.management.base import BaseCommand

from core import history
from core.models import Snapshot


class Command(BaseCommand):
    help = (
        'Record the state of every finding now, so "As Of <date>" can answer for today exactly '
        "(core/history.py). Taken automatically after every import and every night at 05:00; "
        "this command is the way to take one by hand."
    )

    def handle(self, *args, **options):
        snapshot = history.take(Snapshot.Reason.MANUAL)
        self.stdout.write(
            f"Snapshot #{snapshot.pk} Taken at {snapshot.label}: "
            f"{snapshot.findings_total} Findings, {snapshot.findings_open} Open."
        )
