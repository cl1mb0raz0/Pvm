from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from core import kev


class Command(BaseCommand):
    help = "Download the CISA Known Exploited Vulnerabilities catalog now and replace the local copy."

    def handle(self, *args, **options):
        if not settings.KEV_ENABLED:
            raise CommandError("CISA KEV Download Is Disabled (KEV_ENABLED=false).")
        try:
            count = kev.refresh()
        except kev.KevError as exc:
            raise CommandError(str(exc)) from exc
        self.stdout.write(self.style.SUCCESS(f"CISA KEV Catalog Refreshed: {count} Entries."))
