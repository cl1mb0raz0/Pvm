from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from core import epss, priority
from core.models import Cve


class Command(BaseCommand):
    help = "Fetch EPSS scores from FIRST now for every CVE (or only those never fetched) and recompute priorities."

    def add_arguments(self, parser):
        parser.add_argument("--only-new", action="store_true", help="Only CVEs never fetched.")

    def handle(self, *args, **options):
        if not settings.EPSS_ENABLED:
            raise CommandError("EPSS Download Is Disabled (EPSS_ENABLED=false).")
        cves = epss.never_fetched() if options["only_new"] else Cve.objects.all()
        try:
            scored = epss.refresh(cves)
        except epss.EpssError as exc:
            raise CommandError(str(exc)) from exc
        changed = priority.recompute()
        self.stdout.write(self.style.SUCCESS(f"EPSS Refreshed: {scored} CVEs Scored; {changed} Priorities Changed."))
