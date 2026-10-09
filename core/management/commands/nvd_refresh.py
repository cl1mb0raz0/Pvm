from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from core import nvd, priority
from core.models import Cve


class Command(BaseCommand):
    help = "Fetch CVSS scores from NVD for CVEs that are due (or all / some, see options). Runs in the foreground."

    def add_arguments(self, parser):
        parser.add_argument("cve_ids", nargs="*", help="Only these CVE IDs")
        parser.add_argument("--all", action="store_true", help="Refetch every CVE, even recently fetched ones")

    def handle(self, *args, cve_ids, all, **options):
        if not settings.NVD_ENABLED:
            raise CommandError("NVD lookups are disabled (NVD_ENABLED=false).")
        cves = Cve.objects.all() if (all or cve_ids) else nvd.due_for_refresh()
        if cve_ids:
            cves = cves.filter(cve_id__in=[c.upper() for c in cve_ids])
        cves = list(cves)
        minutes = len(cves) * nvd.request_interval() / 60
        self.stdout.write(f"Fetching {len(cves)} CVE(s) from NVD, about {minutes:.0f} min.")
        counts = nvd.refresh(cves)
        priority.recompute()
        self.stdout.write(self.style.SUCCESS(f"Done: {counts}"))
