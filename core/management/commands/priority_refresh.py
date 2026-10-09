import logging

from django.conf import settings
from django.core.management.base import BaseCommand

from core import epss, priority

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = (
        "Recompute the risk priority of open findings. Run at every web start (docker-compose.yml), "
        "so an upgrade never shows stale priorities; also queues EPSS for CVEs never fetched."
    )

    def handle(self, *args, **options):
        changed = priority.recompute()
        self.stdout.write(f"Priorities Recomputed: {changed} Changed.")
        if settings.EPSS_ENABLED and epss.never_fetched().exists():
            from core.tasks import refresh_epss

            try:
                refresh_epss.delay(only_new=True)
            except Exception as exc:  # the broker may be down: never block the web start
                logger.warning("Could not queue the EPSS refresh: %s", exc)
