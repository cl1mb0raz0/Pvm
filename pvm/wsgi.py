import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "pvm.settings")

application = get_wsgi_application()

from pvm.startup import require_real_secret_key  # noqa: E402  (needs settings loaded)

require_real_secret_key()
