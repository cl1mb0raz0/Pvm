FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# WeasyPrint (PDF exports) renders through Pango; the DejaVu fonts are what
# the report asks for, so a container without them does not fall back to boxes.
RUN apt-get update \
    && apt-get install --no-install-recommends -y \
        libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b libffi8 fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Safe without a database connection: it only needs settings to import.
RUN python manage.py collectstatic --noinput

EXPOSE 8000

# Overridden by docker-compose.yml for the worker/beat services and to run
# migrations before starting gunicorn on the web service.
CMD ["gunicorn", "pvm.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "3"]
