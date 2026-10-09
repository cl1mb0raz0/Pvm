"""Rows every PVM installation starts with (also re-created by a factory reset)."""

PERIMETERS = [
    {
        "name": "Internal",
        "slug": "internal",
        "description": "Scanned by the Qualys Scanner Appliance Inside the Network",
        "internet_facing": False,
    },
    {
        "name": "External",
        "slug": "external",
        "description": "Scanned from the Internet by Qualys",
        "internet_facing": True,
    },
]


def create_default_perimeters():
    from .models import Perimeter

    for values in PERIMETERS:
        Perimeter.objects.get_or_create(slug=values["slug"], defaults=values)


# Remediation targets in days, as agreed with the team; editable in the
# Django admin (SLA Policies), which re-applies them to open findings.
SLA_TARGET_DAYS = {"critical": 7, "high": 30, "medium": 90, "low": 180}


def create_default_sla_policies():
    from .models import SLAPolicy

    for severity, days in SLA_TARGET_DAYS.items():
        SLAPolicy.objects.get_or_create(severity=severity, defaults={"target_days": days})
