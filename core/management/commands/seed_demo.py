"""
Fill an empty database with realistic demo data, so the UI can be
explored before the Qualys connector exists.

Creates teams, SLA policies, hosts, installed packages, vulnerability
definitions, eight weekly scan imports with their detection events, and
one distro-patch verification. Refuses to run if any host already exists,
so it can never mix demo rows into real data. Users are never created.

QIDs and the Qualys host IDs are made up; CVE IDs are real. CVSS scores
are not invented: run `python manage.py nvd_refresh` to fetch them.
"""

import random
from datetime import timedelta

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

from accounts.models import Team, User
from core.models import (
    Cve,
    DistroPatchVerification,
    Host,
    InstalledPackage,
    Perimeter,
    ScanDetectionEvent,
    ScanImport,
    SLAPolicy,
    VulnerabilityDefinition,
    VulnerabilityFinding,
)

Severity = VulnerabilityDefinition.Severity
Status = VulnerabilityFinding.Status

SLA_DAYS = {Severity.CRITICAL: 7, Severity.HIGH: 30, Severity.MEDIUM: 90, Severity.LOW: 180}
QUALYS_LEVEL = {Severity.CRITICAL: 5, Severity.HIGH: 4, Severity.MEDIUM: 3}

TEAMS = ["Platform", "DevOps", "Database", "Networking"]

# (hostname, ip, os_version, environment)
HOSTS = [
    ("web-01", "10.0.4.11", "Ubuntu 20.04", Host.Environment.PRODUCTION),
    ("web-02", "10.0.4.12", "Ubuntu 20.04", Host.Environment.PRODUCTION),
    ("api-01", "10.0.4.21", "Ubuntu 22.04", Host.Environment.PRODUCTION),
    ("db-01", "10.0.6.10", "Debian 12", Host.Environment.PRODUCTION),
    ("db-02", "10.0.6.11", "Debian 12", Host.Environment.PRODUCTION),
    ("cache-01", "10.0.6.30", "Ubuntu 22.04", Host.Environment.PRODUCTION),
    ("ci-runner-01", "10.0.8.40", "Ubuntu 22.04", Host.Environment.DEV),
    ("staging-web-01", "10.1.4.11", "Ubuntu 20.04", Host.Environment.STAGING),
    ("vpn-gw-01", "10.0.1.5", "Debian 11", Host.Environment.PRODUCTION),
    ("monitoring-01", "10.0.9.2", "Ubuntu 22.04", Host.Environment.PRODUCTION),
]

# (package, version per distro family)
PACKAGES = {
    "apache2": {"ubuntu20": "2.4.41-4ubuntu3.17", "ubuntu22": "2.4.52-1ubuntu4.9", "debian": "2.4.62-1~deb12u1"},
    "openssh-server": {"ubuntu20": "1:8.2p1-4ubuntu0.11", "ubuntu22": "1:8.9p1-3ubuntu0.10", "debian": "1:9.2p1-2+deb12u3"},
    "openssl": {"ubuntu20": "1.1.1f-1ubuntu2.23", "ubuntu22": "3.0.2-0ubuntu1.18", "debian": "3.0.14-1~deb12u2"},
    "libwebp6": {"ubuntu20": "0.6.1-2ubuntu0.20.04.3"},
    "libwebp7": {"ubuntu22": "1.2.2-2ubuntu0.22.04.2", "debian": "1.2.4-0.2+deb12u1"},
    "postgresql-15": {"debian": "15.8-0+deb12u1"},
    "redis-server": {"ubuntu22": "5:6.0.16-1ubuntu1"},
    "nginx": {"ubuntu22": "1.18.0-6ubuntu14.4", "debian": "1.22.1-9"},
    "sudo": {"ubuntu20": "1.8.31-1ubuntu1.5", "ubuntu22": "1.9.9-1ubuntu2.4", "debian": "1.9.13p3-1+deb12u1"},
    "xz-utils": {"ubuntu22": "5.2.5-2ubuntu1", "debian": "5.4.1-0.2"},
}

# (qid, cves, title, severity, cvss, package)
DEFINITIONS = [
    ("38909", ["CVE-2024-6387"], "OpenSSH Signal Handler Race Condition (regreSSHion)", Severity.CRITICAL, "8.1", "openssh-server"),
    ("380012", ["CVE-2024-3094"], "XZ Utils Backdoor in liblzma", Severity.CRITICAL, "10.0", "xz-utils"),
    ("150440", ["CVE-2021-44228", "CVE-2021-45046"], "Apache Log4j Remote Code Execution (Log4Shell)", Severity.CRITICAL, "10.0", None),
    ("179125", ["CVE-2023-4863"], "libwebp Heap Buffer Overflow in WebP Lossless", Severity.HIGH, "8.8", "libwebp7"),
    ("179140", ["CVE-2023-4863"], "Ubuntu libwebp6 Heap Buffer Overflow", Severity.HIGH, "8.8", "libwebp6"),
    ("150495", ["CVE-2021-41773"], "Apache HTTP Server Path Traversal", Severity.HIGH, "7.5", "apache2"),
    ("38896", ["CVE-2023-38408"], "OpenSSH ssh-agent Remote Code Execution", Severity.HIGH, "9.8", "openssh-server"),
    ("376001", ["CVE-2023-44487"], "HTTP/2 Rapid Reset Denial of Service", Severity.HIGH, "7.5", "nginx"),
    ("376510", ["CVE-2023-22809"], "Sudo sudoedit Privilege Escalation", Severity.HIGH, "7.8", "sudo"),
    ("38657", ["CVE-2016-2183"], "SSL/TLS Birthday Attack on 64-bit Block Ciphers (SWEET32)", Severity.MEDIUM, "7.5", None),
    ("38794", [], "TLS Protocol Version 1.0 and 1.1 Enabled", Severity.MEDIUM, "6.5", None),
    ("376200", ["CVE-2023-48795"], "SSH Terrapin Prefix Truncation Attack", Severity.MEDIUM, "5.9", "openssh-server"),
    ("376305", ["CVE-2023-5678"], "OpenSSL Excessive Time Spent in DH Key Generation", Severity.MEDIUM, "5.3", "openssl"),
    ("237010", ["CVE-2024-24790"], "PostgreSQL Client Library Information Disclosure", Severity.MEDIUM, "5.3", "postgresql-15"),
    ("38170", [], "SSL Certificate Subject Common Name Does Not Match Server FQDN", Severity.LOW, None, None),
    ("38173", [], "SSL Certificate Signature Verification Failed", Severity.LOW, None, None),
    ("86473", [], "Web Server HTTP Trace/Track Method Support", Severity.LOW, "3.7", "apache2"),
    ("38739", [], "Deprecated SSH Cryptographic Settings", Severity.LOW, "3.7", "openssh-server"),
]

PORTS = {"openssh-server": "22/tcp", "apache2": "443/tcp", "nginx": "443/tcp", "postgresql-15": "5432/tcp"}
WEEKS = 8


def _distro(os_version):
    if os_version.startswith("Ubuntu 20"):
        return "ubuntu20"
    if os_version.startswith("Ubuntu"):
        return "ubuntu22"
    return "debian"


class Command(BaseCommand):
    help = "Populate an empty database with demo data for exploring the UI."

    @transaction.atomic
    def handle(self, *args, **options):
        if Host.objects.exists():
            raise CommandError("Hosts already exist; refusing to mix demo data into a non-empty database.")

        rng = random.Random(42)
        now = timezone.now()
        # Demo scans all come from the internal scanner appliance.
        internal = Perimeter.objects.get(slug="internal")

        for severity, days in SLA_DAYS.items():
            SLAPolicy.objects.get_or_create(severity=severity, defaults={"target_days": days})
        teams = [Team.objects.get_or_create(name=name)[0] for name in TEAMS]

        definitions = []
        for qid, cve_ids, title, severity, cvss, package in DEFINITIONS:
            d = VulnerabilityDefinition.objects.create(
                qid=qid,
                title=title,
                severity=severity,
                qualys_severity=QUALYS_LEVEL.get(severity) or rng.choice([1, 2]),
                cvss_score=cvss,
            )
            d.cves.set([Cve.objects.get_or_create(cve_id=c)[0] for c in cve_ids])
            definitions.append((d, package))

        # One automatic import per week; a failed manual upload is added below.
        scan_times = [now - timedelta(weeks=WEEKS - 1 - i, hours=rng.randint(0, 3)) for i in range(WEEKS)]
        imports = []
        for when in scan_times:
            imp = ScanImport.objects.create(
                source=ScanImport.Source.API, status=ScanImport.Status.COMPLETED, perimeter=internal, scanned_at=when
            )
            imports.append((imp, when))

        hosts = []
        for i, (hostname, ip, os_version, env) in enumerate(HOSTS):
            host = Host.objects.create(
                qualys_host_id=f"{1204500 + i * 37}",
                hostname=hostname,
                ip_address=ip,
                os_name="Linux",
                os_version=os_version,
                environment=env,
                last_scanned_at=scan_times[-1],
            )
            distro = _distro(os_version)
            packages = {}
            for name, versions in PACKAGES.items():
                if distro in versions and (name not in {"postgresql-15"} or hostname.startswith("db-")):
                    packages[name] = InstalledPackage.objects.create(
                        host=host,
                        package_name=name,
                        installed_version=versions[distro],
                        detected_at=scan_times[0],
                    )
            hosts.append((host, packages))

        counts = {imp.pk: 0 for imp, _ in imports}
        findings = []
        for host, packages in hosts:
            for definition, package in definitions:
                if package and package not in packages:
                    continue
                if not package and rng.random() > 0.35:
                    continue
                if package and rng.random() > 0.55:
                    continue
                # Detected from a random week onwards; some were fixed along the way.
                first = rng.randint(0, WEEKS - 1)
                last = WEEKS - 1 if rng.random() > 0.25 else rng.randint(first, WEEKS - 1)
                resolved = last < WEEKS - 1
                status = Status.RESOLVED if resolved else rng.choice(
                    [Status.NEW if first == WEEKS - 1 else Status.STILL_OPEN] * 3 + [Status.NEEDS_REVIEW]
                )
                triaged = status != Status.NEW and rng.random() > 0.2
                due = None
                if status != Status.RESOLVED:
                    due = (scan_times[first] + timedelta(days=SLA_DAYS[definition.severity])).date()
                f = VulnerabilityFinding.objects.create(
                    host=host,
                    vulnerability_definition=definition,
                    related_package=packages.get(package),
                    service_port=PORTS.get(package, rng.choice(["443/tcp", "8443/tcp", ""])),
                    perimeter=internal,
                    status=status,
                    assigned_team=rng.choice(teams) if triaged else None,
                    due_date=due,
                    sla_started_at=scan_times[first].date(),
                    first_detected_at=scan_times[first],
                    last_detected_at=scan_times[last],
                    resolved_at=scan_times[last] + timedelta(days=7) if resolved else None,
                )
                ScanDetectionEvent.objects.bulk_create(
                    ScanDetectionEvent(scan_import=imp, vulnerability_finding=f, detected_at=when)
                    for imp, when in imports[first : last + 1]
                )
                for imp, _ in imports[first : last + 1]:
                    counts[imp.pk] += 1
                findings.append(f)

        # started_at is auto_now_add, so backdate it with an update.
        for imp, when in imports:
            ScanImport.objects.filter(pk=imp.pk).update(
                started_at=when, completed_at=when + timedelta(minutes=rng.randint(6, 25)), findings_count=counts[imp.pk]
            )
        failed = ScanImport.objects.create(
            source=ScanImport.Source.MANUAL,
            status=ScanImport.Status.FAILED,
            error_message="Unrecognised report format: expected Qualys XML (VM detection) or CSV.",
        )
        ScanImport.objects.filter(pk=failed.pk).update(started_at=scan_times[-2] + timedelta(days=2))

        self._add_verification(hosts)

        self.stdout.write(self.style.SUCCESS(
            f"Created {len(hosts)} hosts, {len(findings)} findings and {len(imports) + 1} imports."
        ))

    def _add_verification(self, hosts):
        """The worked example: Apache on Ubuntu 20.04."""
        host, packages = hosts[0]
        definition = VulnerabilityDefinition.objects.get(qid="150495")
        finding, _ = VulnerabilityFinding.objects.get_or_create(
            host=host,
            vulnerability_definition=definition,
            service_port="443/tcp",
            perimeter=Perimeter.objects.get(slug="internal"),
            defaults={
                "related_package": packages["apache2"],
                "first_detected_at": timezone.now() - timedelta(weeks=WEEKS - 1),
                "last_detected_at": timezone.now(),
            },
        )
        finding.status = Status.NEEDS_REVIEW
        finding.resolved_at = None
        finding.save(update_fields=["status", "resolved_at"])
        DistroPatchVerification.objects.create(
            vulnerability_finding=finding,
            # Attributed to an existing analyst/admin if there is one.
            verified_by=User.objects.filter(role__in=[User.Role.ANALYST, User.Role.ADMIN]).order_by("pk").first(),
            verdict=DistroPatchVerification.Verdict.LIKELY_FALSE_POSITIVE,
            note=(
                "Qualys flags this from the upstream banner (Apache/2.4.41). Ubuntu 20.04 ships "
                "2.4.41-4ubuntu3.17, and the Ubuntu Security Tracker lists CVE-2021-41773 as "
                "'Not vulnerable' for focal: the affected code was introduced in 2.4.49 and never "
                "shipped in this release. Keep open for one more scan cycle, then close as a false positive."
            ),
            reference_url="https://ubuntu.com/security/CVE-2021-41773",
        )
