"""
Scanner-agnostic import pipeline: applies a list of `Detection` records
from one report to the database.

The diffing rules live here, once, whatever the
report's source (manual upload now, scheduled API import later):

- hosts in the report are created or updated; a host is matched by its
  Qualys host ID when the report has one, otherwise by IP + hostname
- a detection already tracked on (host, QID, port, perimeter) updates that
  finding instead of creating a new one
- an open finding of this report's perimeter, on a host covered by this
  report but absent from it, is resolved; findings on other hosts or of
  other perimeters (an external scan never sees what only the internal
  one can) are untouched
- a resolved finding detected again goes to "needs review", unless an
  analyst verified it as not vulnerable (distro patch verification, e.g.
  a backported fix the scanner cannot see from the version banner): then
  it stays resolved and is counted as "verified not vulnerable"
- every host in the report gets the import's tags (never removed here)
- open findings get their due date from the SLA policy (core/sla.py): the
  clock starts at first detection, and again when a finding comes back
"""

from decimal import Decimal

from django.db import transaction
from django.utils import timezone

from core import audit, balancer, network_mapping, priority, sla, tags
from core.models import (
    Cve,
    DistroPatchVerification,
    Host,
    ScanDetectionEvent,
    ScanImport,
    VulnerabilityDefinition,
    VulnerabilityFinding,
)

Status = VulnerabilityFinding.Status


def _clip(value, model, field):
    return value[: model._meta.get_field(field).max_length]


class Stopped(Exception):
    """The user asked to stop the import: the transaction rolls back, nothing is written."""


class _Run:
    def __init__(self, scan_import, detections, should_stop=None):
        if scan_import.perimeter_id is None:
            raise ValueError("The Import Has No Perimeter.")
        self.scan_import = scan_import
        self.perimeter = scan_import.perimeter
        self.detections = detections
        self.when = scan_import.scanned_at or timezone.now()
        self.counts = {
            "hosts_new": 0,
            "hosts_updated": 0,
            "findings_new": 0,
            "findings_still_open": 0,
            "findings_reopened": 0,
            "findings_resolved": 0,
            "findings_verified": 0,
        }
        self.hosts = {}
        self.definitions = {}
        self.findings = {}
        self.severity_changed = set()
        self.resolver = None
        self.should_stop = should_stop

    def host(self, d):
        key = ("id", d.qualys_host_id) if d.qualys_host_id else ("ip", d.ip, d.hostname)
        if key in self.hosts:
            return self.hosts[key]
        hostname = _clip(d.hostname, Host, "hostname")
        if d.qualys_host_id:
            host = Host.objects.filter(qualys_host_id=d.qualys_host_id).first()
        else:
            host = Host.objects.filter(ip_address=d.ip, hostname=hostname).first()
        if host is None:
            host = Host(qualys_host_id=d.qualys_host_id or None)
            self.counts["hosts_new"] += 1
        else:
            self.counts["hosts_updated"] += 1
        host.ip_address = d.ip
        host.hostname = hostname
        if d.os:
            host.os_name = _clip(d.os, Host, "os_name")
        if not host.last_scanned_at or host.last_scanned_at < self.when:
            host.last_scanned_at = self.when
        host.is_active = True
        others = []
        if not host.private_ip:
            # From the mapping the user uploaded (Imports > Mapping), if it
            # lists this host: a CSV row, or a balancer's name rule or VIP.
            if self.resolver is None:
                self.resolver = balancer.Resolver.stored()
            ips = balancer.private_ips_for_new_host(host, network_mapping.private_ip_for(host), self.resolver)
            host.private_ip, others = (ips[0] if ips else None), ips
        host.save()
        if len(others) > 1:
            balancer.save_other_private_ips(host, others)
        self.hosts[key] = host
        return host

    def definition(self, d):
        if d.qid in self.definitions:
            return self.definitions[d.qid]
        definition, _ = VulnerabilityDefinition.objects.get_or_create(
            qid=d.qid, defaults={"title": d.title, "severity": d.severity}
        )
        definition.title = _clip(d.title, VulnerabilityDefinition, "title")
        if definition.severity != d.severity:
            self.severity_changed.add(definition.pk)
        definition.severity = d.severity
        definition.qualys_severity = d.qualys_severity
        if d.threat:
            definition.description = d.threat
        if d.solution:
            definition.solution_text = d.solution
        if d.cvss:
            definition.cvss_score = Decimal(d.cvss)
        definition.save()
        if d.cves:
            definition.cves.add(*[Cve.objects.get_or_create(cve_id=c.upper())[0] for c in d.cves])
        self.definitions[d.qid] = definition
        return definition

    def finding(self, d):
        host, definition = self.host(d), self.definition(d)
        port = _clip(d.service_port, VulnerabilityFinding, "service_port")
        key = (host.pk, definition.pk, port)
        finding = self.findings.get(key)
        if finding is None:
            finding = VulnerabilityFinding.objects.filter(
                host=host, vulnerability_definition=definition, service_port=port, perimeter=self.perimeter
            ).first()
            if finding is None:
                finding = VulnerabilityFinding(
                    host=host,
                    vulnerability_definition=definition,
                    service_port=port,
                    perimeter=self.perimeter,
                    status=Status.NEW,
                    first_detected_at=self.when,
                    last_detected_at=self.when,
                )
                sla.start_clock(finding, self.when)
                self.counts["findings_new"] += 1
            elif finding.status == Status.RESOLVED and _verified_not_vulnerable(finding):
                self.counts["findings_verified"] += 1
            elif finding.status == Status.RESOLVED:
                finding.status = Status.NEEDS_REVIEW
                finding.resolved_at = None
                sla.start_clock(finding, self.when)
                self.counts["findings_reopened"] += 1
            else:
                if finding.status == Status.NEW:
                    finding.status = Status.STILL_OPEN
                self.counts["findings_still_open"] += 1
            finding.extra_data = {}
            finding.detection_result = ""
            self.findings[key] = finding

        # Several rows can describe the same finding (e.g. one per instance):
        # keep every distinct result and extra value.
        if d.result and d.result not in finding.detection_result:
            finding.detection_result = "\n\n".join(filter(None, [finding.detection_result, d.result]))
        for column, value in d.extra.items():
            previous = finding.extra_data.get(column)
            if previous and value not in previous.split("\n"):
                value = f"{previous}\n{value}"
            finding.extra_data[column] = value
        if finding.last_detected_at < self.when:
            finding.last_detected_at = self.when
        return finding

    def apply(self):
        for i, d in enumerate(self.detections):
            # "Stop Import": checked often enough to answer quickly, rarely
            # enough not to query the database once per row.
            if self.should_stop and i % 500 == 0 and self.should_stop():
                raise Stopped
            self.finding(d)
        target_days = sla.targets()
        for finding in self.findings.values():
            if finding.status != Status.RESOLVED:
                sla.apply(finding, target_days)
            finding.save()
        # Open findings of a QID whose severity changed, on hosts not in this report.
        if self.severity_changed:
            sla.recompute(VulnerabilityFinding.objects.filter(vulnerability_definition__in=self.severity_changed))
        ScanDetectionEvent.objects.bulk_create(
            ScanDetectionEvent(scan_import=self.scan_import, vulnerability_finding=f, detected_at=self.when)
            for f in self.findings.values()
        )

        hosts = list(self.hosts.values())
        self.scan_import.hosts.set(hosts)
        tags.apply(list(self.scan_import.tags.all()), hosts)
        # Only findings last seen before this scan: importing an older
        # report after a newer one must not close what the newer one saw.
        stale = (
            VulnerabilityFinding.objects.filter(
                host__in=hosts, perimeter=self.perimeter, last_detected_at__lt=self.when
            )
            .exclude(status=Status.RESOLVED)
            .exclude(pk__in=[f.pk for f in self.findings.values()])
        )
        self.counts["findings_resolved"] = stale.update(status=Status.RESOLVED, resolved_at=self.when)
        # New CVSS from the report, new findings, perimeters, due dates.
        priority.recompute()
        return self.counts


def _verified_not_vulnerable(finding):
    return DistroPatchVerification.objects.filter(
        vulnerability_finding=finding,
        verdict__in=[
            DistroPatchVerification.Verdict.CONFIRMED_FIXED,
            DistroPatchVerification.Verdict.LIKELY_FALSE_POSITIVE,
        ],
    ).exists()


def run(scan_import, detections, skipped, should_stop=None):
    """
    Apply `detections` to the database and mark `scan_import` completed.
    `should_stop`, called while the rows are applied, raises Stopped when the
    user asked to stop: everything written so far is rolled back with it.
    """
    with transaction.atomic():
        counts = _Run(scan_import, detections, should_stop).apply()
        scan_import.status = ScanImport.Status.COMPLETED
        scan_import.completed_at = timezone.now()
        scan_import.findings_count = (
            counts["findings_new"] + counts["findings_still_open"] + counts["findings_reopened"] + counts["findings_verified"]
        )
        scan_import.summary = {**scan_import.summary, "result": counts, "skipped": dict(skipped)}
        scan_import.error_message = ""
        scan_import.save()
        if scan_import.triggered_by:
            audit.log(scan_import.triggered_by, "import.completed", scan_import, **counts)
    return counts
