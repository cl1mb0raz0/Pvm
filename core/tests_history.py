"""
"As Of <date>": the situation on a past day (core/history.py).

Two paths are covered: the reconstruction from the scans already imported
(which findings were open then, replayed from the detection events) and the
snapshots written after every import and every night, which also remember
the severity, priority, team, due date and verdict of that day.
"""

from datetime import date, timedelta

from django.test import TestCase
from django.utils import timezone

from accounts.models import Team
from backups import service

from . import history
from .models import (
    FindingState,
    Host,
    PatchCheck,
    Perimeter,
    Snapshot,
    VulnerabilityDefinition,
    VulnerabilityFinding,
)
from .tests_imports import FIXTURE, ImportTestMixin

Status = VulnerabilityFinding.Status
# The SSH finding of api.example.test, the row the second scan drops.
DROPPED = '192.0.2.10,api.example.test,,,"host scanned, found vuln",'


class ParseTests(TestCase):
    def test_only_a_past_date_is_accepted(self):
        today = timezone.localdate()
        self.assertEqual(history.parse("2026-06-30"), date(2026, 6, 30))
        self.assertIsNone(history.parse(""))
        self.assertIsNone(history.parse("not a date"))
        self.assertIsNone(history.parse("2026-02-31"))
        self.assertIsNone(history.parse(today.isoformat()))
        self.assertIsNone(history.parse((today + timedelta(days=1)).isoformat()))


class ReconstructionTests(ImportTestMixin, TestCase):
    """Without a snapshot, the scans themselves answer (core/history._from_scans)."""

    def setUp(self):
        super().setUp()
        self.old = timezone.localdate() - timedelta(days=14)
        self.mid = timezone.localdate() - timedelta(days=7)
        self.first = self.full_import(scan_date=self.old)
        # Second scan, a week later: the SSH finding on api.example.test is gone.
        without = FIXTURE.read_text().replace(DROPPED + "38909", DROPPED + "99999")
        self.second = self.full_import(content=without.encode(), scan_date=self.mid)
        self.ssh_api = VulnerabilityFinding.objects.get(
            host__hostname="api.example.test", vulnerability_definition__qid="38909"
        )
        Snapshot.objects.all().delete()  # the imports took some: this class tests the other path

    def open_at(self, day):
        findings, source = history.as_of(VulnerabilityFinding.objects.all(), day)
        return source, set(findings.values_list("pk", flat=True))

    def test_a_finding_closed_by_a_later_scan_was_open_before_it(self):
        source, before = self.open_at(self.old + timedelta(days=1))
        self.assertEqual(source, history.SCANS)
        self.assertIn(self.ssh_api.pk, before)

        _source, after = self.open_at(self.mid + timedelta(days=1))
        self.assertNotIn(self.ssh_api.pk, after)
        self.assertEqual(self.ssh_api.status, Status.RESOLVED)
        # Everything the second scan still saw is open on both days.
        portal = VulnerabilityFinding.objects.get(
            host__hostname="portal.example.test", vulnerability_definition__qid="38909"
        )
        self.assertIn(portal.pk, before)
        self.assertIn(portal.pk, after)

    def test_a_finding_is_not_shown_before_it_existed(self):
        new = VulnerabilityFinding.objects.get(vulnerability_definition__qid="99999")
        _source, before = self.open_at(self.old + timedelta(days=1))
        self.assertNotIn(new.pk, before)
        _source, after = self.open_at(self.mid + timedelta(days=1))
        self.assertIn(new.pk, after)

    def test_a_finding_resolved_by_hand_counts_as_closed_from_that_day(self):
        portal = VulnerabilityFinding.objects.get(
            host__hostname="portal.example.test", vulnerability_definition__qid="38909"
        )
        portal.status = Status.RESOLVED
        portal.resolved_at = timezone.now() - timedelta(days=3)
        portal.save(update_fields=["status", "resolved_at"])
        _source, week_ago = self.open_at(timezone.localdate() - timedelta(days=6))
        self.assertIn(portal.pk, week_ago)
        _source, yesterday = self.open_at(timezone.localdate() - timedelta(days=1))
        self.assertNotIn(portal.pk, yesterday)

    def test_each_perimeter_is_answered_by_its_own_scans(self):
        """An external scan seeing a QID says nothing about the internal finding, and the reverse."""
        self.full_import(scan_date=timezone.localdate() - timedelta(days=1), perimeter="external")
        _source, yesterday = self.open_at(timezone.localdate() - timedelta(days=1))
        internal_ssh = VulnerabilityFinding.objects.get(
            host__hostname="api.example.test", vulnerability_definition__qid="38909", perimeter__slug="internal"
        )
        external_ssh = VulnerabilityFinding.objects.get(
            host__hostname="api.example.test", vulnerability_definition__qid="38909", perimeter__slug="external"
        )
        self.assertNotIn(internal_ssh.pk, yesterday)  # closed by the internal scan of a week ago
        self.assertIn(external_ssh.pk, yesterday)  # the external scan of yesterday saw it

    def test_the_banner_names_the_scans_it_relied_on(self):
        note = history.describe(self.mid + timedelta(days=1), history.SCANS)
        self.assertIn("Reconstructed from the Scans", note)
        self.assertIn(self.mid.strftime("%Y-%m-%d"), note)
        self.assertIn("Today's Values", note)

    def test_nothing_was_known_before_the_first_scan(self):
        day = self.old - timedelta(days=1)
        _source, nothing = self.open_at(day)
        self.assertEqual(nothing, set())
        self.assertIn("No Scan Had Run", history.describe(day, history.SCANS))


class SnapshotTests(ImportTestMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.scan = self.full_import(scan_date=timezone.localdate() - timedelta(days=10))
        self.yesterday = timezone.localdate() - timedelta(days=1)

    def test_an_import_records_one(self):
        snapshot = Snapshot.objects.get(reason=Snapshot.Reason.IMPORT)
        self.assertEqual(snapshot.scan_import, self.scan)
        self.assertEqual(snapshot.findings_total, VulnerabilityFinding.objects.count())
        self.assertEqual(snapshot.findings_open, VulnerabilityFinding.objects.exclude(status=Status.RESOLVED).count())
        self.assertEqual(FindingState.objects.filter(snapshot=snapshot).count(), snapshot.findings_total)
        self.assertEqual(sum(snapshot.counts["severities"].values()), snapshot.findings_total)

    def test_it_answers_with_the_values_of_that_day(self):
        finding = VulnerabilityFinding.objects.get(vulnerability_definition__qid="150440")
        team = Team.objects.create(name="Web Ops")
        finding.assigned_team = team
        finding.due_date = timezone.localdate()
        finding.save(update_fields=["assigned_team", "due_date"])
        PatchCheck.objects.create(
            vulnerability_finding=finding,
            verdict=PatchCheck.Verdict.FIXED,
            ubuntu_release="jammy",
            checked_at=timezone.now(),
        )
        Snapshot.objects.all().delete()
        history.take(Snapshot.Reason.NIGHTLY, when=timezone.now() - timedelta(days=1))

        # Today everything about it changes.
        finding.vulnerability_definition.severity = VulnerabilityDefinition.Severity.LOW
        finding.vulnerability_definition.save(update_fields=["severity"])
        finding.assigned_team = None
        finding.status = Status.RESOLVED
        finding.resolved_at = timezone.now()
        finding.priority_score = 0
        finding.save(update_fields=["assigned_team", "status", "resolved_at", "priority_score"])
        PatchCheck.objects.filter(vulnerability_finding=finding).update(verdict=PatchCheck.Verdict.VULNERABLE_UPDATE)

        findings, source = history.as_of(VulnerabilityFinding.objects.all(), self.yesterday)
        self.assertEqual(source, history.SNAPSHOT)
        row = findings.get(pk=finding.pk)
        state = history.state(row)
        self.assertEqual(state.source, history.SNAPSHOT)
        self.assertEqual(state.severity, VulnerabilityDefinition.Severity.CRITICAL)
        self.assertEqual(state.team, "Web Ops")
        self.assertEqual(state.patch_verdict, PatchCheck.Verdict.FIXED)
        self.assertEqual(state.status, Status.NEW)
        self.assertFalse(state.resolved)
        self.assertIn("Recorded by the Snapshot", state.note)

    def test_a_finding_resolved_then_is_out_of_the_open_view(self):
        finding = VulnerabilityFinding.objects.get(vulnerability_definition__qid="150440")
        finding.status = Status.RESOLVED
        finding.resolved_at = timezone.now()
        finding.save(update_fields=["status", "resolved_at"])
        Snapshot.objects.all().delete()
        history.take(Snapshot.Reason.MANUAL, when=timezone.now() - timedelta(days=1))

        open_then, _ = history.as_of(VulnerabilityFinding.objects.all(), self.yesterday)
        self.assertNotIn(finding.pk, set(open_then.values_list("pk", flat=True)))
        everything, _ = history.as_of(VulnerabilityFinding.objects.all(), self.yesterday, status="all")
        self.assertIn(finding.pk, set(everything.values_list("pk", flat=True)))

    def test_the_team_survives_the_team_being_deleted(self):
        finding = VulnerabilityFinding.objects.get(vulnerability_definition__qid="150440")
        team = Team.objects.create(name="Gone Team")
        finding.assigned_team = team
        finding.save(update_fields=["assigned_team"])
        history.take(Snapshot.Reason.MANUAL, when=timezone.now() - timedelta(days=1))
        team.delete()
        self.assertEqual(
            FindingState.objects.filter(finding=finding).order_by("-pk").first().team, "Gone Team"
        )

    def test_reset_data_removes_the_history(self):
        service.reset_data(self.analyst, delete_report_files=False)
        self.assertEqual(Snapshot.objects.count(), 0)
        self.assertEqual(FindingState.objects.count(), 0)

    def test_the_command_takes_one(self):
        from django.core.management import call_command
        from io import StringIO

        out = StringIO()
        call_command("snapshot", stdout=out)
        self.assertIn("Findings", out.getvalue())
        self.assertTrue(Snapshot.objects.filter(reason=Snapshot.Reason.MANUAL).exists())


class PageTests(ImportTestMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.old = timezone.localdate() - timedelta(days=14)
        self.mid = timezone.localdate() - timedelta(days=7)
        self.full_import(scan_date=self.old)
        without = FIXTURE.read_text().replace(DROPPED + "38909", DROPPED + "99999")
        self.full_import(content=without.encode(), scan_date=self.mid)
        Snapshot.objects.all().delete()

    def test_the_list_shows_the_band_and_hides_triage(self):
        day = (self.old + timedelta(days=1)).isoformat()
        page = self.client.get(f"/vulnerabilities/?as_of={day}")
        self.assertContains(page, "As Of")
        self.assertContains(page, "Reconstructed from the Scans")
        # Triage would act on today's findings: it has no place in a past view.
        self.assertNotContains(page, 'name="finding"')
        live = self.client.get("/vulnerabilities/")
        self.assertContains(live, 'name="finding"')

    def test_the_list_shows_what_was_open_then(self):
        ssh_api = VulnerabilityFinding.objects.get(
            host__hostname="api.example.test", vulnerability_definition__qid="38909"
        )
        added = VulnerabilityFinding.objects.get(vulnerability_definition__qid="99999")
        before = self.client.get(f"/vulnerabilities/?as_of={(self.old + timedelta(days=1)).isoformat()}")
        after = self.client.get(f"/vulnerabilities/?as_of={(self.mid + timedelta(days=1)).isoformat()}")
        shown = lambda page: {f.pk for f in page.context["page"].object_list}  # noqa: E731
        self.assertIn(ssh_api.pk, shown(before))
        self.assertNotIn(added.pk, shown(before))
        self.assertNotIn(ssh_api.pk, shown(after))
        self.assertIn(added.pk, shown(after))
        self.assertEqual(before.context["page"].paginator.count, VulnerabilityFinding.objects.count() - 1)

    def test_a_snapshot_answers_the_page_and_sorts_on_its_own_values(self):
        day = timezone.localdate() - timedelta(days=1)
        history.take(Snapshot.Reason.NIGHTLY, when=timezone.now() - timedelta(days=1))
        # Today's severities change: the page must keep showing the recorded ones.
        VulnerabilityDefinition.objects.update(severity=VulnerabilityDefinition.Severity.LOW)

        page = self.client.get(f"/vulnerabilities/?as_of={day.isoformat()}&sort=severity")
        self.assertContains(page, "From the Snapshot of")
        shown = [history.state(f).severity for f in page.context["page"].object_list]
        self.assertEqual(shown, sorted(shown, key=["critical", "high", "medium", "low"].index))
        self.assertIn("critical", shown)  # recorded, although every QID is low today

        # And the other way round, worst last.
        flipped = self.client.get(f"/vulnerabilities/?as_of={day.isoformat()}&sort=severity&dir=desc")
        first = history.state(flipped.context["page"].object_list[0]).severity
        self.assertEqual(first, "low")

    def test_an_invalid_date_is_ignored(self):
        page = self.client.get("/vulnerabilities/?as_of=yesterday")
        self.assertNotContains(page, "as-of-band")

    def test_the_export_says_which_day_it_describes(self):
        day = (self.old + timedelta(days=1)).isoformat()
        preview = self.client.get(f"/export/preview/?dataset=findings&as_of={day}")
        self.assertContains(preview, "As Of")
        self.assertContains(preview, "Open on That Date")

        report = self.client.get(f"/export/run/?dataset=findings&format=html&as_of={day}")
        body = report.content.decode()
        self.assertIn(f"Vulnerabilities as of {day}", body)
        self.assertIn("Reconstructed from the Scans", body)
        self.assertIn("<b>As Of:</b>", body)

    def test_the_csv_of_an_as_of_export_holds_the_state_of_that_day(self):
        import csv as csv_module
        import io

        day = (self.mid + timedelta(days=1)).isoformat()
        response = self.client.get(f"/vulnerabilities/export.csv?as_of={day}")
        text = b"".join(response.streaming_content).decode("utf-8-sig")
        rows = list(csv_module.reader(io.StringIO(text), delimiter=";"))
        header, data = rows[0], rows[1:]
        status = header.index("Status")
        open_then, _ = history.as_of(VulnerabilityFinding.objects.all(), self.mid + timedelta(days=1))
        self.assertEqual(len(data), open_then.count())
        self.assertEqual({r[status] for r in data}, {"Open"})
