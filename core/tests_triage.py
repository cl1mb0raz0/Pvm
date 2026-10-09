from datetime import date, timedelta

from django.test import TestCase
from django.utils import timezone

from accounts.models import Team, User

from .models import AuditLog, Host, Perimeter, VulnerabilityDefinition, VulnerabilityFinding
from .tests_imports import PASSWORD, ImportTestMixin

Status = VulnerabilityFinding.Status


class TriageTests(ImportTestMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.linux = Team.objects.create(name="Linux")
        internal = Perimeter.objects.get(slug="internal")
        critical = VulnerabilityDefinition.objects.create(qid="100", title="Critical Thing", severity="critical", qualys_severity=5)
        low = VulnerabilityDefinition.objects.create(qid="200", title="Low Thing", severity="low", qualys_severity=1)
        self.appsrv = Host.objects.create(hostname="appsrv.example.test", ip_address="192.0.2.20")
        other = Host.objects.create(hostname="other.example.test", ip_address="192.0.2.21")
        now = timezone.now()
        self.today = timezone.localdate()

        def finding(host, definition):
            return VulnerabilityFinding.objects.create(
                host=host, vulnerability_definition=definition, perimeter=internal,
                first_detected_at=now, last_detected_at=now, sla_started_at=self.today,
                due_date=self.today + timedelta(days=7 if definition.severity == "critical" else 180),
            )

        self.a = finding(self.appsrv, critical)
        self.b = finding(self.appsrv, low)
        self.c = finding(other, critical)

    def triage(self, **data):
        data.setdefault("next", "/vulnerabilities/")
        return self.client.post("/vulnerabilities/triage/", data)

    def test_assign_team_to_ticked_findings_is_audited(self):
        response = self.triage(finding=[self.a.pk, self.b.pk], team=self.linux.pk, note="Patch window Friday")
        self.assertRedirects(response, "/vulnerabilities/", fetch_redirect_response=False)
        self.assertEqual(VulnerabilityFinding.objects.filter(assigned_team=self.linux).count(), 2)
        log = AuditLog.objects.get(action="finding.triaged", entity_id=str(self.a.pk))
        self.assertEqual(log.user, self.analyst)
        self.assertEqual(log.details, {"team": {"from": None, "to": "Linux"}, "note": "Patch window Friday"})

    def test_all_matching_the_filters(self):
        self.triage(scope="all", filters="q=appsrv&status=open", status=Status.RESOLVED)
        self.a.refresh_from_db(), self.c.refresh_from_db()
        self.assertEqual(self.a.status, Status.RESOLVED)
        self.assertIsNotNone(self.a.resolved_at)
        self.assertEqual(self.c.status, Status.NEW)
        self.assertEqual(AuditLog.objects.filter(action="finding.triaged").count(), 2)

    def test_manual_due_date_then_back_to_policy(self):
        self.triage(finding=[self.a.pk], due_mode="date", due_date="2027-01-31")
        self.a.refresh_from_db()
        self.assertEqual((self.a.due_date, self.a.due_date_manual), (date(2027, 1, 31), True))
        self.triage(finding=[self.a.pk], due_mode="policy")
        self.a.refresh_from_db()
        self.assertEqual((self.a.due_date, self.a.due_date_manual), (self.today + timedelta(days=7), False))

    def test_reopening_by_hand_restarts_the_sla_clock(self):
        VulnerabilityFinding.objects.filter(pk=self.a.pk).update(
            status=Status.RESOLVED, resolved_at=timezone.now(), sla_started_at=self.today - timedelta(days=100)
        )
        self.triage(finding=[self.a.pk], status=Status.NEEDS_REVIEW)
        self.a.refresh_from_db()
        self.assertIsNone(self.a.resolved_at)
        self.assertEqual(self.a.due_date, self.today + timedelta(days=7))

    def test_nothing_chosen_or_nothing_ticked_is_refused(self):
        self.triage(finding=[self.a.pk])
        self.triage(team=self.linux.pk)
        self.assertFalse(AuditLog.objects.filter(action="finding.triaged").exists())

    def test_new_cannot_be_set_by_hand(self):
        VulnerabilityFinding.objects.filter(pk=self.a.pk).update(status=Status.STILL_OPEN)
        self.triage(finding=[self.a.pk], status=Status.NEW)
        self.a.refresh_from_db()
        self.assertEqual(self.a.status, Status.STILL_OPEN)

    def test_unchanged_values_write_no_audit(self):
        self.triage(finding=[self.a.pk], team="none")
        self.assertFalse(AuditLog.objects.filter(action="finding.triaged").exists())

    def test_external_redirect_is_ignored(self):
        response = self.triage(finding=[self.a.pk], team=self.linux.pk, next="https://evil.example/")
        self.assertRedirects(response, "/vulnerabilities/", fetch_redirect_response=False)

    def test_bar_and_history_show_to_editors(self):
        self.assertContains(self.client.get("/vulnerabilities/"), "Findings Matching the Filters")
        self.triage(finding=[self.a.pk], status=Status.RESOLVED, note="Fixed by the 2.4.58 upgrade")
        page = self.client.get(f"/hosts/{self.appsrv.pk}/?tab=vulnerabilities")
        self.assertContains(page, "Open Findings of This Host")
        self.assertContains(page, "History (1)")
        self.assertContains(page, "Status: New → Resolved")
        self.assertContains(page, "Fixed by the 2.4.58 upgrade")

    def test_readonly_sees_no_bar_and_cannot_post(self):
        self.client.post("/account/logout/")
        User.objects.create_user("ro", "ro@example.com", PASSWORD, role=User.Role.READONLY)
        self.client.post("/account/login/", {"username": "ro", "password": PASSWORD})
        self.assertNotContains(self.client.get("/vulnerabilities/"), 'id="triage"')
        self.assertEqual(self.triage(finding=[self.a.pk], team=self.linux.pk).status_code, 403)

    def test_admin_shows_triage_fields_read_only(self):
        from .admin import VulnerabilityFindingAdmin

        for field in ("status", "assigned_team", "due_date"):
            self.assertIn(field, VulnerabilityFindingAdmin.readonly_fields)
