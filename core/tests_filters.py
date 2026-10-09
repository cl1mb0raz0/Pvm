"""
The risk filters of the Vulnerabilities list take several values at once
(dropdowns with ticks): Priority, Severity, Qualys, CVSS and Tag.

The same keys serve the Export page, so what a filter means has to be read
once: several ticks keep the findings matching **any** of them.
"""

from decimal import Decimal

from django.test import TestCase

from .models import Cve, Host, Tag, VulnerabilityDefinition, VulnerabilityFinding
from .tests_imports import ImportTestMixin

Severity = VulnerabilityDefinition.Severity


class MultipleValueFilterTests(ImportTestMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.full_import()

    def shown(self, query):
        page = self.client.get(f"/vulnerabilities/?{query}")
        rows = list(page.context["page"].object_list)
        # A filter must never show a finding twice (the tag join would).
        self.assertEqual(len(rows), len({f.pk for f in rows}), "a finding appears more than once")
        self.assertEqual(page.context["page"].paginator.count, len(rows))
        return {f.pk for f in rows}

    def pks(self, **lookup):
        return set(VulnerabilityFinding.objects.filter(**lookup).values_list("pk", flat=True))

    def test_several_severities(self):
        critical = self.pks(vulnerability_definition__severity=Severity.CRITICAL)
        high = self.pks(vulnerability_definition__severity=Severity.HIGH)
        self.assertTrue(critical and high)
        self.assertEqual(self.shown("severity=critical"), critical)
        self.assertEqual(self.shown("severity=critical&severity=high"), critical | high)

    def test_several_qualys_levels(self):
        five = self.pks(vulnerability_definition__qualys_severity=5)
        four = self.pks(vulnerability_definition__qualys_severity=4)
        self.assertTrue(five and four)
        self.assertEqual(self.shown("qualys=5&qualys=4"), five | four)

    def test_several_priority_bands(self):
        from .models import PRIORITY_LEVELS

        bands = {}
        for finding in VulnerabilityFinding.objects.all():
            bands.setdefault(finding.priority_level, set()).add(finding.pk)
        levels = sorted(bands)[:2]
        self.assertEqual(len(levels), 2, "the fixture should land in at least two bands")
        query = "&".join(f"priority={level}" for level in levels)
        self.assertEqual(self.shown(query), bands[levels[0]] | bands[levels[1]])
        self.assertEqual(len(PRIORITY_LEVELS), 4)

    def test_several_cvss_thresholds_including_no_score(self):
        scored = VulnerabilityDefinition.objects.get(qid="150440")
        cve = Cve.objects.create(cve_id="CVE-2099-0001", cvss_score=Decimal("9.8"), cvss_version="3.1")
        scored.cves.add(cve)
        high = self.pks(vulnerability_definition=scored)
        unscored = {
            f.pk
            for f in VulnerabilityFinding.objects.all()
            if not f.vulnerability_definition.cves.filter(cvss_score__isnull=False).exists()
        }
        self.assertEqual(self.shown("cvss=9"), high)
        self.assertEqual(self.shown("cvss=none"), unscored)
        self.assertEqual(self.shown("cvss=9&cvss=none"), high | unscored)

    def test_several_tags_and_no_tag(self):
        hosts = list(Host.objects.order_by("hostname"))
        alpha, finance = Tag.objects.create(name="Alpha"), Tag.objects.create(name="Finance")
        hosts[0].tags.add(alpha)
        hosts[1].tags.add(finance)
        hosts[1].tags.add(alpha)  # a host with two tags must still appear once
        on_das = self.pks(host__tags=alpha)
        on_finance = self.pks(host__tags=finance)
        untagged = self.pks(host__tags__isnull=True)
        self.assertTrue(on_das and on_finance and untagged)

        self.assertEqual(self.shown(f"tag={alpha.pk}"), on_das)
        self.assertEqual(self.shown(f"tag={alpha.pk}&tag={finance.pk}"), on_das | on_finance)
        self.assertEqual(self.shown(f"tag={alpha.pk}&tag=none"), on_das | untagged)
        self.assertEqual(self.shown("tag=none"), untagged)

    def test_filters_combine_as_and_across_fields(self):
        """Several ticks widen one filter; different filters still narrow each other."""
        critical = self.pks(vulnerability_definition__severity=Severity.CRITICAL)
        host = VulnerabilityFinding.objects.get(pk=next(iter(critical))).host
        self.assertEqual(
            self.shown(f"severity=critical&severity=high&host={host.pk}"),
            self.pks(host=host, vulnerability_definition__severity__in=[Severity.CRITICAL, Severity.HIGH]),
        )

    def test_the_page_shows_the_ticks_and_what_is_chosen(self):
        page = self.client.get("/vulnerabilities/?severity=critical&severity=high&priority=3")
        body = page.content.decode()
        self.assertIn('<input type="checkbox" name="severity" value="critical" checked>', body)
        self.assertIn('<input type="checkbox" name="severity" value="high" checked>', body)
        self.assertIn('<input type="checkbox" name="severity" value="medium">', body)
        self.assertIn("2 Selected", body)  # the Severity summary
        self.assertIn("P3 Planned", body)  # the Priority summary, one ticked
        self.assertIn('name="cvss"', body)
        self.assertIn('name="tag"', body)

    def test_an_unknown_value_is_ignored(self):
        everything = self.shown("")
        self.assertEqual(self.shown("priority=9&cvss=nope&tag=abc"), everything)
