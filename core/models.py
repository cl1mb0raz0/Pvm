from django.conf import settings
from django.db import models
from django.db.models.functions import Lower


class Perimeter(models.Model):
    """
    Where a scan looks from: "Internal" (the Qualys scanner appliance inside
    the network) or "External" (Qualys scanning from the internet), plus any
    other an admin adds. The same host can be scanned from several
    perimeters and each sees different things, so findings are tracked per
    perimeter and an import only resolves findings of its own perimeter.
    """

    name = models.CharField(max_length=50, unique=True)
    slug = models.SlugField(max_length=50, unique=True)
    description = models.CharField(max_length=255, blank=True)
    # Findings seen from here are reachable from the internet.
    internet_facing = models.BooleanField(default=False)

    class Meta:
        ordering = ["internet_facing", "name"]

    def __str__(self):
        return self.name


class Tag(models.Model):
    """
    A label for an area or group of assets (e.g. "Alpha"), not exclusive: a
    host can carry several. Applied to every host of an import, or by hand.
    """

    name = models.CharField(max_length=64)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["name"]
        constraints = [models.UniqueConstraint(Lower("name"), name="unique_tag_name_ci")]

    def __str__(self):
        return self.name


class Host(models.Model):
    """A scanned asset, identified by its Qualys host ID."""

    # Ubuntu releases the security tracker knows, newest first.
    class UbuntuRelease(models.TextChoices):
        RESOLUTE = "resolute", "Ubuntu 26.04 LTS (resolute)"
        QUESTING = "questing", "Ubuntu 25.10 (questing)"
        PLUCKY = "plucky", "Ubuntu 25.04 (plucky)"
        NOBLE = "noble", "Ubuntu 24.04 LTS (noble)"
        JAMMY = "jammy", "Ubuntu 22.04 LTS (jammy)"
        FOCAL = "focal", "Ubuntu 20.04 LTS (focal)"
        BIONIC = "bionic", "Ubuntu 18.04 LTS (bionic)"
        XENIAL = "xenial", "Ubuntu 16.04 LTS (xenial)"
        TRUSTY = "trusty", "Ubuntu 14.04 LTS (trusty)"

    # Rocky Linux major releases: Rocky's own errata (core.rocky) tracks
    # fixes per major version, not per point release.
    class RockyRelease(models.TextChoices):
        ROCKY10 = "10", "Rocky Linux 10"
        ROCKY9 = "9", "Rocky Linux 9"
        ROCKY8 = "8", "Rocky Linux 8"

    class Environment(models.TextChoices):
        PRODUCTION = "production", "Production"
        STAGING = "staging", "Staging"
        DEV = "dev", "Development"

    # Not every Qualys export carries the host ID (the scan-report CSV does
    # not); without it a host is identified by IP address plus hostname,
    # since one IP can front many virtual hosts.
    qualys_host_id = models.CharField(max_length=64, unique=True, null=True, blank=True)
    hostname = models.CharField(max_length=255)
    ip_address = models.GenericIPAddressField()
    # The internal address of the server that actually hosts this site, e.g.
    # behind a load balancer: by hand, or from Imports > Mapping (a CSV, a
    # balancer's configuration). When a pool has several servers this is the
    # first one, the others are HostPrivateIp rows (see all_private_ips).
    private_ip = models.GenericIPAddressField(null=True, blank=True)
    os_name = models.CharField(max_length=255, blank=True)
    os_version = models.CharField(
        max_length=100, blank=True, help_text="Distro and Release, e.g. 'Ubuntu 20.04'"
    )
    environment = models.CharField(
        max_length=16, choices=Environment.choices, default=Environment.PRODUCTION
    )
    first_seen_at = models.DateTimeField(auto_now_add=True)
    last_scanned_at = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    # Set by hand (or later by an automatic inventory source); required for
    # checking findings against the Ubuntu security tracker.
    ubuntu_release = models.CharField(max_length=16, choices=UbuntuRelease.choices, blank=True)
    # Same, for a Rocky Linux host (core.rocky_check); a host is one or the
    # other, never both, so they share the check-progress fields below.
    rocky_release = models.CharField(max_length=8, choices=RockyRelease.choices, blank=True)
    # State of the last "check against the Ubuntu tracker" run (core.patchcheck),
    # or the Rocky errata (core.rocky_check) - whichever applies to this host.
    patch_check_state = models.CharField(max_length=16, blank=True, help_text="running, done or failed")
    patch_checked_at = models.DateTimeField(null=True, blank=True)
    patch_check_error = models.CharField(max_length=255, blank=True)
    # While a check runs: tracker records fetched so far, out of how many.
    patch_check_done = models.PositiveIntegerField(default=0)
    patch_check_total = models.PositiveIntegerField(default=0)
    # Package inventory read over SSH (core/ssh.py). The address defaults to
    # the private IP, else the scanned IP; the user to settings.SSH_DEFAULT_USER.
    ssh_enabled = models.BooleanField(default=False)
    ssh_address = models.CharField(max_length=255, blank=True)
    ssh_port = models.PositiveIntegerField(default=22)
    ssh_username = models.CharField(max_length=64, blank=True)
    # The server's host key ("ssh-ed25519 AAAA..."), pinned once an admin
    # confirmed its fingerprint; a different key is refused.
    ssh_host_key = models.TextField(blank=True)
    ssh_pending_host_key = models.TextField(blank=True)
    ssh_state = models.CharField(max_length=16, blank=True, help_text="running, done, failed or host_key")
    ssh_error = models.CharField(max_length=255, blank=True)
    ssh_checked_at = models.DateTimeField(null=True, blank=True)
    running_kernel = models.CharField(max_length=128, blank=True)
    tags = models.ManyToManyField(Tag, blank=True, related_name="hosts")

    class Meta:
        ordering = ["hostname"]

    def __str__(self):
        return self.hostname

    @property
    def is_windows(self):
        """True when the recorded OS (from Qualys Csam or by hand) is some Windows."""
        return "windows" in (self.os_version or self.os_name or "").lower()

    @property
    def is_rocky(self):
        """True when the recorded OS (from Qualys Csam or a scan) is some Rocky Linux."""
        return "rocky linux" in (self.os_version or self.os_name or "").lower()

    @property
    def all_private_ips(self):
        """The private IP first, then the other servers of the same pool."""
        if not self.private_ip:
            return []
        if self.pk is None:
            return [self.private_ip]
        return [self.private_ip] + [p.ip_address for p in self.other_private_ips.all()]

    def set_private_ips(self, ips):
        """Replace every private IP of the host (saved); `ips` in order, duplicates dropped."""
        ips = list(dict.fromkeys(ip for ip in ips if ip))
        self.private_ip = ips[0] if ips else None
        self.save(update_fields=["private_ip"])
        self.other_private_ips.all().delete()
        HostPrivateIp.objects.bulk_create(
            HostPrivateIp(host=self, ip_address=ip, position=i) for i, ip in enumerate(ips[1:], start=1)
        )


class HostPrivateIp(models.Model):
    """A private IP of a host after the first (Host.private_ip): the other servers of its pool."""

    host = models.ForeignKey(Host, on_delete=models.CASCADE, related_name="other_private_ips")
    ip_address = models.GenericIPAddressField()
    position = models.PositiveIntegerField(default=1)

    class Meta:
        ordering = ["host", "position"]
        constraints = [models.UniqueConstraint(fields=["host", "ip_address"], name="unique_host_private_ip")]

    def __str__(self):
        return f"{self.host} -> {self.ip_address}"


class PrivateIpMapping(models.Model):
    """
    "The site published as <hostname> on <public IP> runs on <private IP>",
    uploaded from a CSV (Imports > Mapping, core/network_mapping.py).
    Applied to the matching hosts at upload, and to hosts that appear later
    in an import (core/importers/pipeline.py) if they have no private IP.
    An empty hostname stands for every host on that public IP.
    """

    public_ip = models.GenericIPAddressField()
    hostname = models.CharField(max_length=255, blank=True)
    private_ip = models.GenericIPAddressField()
    uploaded_at = models.DateTimeField(auto_now=True)
    uploaded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )

    class Meta:
        ordering = ["public_ip", "hostname"]
        constraints = [models.UniqueConstraint(fields=["public_ip", "hostname"], name="unique_private_ip_mapping")]

    def __str__(self):
        return f"{self.hostname or '*'} @ {self.public_ip} -> {self.private_ip}"


class BalancerConfig(models.Model):
    """
    A load balancer's configuration read from its file (Imports > Mapping,
    core/balancer.py): only what leads from a VIP or a site name to the real
    servers is kept (BalancerRoute), never the file. Uploading the same
    balancer again replaces it.
    """

    name = models.CharField(max_length=100, unique=True, help_text="e.g. A10, or A10 plus the device's host name")
    product = models.CharField(max_length=100, blank=True, help_text="e.g. A10 ACOS 4.1.4-GR1-P9")
    # {server IP: its name on the balancer, e.g. "10.0.5.20": "app-srv-05"}.
    servers = models.JSONField(default=dict, blank=True)
    filename = models.CharField(max_length=255, blank=True)
    counts = models.JSONField(default=dict, blank=True)
    uploaded_at = models.DateTimeField(auto_now=True)
    uploaded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name


class BalancerRoute(models.Model):
    """
    One way traffic reaches real servers: a VIP port and its pool, or a
    host-switching rule (site names matching `pattern`) and its pool. A rule
    from a template no VIP uses has no VIP.
    """

    class Match(models.TextChoices):
        ANY = "", "Any Name"
        EQUALS = "equals", "Equals"
        STARTS_WITH = "starts-with", "Starts With"
        ENDS_WITH = "ends-with", "Ends With"
        CONTAINS = "contains", "Contains"
        REGEX = "regex-match", "Regex"

    config = models.ForeignKey(BalancerConfig, on_delete=models.CASCADE, related_name="routes")
    vip_name = models.CharField(max_length=255, blank=True)
    vip_ip = models.GenericIPAddressField(null=True, blank=True)
    port = models.CharField(max_length=32, blank=True, help_text="e.g. 443/https")
    match = models.CharField(max_length=16, choices=Match.choices, blank=True)
    pattern = models.CharField(max_length=255, blank=True)
    service_group = models.CharField(max_length=255)
    backend_ips = models.JSONField(default=list)

    class Meta:
        ordering = ["config", "vip_ip", "port", "pattern"]

    def __str__(self):
        rule = f"{self.match} {self.pattern} " if self.pattern else ""
        return f"{self.vip_name or '(no VIP)'} {self.port} {rule}-> {self.service_group}"


class LoadBalancer(models.Model):
    """
    An IP address known to be a load balancer (e.g. the A10 VIP). Marked by
    hand; every host scanned on that address is shown as behind it.
    """

    ip_address = models.GenericIPAddressField(unique=True)
    name = models.CharField(max_length=100, default="Load balancer")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["ip_address"]

    def __str__(self):
        return f"{self.name} ({self.ip_address})"


class InstalledPackage(models.Model):
    """
    A software package installed on a host, with its full version string
    (including distro revision). Used to check whether a vulnerability
    flagged from the upstream version was already patched by the distro.
    """

    class Source(models.TextChoices):
        MANUAL = "manual", "Manual Entry"
        PASTED = "pasted", "Pasted List"
        IMPORT = "import", "Scan Import"
        QUALYS_AGENT = "qualys_agent", "Qualys Cloud Agent"
        SSH = "ssh", "Read over SSH"

    host = models.ForeignKey(Host, on_delete=models.CASCADE, related_name="packages")
    # Binary package name, as dpkg lists it (e.g. openssh-server).
    package_name = models.CharField(max_length=255)
    installed_version = models.CharField(
        max_length=255, help_text="Full Version String, Including Distro Revision"
    )
    # The Ubuntu tracker lists source packages (openssh, not openssh-server).
    # Known when the list came from dpkg-query; otherwise matched by name.
    source_package = models.CharField(max_length=255, blank=True)
    source_version = models.CharField(max_length=255, blank=True)
    source = models.CharField(max_length=16, choices=Source.choices, default=Source.IMPORT)
    detected_at = models.DateTimeField()
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["host", "package_name"], name="unique_package_per_host")
        ]
        ordering = ["host", "package_name"]

    def __str__(self):
        return f"{self.package_name} ({self.installed_version}) on {self.host}"

    @property
    def version_for_tracker(self):
        """The tracker's fixed versions are source versions."""
        return self.source_version or self.installed_version


class Cve(models.Model):
    """
    A single CVE identifier, shared across vulnerability definitions, with
    its CVSS score as published by NVD (filled in by core.nvd, never by the
    scanner report).
    """

    class NvdStatus(models.TextChoices):
        PENDING = "pending", "Not Fetched Yet"
        OK = "ok", "Fetched"
        NOT_FOUND = "not_found", "Not in NVD"
        ERROR = "error", "Fetch Failed"

    cve_id = models.CharField(max_length=32, unique=True, help_text="e.g. CVE-2024-3094")
    cvss_score = models.DecimalField(max_digits=3, decimal_places=1, null=True, blank=True)
    cvss_version = models.CharField(max_length=8, blank=True, help_text="e.g. 3.1")
    cvss_severity = models.CharField(max_length=16, blank=True, help_text="NVD Rating, e.g. CRITICAL")
    cvss_vector = models.CharField(max_length=255, blank=True)
    cvss_source = models.CharField(max_length=100, blank=True, help_text="Who Scored It: NVD or the CNA")
    nvd_published_at = models.DateTimeField(null=True, blank=True)
    nvd_last_modified_at = models.DateTimeField(null=True, blank=True)
    nvd_status = models.CharField(max_length=16, choices=NvdStatus.choices, default=NvdStatus.PENDING)
    nvd_fetched_at = models.DateTimeField(null=True, blank=True)
    nvd_error = models.CharField(max_length=255, blank=True)
    # From the Ubuntu security tracker (core.ubuntu): per source package,
    # per release codename: {"status", "fixed" (version), "pocket", "note"}.
    ubuntu_packages = models.JSONField(default=dict, blank=True)
    ubuntu_priority = models.CharField(max_length=16, blank=True)
    ubuntu_status = models.CharField(max_length=16, choices=NvdStatus.choices, default=NvdStatus.PENDING)
    ubuntu_fetched_at = models.DateTimeField(null=True, blank=True)
    ubuntu_error = models.CharField(max_length=255, blank=True)
    # From Rocky Linux's own errata (core.rocky): per RPM package name, per
    # Rocky major release: {"status", "fixed" (version-release), "note"}.
    rocky_packages = models.JSONField(default=dict, blank=True)
    rocky_priority = models.CharField(max_length=16, blank=True)
    rocky_status = models.CharField(max_length=16, choices=NvdStatus.choices, default=NvdStatus.PENDING)
    rocky_fetched_at = models.DateTimeField(null=True, blank=True)
    rocky_error = models.CharField(max_length=255, blank=True)
    # FIRST's EPSS (core/epss.py): probability of exploitation activity in
    # the next 30 days, and its percentile among all CVEs.
    epss_score = models.DecimalField(max_digits=6, decimal_places=5, null=True, blank=True)
    epss_percentile = models.DecimalField(max_digits=6, decimal_places=5, null=True, blank=True)
    epss_date = models.DateField(null=True, blank=True)
    epss_fetched_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["cve_id"]
        verbose_name = "CVE"
        verbose_name_plural = "CVEs"

    def __str__(self):
        return self.cve_id


class KevEntry(models.Model):
    """
    One CVE of the CISA Known Exploited Vulnerabilities catalog: exploited
    in the wild, according to CISA. The whole catalog is mirrored (core.kev,
    refreshed nightly) and matched to PVM's CVEs by ID, so a CVE imported
    after the last refresh is flagged straight away.
    """

    cve_id = models.CharField(max_length=32, unique=True)
    vendor = models.CharField(max_length=200, blank=True)
    product = models.CharField(max_length=200, blank=True)
    name = models.CharField(max_length=500, blank=True)
    short_description = models.TextField(blank=True)
    required_action = models.TextField(blank=True)
    date_added = models.DateField(null=True, blank=True)
    # The remediation deadline CISA sets for US federal agencies: a useful
    # benchmark, not an obligation here.
    due_date = models.DateField(null=True, blank=True)
    ransomware = models.BooleanField(default=False, help_text="Known to Be Used in Ransomware Campaigns")
    notes = models.TextField(blank=True)

    class Meta:
        ordering = ["-date_added"]
        verbose_name = "CISA KEV entry"
        verbose_name_plural = "CISA KEV entries"

    def __str__(self):
        return self.cve_id


class VulnerabilityDefinition(models.Model):
    """The shared catalog entry for a vulnerability (one Qualys QID)."""

    class Severity(models.TextChoices):
        CRITICAL = "critical", "Critical"
        HIGH = "high", "High"
        MEDIUM = "medium", "Medium"
        LOW = "low", "Low"

    class QualysSeverity(models.IntegerChoices):
        URGENT = 5, "5 Urgent"
        CRITICAL = 4, "4 Critical"
        SERIOUS = 3, "3 Serious"
        MEDIUM = 2, "2 Medium"
        MINIMAL = 1, "1 Minimal"

    qid = models.CharField(max_length=32, unique=True, help_text="Qualys QID")
    cves = models.ManyToManyField(Cve, blank=True, related_name="vulnerability_definitions")
    title = models.CharField(max_length=500)
    description = models.TextField(blank=True)
    # PVM's four levels, used for SLA and dashboards; derived from the
    # Qualys level (5 critical, 4 high, 3 medium, 2 and 1 low).
    severity = models.CharField(max_length=16, choices=Severity.choices)
    # The scanner's own 1-5 level, as reported.
    qualys_severity = models.PositiveSmallIntegerField(choices=QualysSeverity.choices, null=True, blank=True)
    # CVSS as given in the scanner report, if that column was imported; the
    # authoritative per-CVE score comes from NVD (Cve.cvss_score).
    cvss_score = models.DecimalField(max_digits=3, decimal_places=1, null=True, blank=True)
    solution_text = models.TextField(blank=True)

    class Meta:
        ordering = ["qid"]

    def __str__(self):
        return f"{self.qid} - {self.title}"

    @property
    def qualys_severity_name(self):
        """'Urgent' for level 5, etc.; empty if unknown."""
        return self.get_qualys_severity_display().split(" ", 1)[1] if self.qualys_severity else ""

    @property
    def nvd_cvss(self):
        """The highest-scored of this definition's CVEs (uses prefetched `cves`)."""
        scored = [c for c in self.cves.all() if c.cvss_score is not None]
        return max(scored, key=lambda c: c.cvss_score, default=None)

    @property
    def top_epss(self):
        """The CVE with the highest EPSS among this definition's CVEs (uses prefetched `cves`)."""
        scored = [c for c in self.cves.all() if c.epss_score is not None]
        return max(scored, key=lambda c: c.epss_score, default=None)


class SLAPolicy(models.Model):
    """Remediation target, in days, per severity level."""

    severity = models.CharField(
        max_length=16, choices=VulnerabilityDefinition.Severity.choices, unique=True
    )
    target_days = models.PositiveIntegerField()

    class Meta:
        verbose_name = "SLA policy"
        verbose_name_plural = "SLA policies"
        ordering = ["severity"]

    def __str__(self):
        return f"{self.get_severity_display()}: {self.target_days}d"


# Risk priority bands (core/priority.py): (level, lowest score, label).
PRIORITY_LEVELS = [(1, 70, "Fix Now"), (2, 50, "Next"), (3, 30, "Planned"), (4, 0, "Backlog")]


class VulnerabilityFinding(models.Model):
    """
    A vulnerability instance on a specific host, persistent across scans.

    The unique constraint on (host, vulnerability_definition, service_port,
    perimeter) is what lets a new scan import update an existing finding instead of
    creating a duplicate, which is how the still-open/resolved history and
    the false-positive review workflow stay accurate over time.
    """

    class Status(models.TextChoices):
        NEW = "new", "New"
        STILL_OPEN = "still_open", "Still Open"
        NEEDS_REVIEW = "needs_review", "Needs Review"
        RESOLVED = "resolved", "Resolved"

    host = models.ForeignKey(Host, on_delete=models.CASCADE, related_name="findings")
    vulnerability_definition = models.ForeignKey(
        VulnerabilityDefinition, on_delete=models.PROTECT, related_name="findings"
    )
    related_package = models.ForeignKey(
        InstalledPackage,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="findings",
    )
    service_port = models.CharField(max_length=32, blank=True, default="")
    perimeter = models.ForeignKey(Perimeter, on_delete=models.PROTECT, related_name="findings")
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.NEW)
    assigned_team = models.ForeignKey(
        "accounts.Team",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="findings",
    )
    due_date = models.DateField(null=True, blank=True)
    # SLA (core/sla.py): the due date follows the policy from this day on,
    # unless it was set by hand.
    sla_started_at = models.DateField(null=True, blank=True)
    due_date_manual = models.BooleanField(default=False)
    # Risk priority, 0-100 (core/priority.py), and the points behind it.
    priority_score = models.PositiveSmallIntegerField(default=0, db_index=True)
    priority_factors = models.JSONField(default=list, blank=True)
    first_detected_at = models.DateTimeField()
    last_detected_at = models.DateTimeField()
    resolved_at = models.DateTimeField(null=True, blank=True)
    # The scanner's evidence for this detection (Qualys "Results"), from
    # the most recent import that saw it.
    detection_result = models.TextField(blank=True)
    # Report columns the user chose to import that have no dedicated field,
    # keyed by column name, from the most recent import that saw it.
    extra_data = models.JSONField(default=dict, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["host", "vulnerability_definition", "service_port", "perimeter"],
                name="unique_finding_per_host_vuln_port_perimeter",
            )
        ]
        ordering = ["-last_detected_at"]

    def __str__(self):
        return f"{self.vulnerability_definition.qid} on {self.host}"

    @property
    def priority_level(self):
        return next(level for level, lowest, _ in PRIORITY_LEVELS if self.priority_score >= lowest)

    @property
    def priority_label(self):
        return next(label for level, _, label in PRIORITY_LEVELS if level == self.priority_level)


class ScanImport(models.Model):
    """One Qualys report import, manual or automatic."""

    class Source(models.TextChoices):
        MANUAL = "manual", "Manual Upload"
        QUALYS = "qualys", "From Qualys"
        API = "api", "Automatic (API)"

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        DOWNLOADING = "downloading", "Downloading"
        PARSING = "parsing", "Parsing"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"

    source = models.CharField(max_length=16, choices=Source.choices)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.PENDING)
    # A name the user gives the import (e.g. "Internal Alpha") to find it in
    # the history; optional, the number and file name identify it otherwise.
    name = models.CharField(max_length=100, blank=True)
    # Chosen by the user before processing; null only while still pending.
    perimeter = models.ForeignKey(
        Perimeter, on_delete=models.PROTECT, null=True, blank=True, related_name="scan_imports"
    )
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    triggered_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="scan_imports",
    )
    raw_file_path = models.CharField(
        max_length=500, blank=True, help_text="Where the Original Report Is Archived, for Re-Processing"
    )
    original_filename = models.CharField(max_length=255, blank=True)
    # When the scan itself ran (entered on upload, or reported by the API);
    # detection timestamps use this, not the import time.
    scanned_at = models.DateTimeField(null=True, blank=True)
    # Hosts covered by this import. Only their findings can be resolved by
    # it, so a partial export never closes findings on other hosts.
    hosts = models.ManyToManyField(Host, blank=True, related_name="scan_imports")
    # Given to every host of the report when it is applied (core/tags.py).
    tags = models.ManyToManyField(Tag, blank=True, related_name="scan_imports")
    # Report column name -> PVM field, as chosen by the user.
    column_mapping = models.JSONField(default=dict, blank=True)
    # File analysis (columns, samples, row counts) and processing results.
    summary = models.JSONField(default=dict, blank=True)
    findings_count = models.PositiveIntegerField(default=0)
    error_message = models.TextField(blank=True)
    # "Stop Import": the Celery task checks this between steps and rolls back
    # (core/tasks.py); task_id lets a queued task be revoked before it starts.
    stop_requested = models.BooleanField(default=False)
    task_id = models.CharField(max_length=64, blank=True)
    # The Qualys scan it came from (core.qualys), e.g. "scan/1790067077.66762":
    # a scan is imported once, whether chosen by hand or by a rule.
    qualys_scan_ref = models.CharField(max_length=64, blank=True, db_index=True)
    rule = models.ForeignKey(
        "QualysImportRule", on_delete=models.SET_NULL, null=True, blank=True, related_name="imports"
    )

    class Meta:
        ordering = ["-started_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["qualys_scan_ref"], condition=~models.Q(qualys_scan_ref=""), name="unique_qualys_scan_import"
            )
        ]

    def __str__(self):
        return f"Import #{self.pk} ({self.get_status_display()})"

    @property
    def label(self):
        """How the import is shown in lists: its name, else its number."""
        return self.name or f"Import #{self.pk}"


class ScanDetectionEvent(models.Model):
    """
    Links a scan import to the findings it detected. A finding with no
    event on the latest import is no longer present and can be resolved.
    """

    scan_import = models.ForeignKey(ScanImport, on_delete=models.CASCADE, related_name="detection_events")
    vulnerability_finding = models.ForeignKey(
        VulnerabilityFinding, on_delete=models.CASCADE, related_name="detection_events"
    )
    detected_at = models.DateTimeField()

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["scan_import", "vulnerability_finding"],
                name="unique_detection_per_scan",
            )
        ]
        ordering = ["-detected_at"]

    def __str__(self):
        return f"Finding #{self.vulnerability_finding_id} in import #{self.scan_import_id}"


class PatchCheck(models.Model):
    """
    The latest automatic check of a finding against its source of patch
    truth (core.patchcheck for Linux, core.qualys_pm for Windows). Advisory
    only: an analyst confirms it, which records a DistroPatchVerification.
    """

    class Verdict(models.TextChoices):
        FIXED = "fixed", "Fixed in the Installed Version"
        NOT_AFFECTED = "not_affected", "Not Affected"
        VULNERABLE_UPDATE = "vulnerable_update", "Vulnerable, Update Available"
        VULNERABLE_PRO = "vulnerable_pro", "Vulnerable, Fix Needs Ubuntu Pro (ESM)"
        VULNERABLE_NO_FIX = "vulnerable_no_fix", "Vulnerable, No Fix Yet"
        UNKNOWN = "unknown", "Cannot Verify"

    class Source(models.TextChoices):
        UBUNTU_TRACKER = "ubuntu_tracker", "Ubuntu Security Tracker"
        QUALYS_PM = "qualys_pm", "Qualys Patch Management"
        ROCKY_TRACKER = "rocky_tracker", "Rocky Linux Errata"

    vulnerability_finding = models.OneToOneField(
        VulnerabilityFinding, on_delete=models.CASCADE, related_name="patch_check"
    )
    verdict = models.CharField(max_length=32, choices=Verdict.choices)
    source = models.CharField(max_length=16, choices=Source.choices, default=Source.UBUNTU_TRACKER)
    # Only meaningful for source=ubuntu_tracker.
    ubuntu_release = models.CharField(max_length=16, blank=True)
    # One entry per CVE: its verdict, the packages (or, for Qualys Patch
    # Management, the patches/KBs) compared and why.
    details = models.JSONField(default=list, blank=True)
    # Installed versions the verdict was based on, by package name; empty
    # for a Qualys Patch Management check (nothing to compare on re-read,
    # the next "Search Qualys Pm" simply recomputes the verdict).
    package_versions = models.JSONField(default=dict, blank=True)
    checked_at = models.DateTimeField()

    def __str__(self):
        return f"{self.get_verdict_display()} for {self.vulnerability_finding}"

    @property
    def is_not_vulnerable(self):
        return self.verdict in {self.Verdict.FIXED, self.Verdict.NOT_AFFECTED}

    @property
    def is_vulnerable(self):
        return self.verdict.startswith("vulnerable")


class DistroPatchVerification(models.Model):
    """
    An analyst's note confirming (or rejecting) that a version-based
    detection is actually covered by a distro backported patch.
    """

    class Verdict(models.TextChoices):
        LIKELY_FALSE_POSITIVE = "likely_false_positive", "Likely False Positive"
        CONFIRMED_VULNERABLE = "confirmed_vulnerable", "Confirmed Vulnerable"
        CONFIRMED_FIXED = "confirmed_fixed", "Confirmed Fixed"

    vulnerability_finding = models.OneToOneField(
        VulnerabilityFinding, on_delete=models.CASCADE, related_name="distro_verification"
    )
    verified_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="distro_verifications",
    )
    verified_at = models.DateTimeField(auto_now_add=True)
    note = models.TextField()
    reference_url = models.URLField(blank=True)
    verdict = models.CharField(max_length=32, choices=Verdict.choices)
    # Which automatic check this came from (see PatchCheck.Source), or
    # ubuntu_tracker (the default) when written by hand.
    source = models.CharField(max_length=16, choices=PatchCheck.Source.choices, default=PatchCheck.Source.UBUNTU_TRACKER)
    # Confirmed from an automatic check (Ubuntu tracker or Qualys Patch
    # Management), or written by hand.
    from_patch_check = models.BooleanField(default=False)
    # Installed versions at verification time: if they change, the
    # verification no longer describes the host.
    package_versions = models.JSONField(default=dict, blank=True)

    def __str__(self):
        return f"Verification for {self.vulnerability_finding}"


class PmSearch(models.Model):
    """
    One "Search Qualys Pm" run (core.qualys_pm): reads Qualys Patch
    Management for PVM's Windows hosts and writes a PatchCheck
    (source=qualys_pm) directly on every relevant finding it can match by
    QID - no approval step, like the Ubuntu tracker check. Only the latest
    run is kept (mirrors CsamSearch).
    """

    class State(models.TextChoices):
        RUNNING = "running", "Searching"
        DONE = "done", "Done"
        FAILED = "failed", "Failed"

    state = models.CharField(max_length=16, choices=State.choices, default=State.RUNNING)
    started_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    started_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )
    windows_hosts = models.PositiveIntegerField(default=0)
    matched = models.PositiveIntegerField(default=0)
    patches_seen = models.PositiveIntegerField(default=0)
    findings_checked = models.PositiveIntegerField(default=0)
    missing_count = models.PositiveIntegerField(default=0)
    fixed_count = models.PositiveIntegerField(default=0)
    unknown_count = models.PositiveIntegerField(default=0)
    api_calls = models.PositiveIntegerField(default=0)
    error = models.TextField(blank=True)

    class Meta:
        ordering = ["-started_at"]


class AuditLog(models.Model):
    """Who did what, for accountability and security audits."""

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name="audit_logs"
    )
    action = models.CharField(max_length=100)
    entity_type = models.CharField(max_length=100)
    entity_id = models.CharField(max_length=64)
    timestamp = models.DateTimeField(auto_now_add=True)
    details = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-timestamp"]
        # Failed sign-ins are counted from here (accounts/throttle.py).
        indexes = [models.Index(fields=["action", "timestamp"], name="auditlog_action_time")]

    def __str__(self):
        return f"{self.action} on {self.entity_type}#{self.entity_id}"


class SshKey(models.Model):
    """
    PVM's SSH client key, at most one: generated in PVM or uploaded. The
    private part is stored encrypted with PVM_SSH_KEY_SECRET (core/ssh.py),
    so a database backup alone does not give it away.
    """

    class Origin(models.TextChoices):
        GENERATED = "generated", "Generated in Pvm"
        UPLOADED = "uploaded", "Uploaded"

    key_type = models.CharField(max_length=32)
    public_key = models.TextField()
    fingerprint = models.CharField(max_length=80)
    private_key_encrypted = models.TextField()
    origin = models.CharField(max_length=16, choices=Origin.choices)
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )

    class Meta:
        verbose_name = "SSH key"

    def __str__(self):
        return f"{self.key_type} {self.fingerprint}"


class QualysImportRule(models.Model):
    """
    "Import this Qualys scan automatically": created by an admin for one
    recurring scan (matched by its exact title). When due, the latest
    finished run of that scan is imported, if not imported yet
    (core.tasks.run_qualys_rules). Times are in settings.SCHEDULE_TIME_ZONE.
    """

    class Frequency(models.TextChoices):
        WEEKLY = "weekly", "Weekly"
        MONTHLY = "monthly", "Monthly"

    class Weekday(models.IntegerChoices):
        MONDAY = 0, "Monday"
        TUESDAY = 1, "Tuesday"
        WEDNESDAY = 2, "Wednesday"
        THURSDAY = 3, "Thursday"
        FRIDAY = 4, "Friday"
        SATURDAY = 5, "Saturday"
        SUNDAY = 6, "Sunday"

    scan_title = models.CharField(max_length=255, unique=True)
    frequency = models.CharField(max_length=16, choices=Frequency.choices, default=Frequency.WEEKLY)
    weekday = models.PositiveSmallIntegerField(choices=Weekday.choices, default=Weekday.MONDAY)
    # 1-28, so every month has it.
    day_of_month = models.PositiveSmallIntegerField(default=1)
    at_time = models.TimeField()
    perimeter = models.ForeignKey(Perimeter, on_delete=models.PROTECT, related_name="qualys_rules")
    tags = models.ManyToManyField(Tag, blank=True, related_name="qualys_rules")
    enabled = models.BooleanField(default=True)
    next_run_at = models.DateTimeField()
    last_run_at = models.DateTimeField(null=True, blank=True)
    last_result = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )

    class Meta:
        ordering = ["scan_title"]

    def __str__(self):
        return f"{self.scan_title} ({self.schedule_label})"

    @property
    def schedule_label(self):
        at = self.at_time.strftime("%H:%M")
        if self.frequency == self.Frequency.WEEKLY:
            return f"Every {self.get_weekday_display()} at {at}"
        return f"Monthly on Day {self.day_of_month} at {at}"


class CsamSearch(models.Model):
    """One "Search Qualys CSAM" (core.csam): its state and counts. Only the latest is kept."""

    class State(models.TextChoices):
        RUNNING = "running", "Searching"
        DONE = "done", "Done"
        FAILED = "failed", "Failed"

    state = models.CharField(max_length=16, choices=State.choices, default=State.RUNNING)
    started_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    started_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )
    assets_seen = models.PositiveIntegerField(default=0)
    hosts_total = models.PositiveIntegerField(default=0)
    matched = models.PositiveIntegerField(default=0)
    api_calls = models.PositiveIntegerField(default=0)
    error = models.TextField(blank=True)

    class Meta:
        ordering = ["-started_at"]


class CsamProposal(models.Model):
    """What CSAM knows about one PVM host, waiting for the user to import it (or not)."""

    search = models.ForeignKey(CsamSearch, on_delete=models.CASCADE, related_name="proposals")
    host = models.ForeignKey(Host, on_delete=models.CASCADE, related_name="csam_proposals")
    asset_id = models.BigIntegerField()
    qualys_host_id = models.CharField(max_length=64, blank=True)
    asset_name = models.CharField(max_length=255, blank=True)
    matched_by = models.CharField(max_length=32)
    os_full = models.CharField(max_length=255, blank=True)
    ubuntu_release = models.CharField(max_length=16, blank=True)
    inventory_source = models.CharField(max_length=32, blank=True)
    agent_checked_in = models.DateTimeField(null=True, blank=True)
    qualys_tags = models.JSONField(default=list, blank=True)
    criticality = models.PositiveSmallIntegerField(null=True, blank=True)
    # [[dpkg name, full version], ...]: from the Cloud Agent, Ubuntu only.
    packages = models.JSONField(default=list, blank=True)
    imported_at = models.DateTimeField(null=True, blank=True)
    imported_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )

    class Meta:
        ordering = ["host__hostname"]

    @property
    def has_agent(self):
        return self.inventory_source == "QAGENT"


class Snapshot(models.Model):
    """
    The state of every finding at one moment, so "how did the vulnerabilities
    look on day X" is later answered from record rather than reconstructed
    (core/history.py explains both paths).

    Written after every completed import and every night. It is deliberately
    a flat copy: a finding's severity, priority, verdict and triage as they
    were, because all of those live in one mutable row the next scan
    overwrites. Only the future is covered: for a date before the first
    snapshot, history.py reconstructs the answer from the scans themselves.
    """

    class Reason(models.TextChoices):
        IMPORT = "import", "After an Import"
        NIGHTLY = "nightly", "Nightly"
        MANUAL = "manual", "On Request"

    taken_at = models.DateTimeField(db_index=True)
    reason = models.CharField(max_length=16, choices=Reason.choices)
    scan_import = models.ForeignKey(
        ScanImport, on_delete=models.SET_NULL, null=True, blank=True, related_name="snapshots"
    )
    findings_total = models.PositiveIntegerField(default=0)
    findings_open = models.PositiveIntegerField(default=0)
    # Counts by severity and by status, for a quick read without the rows.
    counts = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-taken_at"]

    def __str__(self):
        return f"Snapshot of {self.taken_at:%Y-%m-%d %H:%M} ({self.get_reason_display()})"

    @property
    def label(self):
        return f"{self.taken_at:%Y-%m-%d %H:%M}"


class FindingState(models.Model):
    """
    One finding as it stood in one snapshot.

    The team is kept as text, like `Backup.created_by`: renaming or deleting
    a team must not rewrite what a report said last quarter.
    """

    snapshot = models.ForeignKey(Snapshot, on_delete=models.CASCADE, related_name="states")
    finding = models.ForeignKey(VulnerabilityFinding, on_delete=models.CASCADE, related_name="states")
    status = models.CharField(max_length=16)
    severity = models.CharField(max_length=16)
    priority_score = models.PositiveSmallIntegerField(default=0)
    patch_verdict = models.CharField(max_length=32, blank=True)
    team = models.CharField(max_length=100, blank=True)
    due_date = models.DateField(null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["snapshot", "finding"], name="unique_state_per_snapshot"),
        ]
