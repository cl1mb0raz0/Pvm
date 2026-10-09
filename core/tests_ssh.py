from unittest import mock

import paramiko
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from django.test import TestCase, override_settings
from django.utils import timezone

from accounts.models import User

from . import ssh
from .models import AuditLog, Cve, Host, InstalledPackage, PatchCheck, Perimeter, SshKey, VulnerabilityDefinition, VulnerabilityFinding
from .tests_imports import PASSWORD, ImportTestMixin
from .tests_patchcheck import tracker_record

SECRET = "test-secret-for-the-ssh-key-0123456789"
HOST_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
OUTPUT = """### os-release
NAME="Ubuntu"
ID=ubuntu
VERSION_CODENAME=focal
PRETTY_NAME="Ubuntu 20.04.6 LTS"
### kernel
5.4.0-200-generic
### packages
apache2\t2.4.41-4ubuntu3.17\tapache2\t2.4.41-4ubuntu3.17
libc6:amd64\t2.31-0ubuntu9.16\tglibc\t2.31-0ubuntu9.16
"""


@override_settings(SSH_KEY_SECRET=SECRET)
class KeyTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_user("adm", "adm@example.com", PASSWORD, role=User.Role.ADMIN)

    def test_generated_key_is_encrypted_and_usable(self):
        key = ssh.generate_key(self.admin)
        self.assertTrue(key.public_key.startswith("ssh-ed25519 "))
        self.assertTrue(key.fingerprint.startswith("SHA256:"))
        self.assertNotIn("PRIVATE KEY", key.private_key_encrypted)
        self.assertIsInstance(ssh._paramiko_key(key), paramiko.Ed25519Key)
        # A new key replaces the old one.
        ssh.generate_key(self.admin)
        self.assertEqual(SshKey.objects.count(), 1)

    def test_upload_with_passphrase(self):
        private = ed25519.Ed25519PrivateKey.generate()
        text = private.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.BestAvailableEncryption(b"pass phrase")
        ).decode()
        with self.assertRaisesMessage(ssh.SshError, "Protected by a Passphrase"):
            ssh.upload_key(text, "", self.admin)
        with self.assertRaisesMessage(ssh.SshError, "Wrong Passphrase"):
            ssh.upload_key(text, "wrong", self.admin)
        key = ssh.upload_key(text, "pass phrase", self.admin)
        self.assertEqual(key.origin, SshKey.Origin.UPLOADED)
        public = private.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
        self.assertEqual(key.fingerprint, ssh.fingerprint(public))

    def test_upload_rejects_weak_or_invalid_keys(self):
        weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        pem = weak.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()).decode()
        with self.assertRaisesMessage(ssh.SshError, "2048"):
            ssh.upload_key(pem, "", self.admin)
        with self.assertRaisesMessage(ssh.SshError, "Not a Readable Private Key"):
            ssh.upload_key("hello", "", self.admin)

    def test_changed_secret_is_reported(self):
        key = ssh.generate_key(self.admin)
        with override_settings(SSH_KEY_SECRET="another-secret"), self.assertRaisesMessage(ssh.SshError, "Changed"):
            ssh._paramiko_key(key)

    @override_settings(SSH_KEY_SECRET="")
    def test_no_secret_no_key(self):
        with self.assertRaisesMessage(ssh.SshError, "PVM_SSH_KEY_SECRET"):
            ssh.generate_key(self.admin)

    @override_settings(SSH_FROM="192.0.2.5")
    def test_authorized_keys_line_is_restricted(self):
        line = ssh.authorized_keys_line(ssh.generate_key(self.admin))
        self.assertTrue(line.startswith('command="/usr/local/bin/pvm-inventory",from="192.0.2.5",no-pty,no-port-forwarding'))


class ParseAndPolicyTests(TestCase):
    def test_parse_output(self):
        result = ssh.parse_output(OUTPUT)
        self.assertEqual(ssh.ubuntu_release(result["os"]), "focal")
        self.assertEqual(result["kernel"], "5.4.0-200-generic")
        self.assertEqual([(e.name, e.source) for e in result["entries"]], [("apache2", "apache2"), ("libc6", "glibc")])

    def test_unexpected_output(self):
        with self.assertRaisesMessage(ssh.SshError, "Unexpected Answer"):
            ssh.parse_output("Welcome to the server\n$ ")

    def test_non_ubuntu(self):
        self.assertEqual(ssh.ubuntu_release({"ID": "debian", "VERSION_CODENAME": "bookworm"}), "")

    def test_host_key_policy(self):
        key = mock.Mock(**{"get_name.return_value": "ssh-ed25519", "get_base64.return_value": HOST_KEY.split()[1]})
        with self.assertRaises(ssh.HostKeyUnknown) as unknown:
            ssh._PinnedHostKey("").missing_host_key(None, "h", key)
        self.assertEqual(unknown.exception.key, HOST_KEY)
        ssh._PinnedHostKey(HOST_KEY).missing_host_key(None, "h", key)  # accepted
        with self.assertRaises(ssh.HostKeyMismatch):
            ssh._PinnedHostKey("ssh-ed25519 AAAAotherkey").missing_host_key(None, "h", key)

    def test_target_defaults(self):
        host = Host(hostname="appsrv", ip_address="198.51.100.9", private_ip="10.0.0.9")
        self.assertEqual(ssh.target(host), ("10.0.0.9", 22, "pvm-inventory"))
        host.ssh_address, host.ssh_port, host.ssh_username = "appsrv.example.test", 2222, "inv"
        self.assertEqual(ssh.target(host), ("appsrv.example.test", 2222, "inv"))


class AskServerFlowTests(ImportTestMixin, TestCase):
    """Admin enables SSH, confirms the host key, the inventory arrives; the finding still needs a Confirm."""

    def setUp(self):
        super().setUp()
        # After the mixin's own overrides, which turn the tracker off.
        override = override_settings(SSH_KEY_SECRET=SECRET, UBUNTU_TRACKER_ENABLED=True)
        override.enable()
        self.addCleanup(override.disable)
        self.admin = User.objects.create_user("adm", "adm@example.com", PASSWORD, role=User.Role.ADMIN)
        self.client.post("/account/logout/")
        self._login_verified(self.admin)
        self.host = Host.objects.create(hostname="appsrv", ip_address="198.51.100.9", private_ip="10.0.0.9")
        definition = VulnerabilityDefinition.objects.create(qid="150495", title="Apache Path Traversal", severity="high", qualys_severity=4)
        definition.cves.add(Cve.objects.create(cve_id="CVE-2021-44790"))
        self.finding = VulnerabilityFinding.objects.create(
            host=self.host, vulnerability_definition=definition, perimeter=Perimeter.objects.get(slug="internal"),
            first_detected_at=timezone.now(), last_detected_at=timezone.now(),
        )
        for target, kwargs in [("core.ubuntu.fetch", {"side_effect": tracker_record}), ("core.ubuntu.time.sleep", {})]:
            patcher = mock.patch(target, **kwargs)
            patcher.start()
            self.addCleanup(patcher.stop)

    def post(self, url, data=None):
        with self.captureOnCommitCallbacks(execute=True):
            return self.client.post(url, data or {})

    def test_full_flow(self):
        base = f"/hosts/{self.host.pk}/ssh"
        self.post("/ssh/key/generate/")
        self.assertContains(self.client.get("/ssh/"), "authorized_keys")
        self.post(f"{base}/", {"ssh_enabled": "1", "ssh_port": "22"})

        # First contact: the server's key is only recorded.
        with mock.patch("core.ssh._run", side_effect=ssh.HostKeyUnknown(HOST_KEY)):
            self.post(f"{base}/ask/")
        self.host.refresh_from_db()
        self.assertEqual((self.host.ssh_state, self.host.ssh_pending_host_key), ("host_key", HOST_KEY))
        page = self.client.get(f"/hosts/{self.host.pk}/?tab=packages")
        self.assertContains(page, ssh.fingerprint(HOST_KEY))
        self.assertContains(page, "ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub")

        # The admin confirms it: the inventory is read and checked.
        with mock.patch("core.ssh._run", return_value=OUTPUT) as run:
            self.post(f"{base}/trust/", {"host_key": HOST_KEY})
        self.assertEqual(run.call_args[0][1], ssh.REMOTE_COMMAND)
        self.host.refresh_from_db()
        self.assertEqual((self.host.ssh_host_key, self.host.ssh_state), (HOST_KEY, "done"))
        self.assertEqual((self.host.ubuntu_release, self.host.running_kernel), ("focal", "5.4.0-200-generic"))
        self.assertEqual(set(self.host.packages.values_list("source", flat=True)), {InstalledPackage.Source.SSH})
        check = PatchCheck.objects.get(vulnerability_finding=self.finding)
        self.assertIn(check.verdict, ("fixed", "not_affected"))
        # Manual closing: still open until an analyst confirms.
        self.finding.refresh_from_db()
        self.assertEqual(self.finding.status, VulnerabilityFinding.Status.NEW)
        self.assertTrue(AuditLog.objects.filter(action="inventory.ssh", entity_id=str(self.host.pk)).exists())

    def test_trust_needs_the_same_pending_key(self):
        Host.objects.filter(pk=self.host.pk).update(ssh_enabled=True, ssh_pending_host_key=HOST_KEY, ssh_state="host_key")
        self.post(f"/hosts/{self.host.pk}/ssh/trust/", {"host_key": "ssh-ed25519 AAAAsomethingelse"})
        self.host.refresh_from_db()
        self.assertEqual(self.host.ssh_host_key, "")

    def test_changing_the_address_forgets_the_host_key(self):
        Host.objects.filter(pk=self.host.pk).update(ssh_enabled=True, ssh_host_key=HOST_KEY)
        self.post(f"/hosts/{self.host.pk}/ssh/", {"ssh_enabled": "1", "ssh_address": "10.0.0.10", "ssh_port": "22"})
        self.host.refresh_from_db()
        self.assertEqual(self.host.ssh_host_key, "")

    def test_invalid_settings_are_refused(self):
        for data in ({"ssh_address": "bad host;rm", "ssh_port": "22"}, {"ssh_port": "70000"}, {"ssh_port": "22", "ssh_username": "Root User"}):
            self.post(f"/hosts/{self.host.pk}/ssh/", {"ssh_enabled": "1", **data})
        self.host.refresh_from_db()
        self.assertFalse(self.host.ssh_enabled)

    def test_failure_is_shown_and_audited(self):
        ssh.generate_key(self.admin)
        Host.objects.filter(pk=self.host.pk).update(ssh_enabled=True, ssh_host_key=HOST_KEY)
        with mock.patch("core.ssh._run", side_effect=ssh.SshError("Authentication Refused for pvm-inventory@10.0.0.9: Is Pvm's Public Key Installed?")):
            self.post(f"/hosts/{self.host.pk}/ssh/ask/")
        self.host.refresh_from_db()
        self.assertEqual(self.host.ssh_state, "failed")
        self.assertContains(self.client.get(f"/hosts/{self.host.pk}/?tab=packages"), "Authentication Refused")
        self.assertTrue(AuditLog.objects.filter(action="inventory.ssh_failed").exists())

    def test_analyst_can_ask_but_not_manage(self):
        ssh.generate_key(self.admin)
        Host.objects.filter(pk=self.host.pk).update(ssh_enabled=True, ssh_host_key=HOST_KEY)
        self.client.post("/account/logout/")
        self._login_verified(User.objects.get(username="ana"))
        self.assertEqual(self.client.get("/ssh/").status_code, 403)
        self.assertEqual(self.client.post("/ssh/key/generate/").status_code, 403)
        self.assertEqual(self.client.post(f"/hosts/{self.host.pk}/ssh/", {"ssh_port": "22"}).status_code, 403)
        with mock.patch("core.ssh._run", return_value=OUTPUT):
            self.assertEqual(self.post(f"/hosts/{self.host.pk}/ssh/ask/").status_code, 302)
        self.host.refresh_from_db()
        self.assertEqual(self.host.ssh_state, "done")

    def test_readonly_cannot_ask(self):
        self.client.post("/account/logout/")
        User.objects.create_user("ro", "ro@example.com", PASSWORD, role=User.Role.READONLY)
        self.client.post("/account/login/", {"username": "ro", "password": PASSWORD})
        self.assertEqual(self.client.post(f"/hosts/{self.host.pk}/ssh/ask/").status_code, 403)
