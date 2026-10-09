"""
Package inventory read over SSH ("Ask Server").

PVM connects with its own key to a dedicated, unprivileged account on the
host, runs one read-only command and stores what it prints: the Ubuntu
release, the running kernel and every installed package (dpkg-query needs
no root). The result feeds the same InstalledPackage rows as a list pasted
from the sysadmin's email, and the Ubuntu tracker check re-runs on it.
Verdicts still need an analyst's "Confirm": nothing is resolved here.

Security, in layers:

- the sysadmins restrict PVM's public key in authorized_keys to one forced
  command (the script below) and to PVM's address, with no shell, pty or
  forwarding: a stolen key can only read the package list
- the private key is stored encrypted with PVM_SSH_KEY_SECRET (.env), so a
  database backup alone does not give it away
- host keys are pinned: the first contact only records the server's key,
  an admin confirms its fingerprint, and any other key is refused
- every connection and key change is written to the audit log
"""

import base64
import hashlib
import io
import logging
import socket

import paramiko
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from django.conf import settings

from . import inventory
from .models import Host, SshKey

logger = logging.getLogger(__name__)

# The account PVM expects on each host sends this command; with a forced
# command in authorized_keys the server runs its own copy regardless.
REMOTE_COMMAND = "/usr/local/bin/pvm-inventory"
CONNECT_TIMEOUT_SECONDS = 15
COMMAND_TIMEOUT_SECONDS = 120
MAX_OUTPUT_BYTES = 20 * 1024 * 1024

# Given to the sysadmins, installed as /usr/local/bin/pvm-inventory
# (root-owned, mode 755). Read-only; prints three marked sections.
INVENTORY_SCRIPT = r"""#!/bin/sh
# PVM package inventory: read-only, runs as an unprivileged user.
# Prints the OS release, the running kernel and the installed packages.
echo "### os-release"
cat /etc/os-release
echo "### kernel"
uname -r
echo "### packages"
dpkg-query -W -f='${binary:Package}\t${Version}\t${source:Package}\t${source:Version}\n'
"""

AUTHORIZED_KEYS_OPTIONS = 'command="{command}",{source}no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding'


class SshError(Exception):
    """Anything that stops an inventory run; the message is shown to the user."""


class HostKeyUnknown(SshError):
    def __init__(self, key):
        super().__init__("The Server's Host Key Is Not Confirmed Yet.")
        self.key = key


class HostKeyMismatch(SshError):
    def __init__(self, key):
        super().__init__(f"Host Key Changed: The Server Now Presents {fingerprint(key)}. Connection Refused.")
        self.key = key


# --- PVM's key ----------------------------------------------------------


def secret_configured():
    return bool(settings.SSH_KEY_SECRET)


def _fernet():
    if not secret_configured():
        raise SshError("PVM_SSH_KEY_SECRET Is Not Set in .env: the SSH Key Cannot Be Stored or Used.")
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(settings.SSH_KEY_SECRET.encode()).digest()))


def fingerprint(public_key):
    """"ssh-ed25519 AAAA..." -> "SHA256:...", as ssh-keygen -l prints it."""
    blob = base64.b64decode(public_key.split()[1])
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def _save(private_key, origin, user):
    """Store `private_key` (a cryptography key object) as PVM's only key."""
    if isinstance(private_key, rsa.RSAPrivateKey) and private_key.key_size < 2048:
        raise SshError("RSA Keys Shorter Than 2048 Bits Are Not Accepted.")
    if not isinstance(private_key, (ed25519.Ed25519PrivateKey, rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
        raise SshError("Unsupported Key Type: Use Ed25519 (Recommended), ECDSA or RSA.")
    pem = private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()
    )
    public = private_key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
    encrypted = _fernet().encrypt(pem).decode()
    SshKey.objects.all().delete()
    return SshKey.objects.create(
        key_type=public.split()[0],
        public_key=f"{public} pvm",
        fingerprint=fingerprint(public),
        private_key_encrypted=encrypted,
        origin=origin,
        created_by=user,
    )


def generate_key(user):
    """A new Ed25519 key replacing the current one."""
    return _save(ed25519.Ed25519PrivateKey.generate(), SshKey.Origin.GENERATED, user)


def upload_key(text, passphrase, user):
    """An existing private key (OpenSSH or PEM, optionally passphrase-protected) replacing the current one."""
    data = text.strip().encode()
    password = passphrase.encode() if passphrase else None
    loaders = (serialization.load_ssh_private_key, serialization.load_pem_private_key)
    for load in loaders:
        try:
            private_key = load(data, password=password)
            break
        except TypeError as exc:  # encrypted without a passphrase, or the reverse
            raise SshError("The Key Is Protected by a Passphrase: Enter It." if not password else "This Key Has No Passphrase: Leave It Empty.") from exc
        except ValueError:
            continue
    else:
        raise SshError("Not a Readable Private Key, or Wrong Passphrase.")
    return _save(private_key, SshKey.Origin.UPLOADED, user)


def current_key():
    return SshKey.objects.first()


def _paramiko_key(ssh_key):
    try:
        pem = _fernet().decrypt(ssh_key.private_key_encrypted.encode()).decode()
    except InvalidToken as exc:
        raise SshError("The Stored Key Cannot Be Decrypted: PVM_SSH_KEY_SECRET Changed. Generate or Upload the Key Again.") from exc
    for cls in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
        try:
            return cls.from_private_key(io.StringIO(pem))
        except (paramiko.SSHException, ValueError):
            continue
    raise SshError("The Stored Key Could Not Be Loaded.")


def authorized_keys_line(ssh_key):
    """The line for the host account's ~/.ssh/authorized_keys, restricted to the inventory command."""
    source = f'from="{settings.SSH_FROM}",' if settings.SSH_FROM else ""
    return AUTHORIZED_KEYS_OPTIONS.format(command=REMOTE_COMMAND, source=source) + " " + ssh_key.public_key


# --- Connecting -----------------------------------------------------------


def not_ready_reason(host):
    """Why "Ask Server" cannot run for `host`, or "" when it can."""
    if not host.ssh_enabled:
        return "SSH Is Not Enabled for This Host."
    if not secret_configured():
        return "PVM_SSH_KEY_SECRET Is Not Set in .env."
    if current_key() is None:
        return "No SSH Key: an Admin Generates or Uploads It in Access (Ssh)."
    return ""


HOST_KEY_FILES = {"ssh-ed25519": "ed25519", "ssh-rsa": "rsa"}


def host_key_file(public_key):
    """The server file holding this host key, for the sysadmin to compare fingerprints."""
    kind = public_key.split()[0]
    name = HOST_KEY_FILES.get(kind, "ecdsa" if kind.startswith("ecdsa") else kind)
    return f"/etc/ssh/ssh_host_{name}_key.pub"


def target(host):
    """(address, port, username) PVM connects to for `host`."""
    address = host.ssh_address or host.private_ip or host.ip_address
    return address, host.ssh_port or 22, host.ssh_username or settings.SSH_DEFAULT_USER


class _PinnedHostKey(paramiko.MissingHostKeyPolicy):
    """Accept only the pinned key; with none pinned, report the offered one and stop."""

    def __init__(self, pinned):
        self.pinned = pinned.strip()

    def missing_host_key(self, client, hostname, key):
        offered = f"{key.get_name()} {key.get_base64()}"
        if not self.pinned:
            raise HostKeyUnknown(offered)
        if offered != self.pinned:
            raise HostKeyMismatch(offered)


def _run(host, command):
    """Output of `command` on `host`, as text."""
    ssh_key = current_key()
    if ssh_key is None:
        raise SshError("No SSH Key: Generate or Upload One in Access (Ssh).")
    pkey = _paramiko_key(ssh_key)
    address, port, username = target(host)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(_PinnedHostKey(host.ssh_host_key))
    try:
        client.connect(
            address,
            port=port,
            username=username,
            pkey=pkey,
            timeout=CONNECT_TIMEOUT_SECONDS,
            banner_timeout=CONNECT_TIMEOUT_SECONDS,
            auth_timeout=CONNECT_TIMEOUT_SECONDS,
            allow_agent=False,
            look_for_keys=False,
        )
        _, stdout, stderr = client.exec_command(command, timeout=COMMAND_TIMEOUT_SECONDS)
        output = stdout.read(MAX_OUTPUT_BYTES + 1)
        if len(output) > MAX_OUTPUT_BYTES:
            raise SshError("The Server's Answer Is Too Large.")
        status = stdout.channel.recv_exit_status()
        if status != 0:
            detail = stderr.read(2000).decode(errors="replace").strip()
            raise SshError(f"The Inventory Command Failed (Exit {status}){': ' + detail if detail else ''}.")
        return output.decode(errors="replace")
    except SshError:
        raise
    except paramiko.AuthenticationException as exc:
        raise SshError(f"Authentication Refused for {username}@{address}: Is Pvm's Public Key Installed?") from exc
    except paramiko.ssh_exception.NoValidConnectionsError as exc:
        raise SshError(f"Cannot Connect to {address}:{port}: Connection Refused.") from exc
    except (socket.timeout, TimeoutError) as exc:
        raise SshError(f"Timed Out Connecting to {address}:{port}.") from exc
    except (OSError, paramiko.SSHException) as exc:
        raise SshError(f"Cannot Connect to {address}:{port}: {exc}") from exc
    finally:
        client.close()


def parse_output(text):
    """The script's sections -> {"os": {os-release keys}, "kernel", "entries", "errors"}."""
    sections, current = {}, None
    for line in text.splitlines():
        if line.startswith("### "):
            current = line[4:].strip()
            sections[current] = []
        elif current:
            sections[current].append(line)
    if "packages" not in sections:
        raise SshError("Unexpected Answer: Is /usr/local/bin/pvm-inventory the Script Pvm Provides?")
    os_release = {}
    for line in sections.get("os-release", []):
        key, sep, value = line.partition("=")
        if sep:
            os_release[key.strip()] = value.strip().strip('"')
    _, entries, errors = inventory.parse("\n".join(sections["packages"]))
    kernel = next((l.strip() for l in sections.get("kernel", []) if l.strip()), "")
    return {"os": os_release, "kernel": kernel, "entries": entries, "errors": errors}


def collect(host):
    """Connect to `host`, read and parse its inventory. Raises SshError."""
    return parse_output(_run(host, REMOTE_COMMAND))


def ubuntu_release(os_release):
    """The Host.UbuntuRelease value for an os-release dict, or "" when not a supported Ubuntu."""
    if os_release.get("ID") != "ubuntu":
        return ""
    codename = os_release.get("VERSION_CODENAME") or os_release.get("UBUNTU_CODENAME") or ""
    return codename if codename in Host.UbuntuRelease.values else ""
