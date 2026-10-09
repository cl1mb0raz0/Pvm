"""
SSH access (core.ssh): PVM's key and each host's connection, admins only;
"Ask Server", any editor. See core/ssh.py for the security model.
"""

import ipaddress
import re

from django.conf import settings
from django.contrib import messages
from django.db import transaction
from django.db.models import F
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.http import require_POST

from accounts.permissions import can_manage_settings, editor_required, require

from . import audit, ssh
from .models import Host
from .sorting import sorting

admin_required = require(can_manage_settings)
HOSTNAME = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,253}[A-Za-z0-9])?$")


def _packages_tab(host):
    return redirect(reverse("core:host_detail", args=[host.pk]) + "?tab=packages")


# Hosts reachable over SSH: (query key, header, sorted field, first click, numeric).
SSH_COLUMNS = [
    ("host", "Host", "hostname", "asc", False),
    ("address", "Connects To", "ssh_address", "asc", False),
    ("key", "Host Key", "ssh_host_key", "asc", False),
    ("checked", "Last Ask", "ssh_checked_at", "desc", False),
    ("result", "Result", "ssh_error", "asc", False),
]


@admin_required
def settings_page(request):
    key = ssh.current_key()
    field, direction, sort, headers = sorting(request, SSH_COLUMNS, "host")
    column = F(field).asc(nulls_last=True) if direction == "asc" else F(field).desc(nulls_last=True)
    hosts = Host.objects.filter(ssh_enabled=True).order_by(column, "hostname")
    return render(
        request,
        "core/ssh_access.html",
        {
            "key": key,
            "secret_configured": ssh.secret_configured(),
            "authorized_keys_line": ssh.authorized_keys_line(key) if key else "",
            "script": ssh.INVENTORY_SCRIPT,
            "remote_command": ssh.REMOTE_COMMAND,
            "default_user": settings.SSH_DEFAULT_USER,
            "ssh_from": settings.SSH_FROM,
            "hosts": hosts,
            "headers": headers,
            "sort": sort,
            "dir": direction,
        },
    )


@admin_required
@require_POST
def generate_key(request):
    replacing = ssh.current_key()
    try:
        key = ssh.generate_key(request.user)
    except ssh.SshError as exc:
        messages.error(request, str(exc))
        return redirect("core:ssh_access")
    audit.log(request.user, "ssh.key_generated", key, fingerprint=key.fingerprint, replaced=replacing.fingerprint if replacing else None)
    messages.success(request, f"New {key.key_type} Key Generated: Give the Public Key to the Sysadmins.")
    return redirect("core:ssh_access")


@admin_required
@require_POST
def upload_key(request):
    text = request.POST.get("private_key", "")
    if not text.strip() and request.FILES.get("key_file"):
        text = request.FILES["key_file"].read(64 * 1024).decode(errors="replace")
    if not text.strip():
        messages.error(request, "Paste the Private Key or Choose Its File.")
        return redirect("core:ssh_access")
    replacing = ssh.current_key()
    try:
        key = ssh.upload_key(text, request.POST.get("passphrase", ""), request.user)
    except ssh.SshError as exc:
        messages.error(request, str(exc))
        return redirect("core:ssh_access")
    audit.log(request.user, "ssh.key_uploaded", key, fingerprint=key.fingerprint, replaced=replacing.fingerprint if replacing else None)
    messages.success(request, f"Key Uploaded ({key.key_type}, {key.fingerprint}). It Is Stored Encrypted; the Passphrase Is Not Kept.")
    return redirect("core:ssh_access")


@admin_required
@require_POST
def delete_key(request):
    key = ssh.current_key()
    if key:
        audit.log(request.user, "ssh.key_deleted", key, fingerprint=key.fingerprint)
        key.delete()
        messages.success(request, "SSH Key Deleted. Ask the Sysadmins to Remove It from the Hosts Too.")
    return redirect("core:ssh_access")


@admin_required
@require_POST
def host_settings(request, pk):
    host = get_object_or_404(Host, pk=pk)
    address = request.POST.get("ssh_address", "").strip()
    username = request.POST.get("ssh_username", "").strip()
    port = request.POST.get("ssh_port", "22").strip() or "22"
    if address:
        try:
            ipaddress.ip_address(address)
        except ValueError:
            if not HOSTNAME.match(address):
                messages.error(request, "Enter an IP Address or a Host Name.")
                return _packages_tab(host)
    if not port.isdigit() or not 0 < int(port) < 65536:
        messages.error(request, "Enter a Port Between 1 and 65535.")
        return _packages_tab(host)
    if username and not re.fullmatch(r"[a-z_][a-z0-9_.-]{0,31}", username):
        messages.error(request, "Enter a Valid Linux User Name.")
        return _packages_tab(host)

    before = ssh.target(host)
    host.ssh_enabled = bool(request.POST.get("ssh_enabled"))
    host.ssh_address, host.ssh_port, host.ssh_username = address, int(port), username
    if ssh.target(host)[:2] != before[:2]:
        # Another address or port may be another server: its key must be confirmed again.
        host.ssh_host_key = host.ssh_pending_host_key = ""
        host.ssh_state = host.ssh_error = ""
    host.save()
    address, port, username = ssh.target(host)
    audit.log(request.user, "host.ssh_settings", host, enabled=host.ssh_enabled, target=f"{username}@{address}:{port}")
    messages.success(request, f"SSH Settings Saved: {username}@{address}:{port}{'' if host.ssh_enabled else ' (Disabled)'}.")
    return _packages_tab(host)


@admin_required
@require_POST
def trust_host_key(request, pk):
    host = get_object_or_404(Host, pk=pk)
    offered = request.POST.get("host_key", "")
    # The fingerprint the admin saw must be the one still pending.
    if not host.ssh_pending_host_key or offered != host.ssh_pending_host_key:
        messages.error(request, "The Pending Host Key Changed; Review It Again.")
        return _packages_tab(host)
    host.ssh_host_key, host.ssh_pending_host_key = offered, ""
    host.ssh_state, host.ssh_error = "", ""
    host.save(update_fields=["ssh_host_key", "ssh_pending_host_key", "ssh_state", "ssh_error"])
    audit.log(request.user, "host.ssh_host_key_trusted", host, fingerprint=ssh.fingerprint(offered))
    _start(host, request.user)
    messages.success(request, f"Host Key {ssh.fingerprint(offered)} Confirmed. Asking the Server…")
    return _packages_tab(host)


@admin_required
@require_POST
def forget_host_key(request, pk):
    host = get_object_or_404(Host, pk=pk)
    if host.ssh_host_key:
        audit.log(request.user, "host.ssh_host_key_forgotten", host, fingerprint=ssh.fingerprint(host.ssh_host_key))
    host.ssh_host_key = host.ssh_pending_host_key = ""
    host.ssh_state = host.ssh_error = ""
    host.save(update_fields=["ssh_host_key", "ssh_pending_host_key", "ssh_state", "ssh_error"])
    messages.info(request, "Host Key Forgotten: the Next Connection Will Ask to Confirm the New One.")
    return _packages_tab(host)


def _start(host, user):
    """Queue "Ask Server" for `host` once the current transaction commits."""
    from .tasks import ask_server

    Host.objects.filter(pk=host.pk).update(ssh_state="running", ssh_error="")

    def enqueue():
        try:
            ask_server.delay(host.pk, user.pk)
        except Exception as exc:  # broker unreachable
            Host.objects.filter(pk=host.pk).update(ssh_state="failed", ssh_error=f"Could Not Queue: {exc}"[:255])

    transaction.on_commit(enqueue)


@editor_required
@require_POST
def ask(request, pk):
    host = get_object_or_404(Host, pk=pk)
    reason = ssh.not_ready_reason(host)
    if reason:
        messages.error(request, reason)
    elif host.ssh_state == "running":
        messages.info(request, "Already Asking This Server.")
    else:
        _start(host, request.user)
    return _packages_tab(host)


@admin_required
@require_POST
def ask_all(request):
    count = 0
    for host in Host.objects.filter(ssh_enabled=True).exclude(ssh_state="running"):
        if not ssh.not_ready_reason(host):
            _start(host, request.user)
            count += 1
    messages.success(request, f"Asking {count} Server{'s' if count != 1 else ''}. Each Host Page Shows Its Result.")
    return redirect("core:ssh_access")
