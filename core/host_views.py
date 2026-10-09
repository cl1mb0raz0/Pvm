import ipaddress

from django.contrib import messages
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse
from django.views.decorators.http import require_POST

from accounts.permissions import editor_required

from . import audit, tags
from .models import Host, LoadBalancer, Tag


@editor_required
@require_POST
def update_network(request, pk):
    """Save the host's private IPs and whether its scanned IP is a load balancer."""
    host = get_object_or_404(Host, pk=pk)
    back = redirect(reverse("core:host_detail", args=[host.pk]) + "?tab=network")

    # Several addresses (the servers of a pool) separated by commas or spaces; the first is the main one.
    typed = request.POST.get("private_ip", "").replace(",", " ").split()
    ips = []
    for value in typed:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            messages.error(request, f"“{value}” Is Not a Valid IP Address.")
            return back
        if not address.is_private:
            messages.warning(request, f"{value} Is Not a Private Address; Saved Anyway.")
        ips.append(str(address))
    host.set_private_ips(ips)

    name = request.POST.get("balancer_name", "").strip()[:100] or "Load balancer"
    if request.POST.get("is_balancer"):
        LoadBalancer.objects.update_or_create(ip_address=host.ip_address, defaults={"name": name})
    else:
        LoadBalancer.objects.filter(ip_address=host.ip_address).delete()

    audit.log(
        request.user,
        "host.network_updated",
        host,
        private_ip=host.private_ip,
        other_private_ips=ips[1:],
        load_balancer=bool(request.POST.get("is_balancer")),
    )
    messages.success(request, "Network Details Saved.")
    return back


@editor_required
@require_POST
def add_tags(request, pk):
    host = get_object_or_404(Host, pk=pk)
    added = tags.resolve(tags.parse(request.POST.get("new_tags", "")))
    if added:
        host.tags.add(*added)
        audit.log(request.user, "host.tagged", host, tags=[t.name for t in added])
    return redirect("core:host_detail", host.pk)


@editor_required
@require_POST
def remove_tag(request, pk, tag_pk):
    host = get_object_or_404(Host, pk=pk)
    tag = get_object_or_404(Tag, pk=tag_pk)
    host.tags.remove(tag)
    audit.log(request.user, "host.untagged", host, tag=tag.name)
    return redirect("core:host_detail", host.pk)
