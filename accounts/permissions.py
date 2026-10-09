from functools import wraps

from django.core.exceptions import PermissionDenied

from .models import User

Role = User.Role
EDITOR_ROLES = {Role.SUPER_ADMIN, Role.ADMIN, Role.ANALYST}
ADMIN_ROLES = {Role.SUPER_ADMIN, Role.ADMIN}


def _has_role(user, roles):
    return user.is_authenticated and (user.is_superuser or user.role in roles)


def can_edit(user):
    """
    Admins and analysts change data; read-only users only view it.
    Superusers always can, whatever their role.
    """
    return _has_role(user, EDITOR_ROLES)


def can_manage_backups(user):
    """See the backup list and take a backup."""
    return _has_role(user, ADMIN_ROLES)


def can_manage_settings(user):
    """PVM's SSH key and each host's SSH connection settings: admins only."""
    return _has_role(user, ADMIN_ROLES)


def is_super_admin(user):
    """Restore, delete or download a backup: they hold every password hash and MFA secret."""
    return _has_role(user, {Role.SUPER_ADMIN})


def require(check):
    """View decorator: 403 unless `check(request.user)`."""

    def decorator(view):
        @wraps(view)
        def wrapper(request, *args, **kwargs):
            if not check(request.user):
                raise PermissionDenied
            return view(request, *args, **kwargs)

        return wrapper

    return decorator


editor_required = require(can_edit)
