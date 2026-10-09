from .models import AuditLog


def log(user, action, entity, **details):
    """Record `action` performed by `user` on `entity` (any model instance)."""
    AuditLog.objects.create(
        user=user if user.is_authenticated else None,
        action=action,
        entity_type=entity._meta.label,
        entity_id=str(entity.pk),
        details=details,
    )
