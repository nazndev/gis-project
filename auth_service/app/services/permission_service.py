from app.models.permission_model import Permission, db
from sqlalchemy.exc import IntegrityError

def create_permission(name):
    """Create a new permission with validation."""
    existing_permission = Permission.query.filter_by(name=name).first()
    if existing_permission:
        return None, "Permission already exists"

    try:
        permission = Permission(name=name)
        db.session.add(permission)
        db.session.commit()
        return permission, None
    except Exception as e:
        db.session.rollback()
        return None, str(e)

def get_permissions():
    """Retrieve all permissions."""
    permissions = Permission.query.all()
    return [{"permission_id": p.id, "permission_name": p.name} for p in permissions]
