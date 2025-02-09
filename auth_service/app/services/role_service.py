from app.models.role_model import Role, db
from sqlalchemy.exc import IntegrityError

def create_role(name):
    """Create a new role with validation."""
    existing_role = Role.query.filter_by(name=name).first()
    if existing_role:
        return None, "Role already exists"

    try:
        role = Role(name=name)
        db.session.add(role)
        db.session.commit()
        return role, None
    except Exception as e:
        db.session.rollback()
        return None, str(e)

def get_roles():
    """Retrieve all roles."""
    roles = Role.query.all()
    return [{"role_id": r.id, "role_name": r.name} for r in roles]
