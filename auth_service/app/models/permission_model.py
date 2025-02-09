from app.database import db
from app.models.role_model import role_permissions

class Permission(db.Model):
    """Permission Model for defining user permissions."""
    __tablename__ = 'permissions'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)

    # Many-to-Many Relationship with Roles
    roles = db.relationship('Role', secondary=role_permissions, back_populates="permissions")

    def __repr__(self):
        return f"<Permission(id={self.id}, name={self.name})>"
