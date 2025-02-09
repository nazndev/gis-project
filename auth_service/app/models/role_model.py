from app.database import db

# Many-to-Many table for User-Role mapping
user_role_mapping = db.Table(
    'user_role_mapping',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id', ondelete="CASCADE"), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey('roles.id', ondelete="CASCADE"), primary_key=True)
)

# Many-to-Many table for Role-Permission mapping
role_permissions = db.Table(
    'role_permissions',
    db.Column('role_id', db.Integer, db.ForeignKey('roles.id', ondelete="CASCADE"), primary_key=True),
    db.Column('permission_id', db.Integer, db.ForeignKey('permissions.id', ondelete="CASCADE"), primary_key=True)
)

class Role(db.Model):
    """Role Model for defining user roles."""
    __tablename__ = 'roles'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

    # Many-to-Many Relationship with Users
    users = db.relationship('User', secondary=user_role_mapping, back_populates="roles")

    # Many-to-Many Relationship with Permissions
    permissions = db.relationship('Permission', secondary=role_permissions, back_populates="roles")

    def __repr__(self):
        return f"<Role(id={self.id}, name={self.name})>"
