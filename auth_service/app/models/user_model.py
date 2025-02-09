from app.database import db
from app.models.role_model import user_role_mapping

class User(db.Model):
    """User Model for managing application users."""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=True)  # Nullable for OpenID users

    # Many-to-Many Relationship with Roles
    roles = db.relationship('Role', secondary=user_role_mapping, back_populates="users")

    def __repr__(self):
        return f"<User(id={self.id}, email={self.email})>"
