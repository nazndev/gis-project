from app.database import db

class User(db.Model):
    """User Model for managing application users."""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=True)  # Nullable for OpenID users
    oidc_sub = db.Column(db.String(255), unique=True, nullable=True)  # Add OIDC subject ID

    # Many-to-Many Relationship with Roles
    roles = db.relationship(
        'Role', secondary='user_role_mapping', back_populates="users"
    )

    def __repr__(self):
        return f"<User(id={self.id}, email={self.email}, oidc_sub={self.oidc_sub})>"
