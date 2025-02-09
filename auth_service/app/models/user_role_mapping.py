from app.database import db

class UserRoleMapping(db.Model):
    """Mapping table between users and roles."""
    __tablename__ = 'user_role_mapping'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete="CASCADE"), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id', ondelete="CASCADE"), nullable=False)
