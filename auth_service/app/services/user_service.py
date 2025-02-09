from app.models.user_model import User, db
from app.utils.security_util import hash_password

def create_user(email, password):
    """Create a new user with hashed password."""
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return None, "User already exists"

    try:
        hashed_pw = hash_password(password)
        user = User(email=email, password=hashed_pw)
        db.session.add(user)
        db.session.commit()
        return user, None
    except Exception as e:
        db.session.rollback()
        return None, str(e)

def get_user_by_email(email):
    """Fetch user details by email."""
    return User.query.filter_by(email=email).first()
