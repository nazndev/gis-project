import bcrypt

def hash_password(password):
    """Hash a password securely."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def check_password(password, hashed_password):
    """Verify a stored password against user input."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
