import requests
import jwt
import json
from flask import request, jsonify, redirect, session
from flask_jwt_extended import create_access_token, jwt_required
from app.models.user_model import User, db
from app.config import Config
from urllib.parse import urlencode
import logging

logger = logging.getLogger(__name__)

def get_oidc_config():
    """ Fetch OpenID Configuration securely. """
    if not Config.OIDC_PROVIDER_URL:
        logger.error("OIDC_PROVIDER_URL is not set in environment variables")
        raise ValueError("OIDC Provider URL is missing. Check your .env file.")

    try:
        response = requests.get(f"{Config.OIDC_PROVIDER_URL}/.well-known/openid-configuration")
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger.error(f"Failed to fetch OpenID configuration: {str(e)}")
        raise ValueError("Could not retrieve OpenID configuration")

# Load OpenID Configuration
OIDC_CONFIG = get_oidc_config()
OIDC_AUTH_URL = OIDC_CONFIG.get("authorization_endpoint", f"{Config.OIDC_PROVIDER_URL}/o/oauth2/auth")
OIDC_TOKEN_URL = OIDC_CONFIG.get("token_endpoint", f"{Config.OIDC_PROVIDER_URL}/o/oauth2/token")
OIDC_USERINFO_URL = OIDC_CONFIG.get("userinfo_endpoint", f"{Config.OIDC_PROVIDER_URL}/oauth2/v3/userinfo")
OIDC_JWKS_URI = OIDC_CONFIG.get("jwks_uri", f"{Config.OIDC_PROVIDER_URL}/oauth2/v3/certs")

def get_oidc_login_url():
    """ Generate OpenID Connect Login URL """
    params = {
        "client_id": Config.OIDC_CLIENT_ID,
        "response_type": "code",
        "scope": "openid email profile",
        "redirect_uri": Config.OIDC_REDIRECT_URI
    }
    return f"{OIDC_AUTH_URL}?{urlencode(params)}"

def authenticate_with_oidc():
    """ Redirect user to OIDC authentication page """
    return redirect(get_oidc_login_url())

def oidc_callback():
    """ Handle OIDC callback and issue JWT token """
    code = request.args.get("code")
    if not code:
        return jsonify({"error": "Authorization code not found"}), 400

    try:
        tokens = exchange_code_for_token(code)
        return jsonify({"access_token": tokens["jwt_access_token"], "email": tokens["email"]})
    except ValueError as e:
        logger.error(f"OIDC Authentication Error: {str(e)}")
        return jsonify({"error": str(e)}), 401
    except Exception as e:
        logger.error(f"Unexpected Error: {str(e)}")
        return jsonify({"error": "Internal Server Error"}), 500

def exchange_code_for_token(auth_code):
    """ Exchange authorization code for access & ID tokens """
    if not auth_code:
        raise ValueError("Authorization code is required")

    payload = {
        "client_id": Config.OIDC_CLIENT_ID,
        "client_secret": Config.OIDC_CLIENT_SECRET,
        "code": auth_code,
        "grant_type": "authorization_code",
        "redirect_uri": Config.OIDC_REDIRECT_URI
    }

    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    try:
        response = requests.post(OIDC_TOKEN_URL, data=payload, headers=headers)
        response.raise_for_status()
        token_data = response.json()
    except requests.RequestException as e:
        logger.error(f"Error exchanging code for token: {str(e)}")
        raise ValueError("Failed to exchange code for token")

    id_token = token_data.get("id_token")
    access_token = token_data.get("access_token")
    if not id_token or not access_token:
        raise ValueError("Failed to retrieve ID token or access token")

    user_email = validate_id_token(id_token)

    user = User.query.filter_by(email=user_email).first()
    if not user:
        user = User(email=user_email)
        db.session.add(user)
        db.session.commit()

    jwt_token = create_access_token(identity=user.id)
    session["access_token"] = access_token  # Store OpenID access token securely
    return {"jwt_access_token": jwt_token, "openid_access_token": access_token, "email": user_email}

def validate_id_token(id_token):
    """Validate ID Token using OpenID public keys."""
    try:
        jwks = requests.get(OIDC_JWKS_URI).json()
        public_keys = {key["kid"]: jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key)) for key in jwks["keys"]}

        decoded_header = jwt.get_unverified_header(id_token)
        public_key = public_keys.get(decoded_header["kid"])
        if not public_key:
            raise ValueError("Invalid token signature")

        decoded_token = jwt.decode(id_token, public_key, algorithms=["RS256"], audience=Config.OIDC_CLIENT_ID)
        return decoded_token.get("email")
    except Exception as e:
        logger.error(f"JWT validation failed: {str(e)}")
        raise ValueError("Invalid ID token")

@jwt_required()
def get_user_info():
    """Fetch user info from OpenID provider using access token."""
    access_token = session.get("access_token")
    if not access_token:
        return jsonify({"error": "Unauthorized"}), 401

    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.get(OIDC_USERINFO_URL, headers=headers)

    if response.status_code != 200:
        return jsonify({"error": "Failed to fetch user info"}), 400

    return jsonify(response.json()), 200

def process_oidc_callback(auth_code):
    """Process OIDC callback and fetch tokens."""
    if not auth_code:
        raise ValueError("Authorization code not provided")

    data = {
        "client_id": Config.OIDC_CLIENT_ID,
        "client_secret": Config.OIDC_CLIENT_SECRET,
        "code": auth_code,
        "grant_type": "authorization_code",
        "redirect_uri": Config.OIDC_REDIRECT_URI
    }

    try:
        response = requests.post(OIDC_TOKEN_URL, data=data)
        response.raise_for_status()
        token_response = response.json()
    except requests.RequestException as e:
        logger.error(f"OIDC Token Request Failed: {str(e)}")
        raise ValueError("OIDC authentication failed")

    id_token = token_response.get("id_token")
    access_token = token_response.get("access_token")
    if not id_token or not access_token:
        raise ValueError("Failed to retrieve tokens")

    user_email = validate_id_token(id_token)

    user = User.query.filter_by(email=user_email).first()
    if not user:
        user = User(email=user_email)
        db.session.add(user)
        db.session.commit()

    jwt_token = create_access_token(identity=user.id)
    session["access_token"] = access_token  # Store OpenID access token securely
    return {"jwt_access_token": jwt_token, "openid_access_token": access_token, "email": user_email}
