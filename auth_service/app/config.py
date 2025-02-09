import os
import requests
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "postgresql://postgres:nazim@localhost:5432/gis_auth_db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
    JWT_ACCESS_TOKEN_EXPIRES = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRES", 3600))

    # OpenID Connect Configuration
    OIDC_PROVIDER_URL = os.getenv("OIDC_PROVIDER_URL")
    OIDC_CLIENT_ID = os.getenv("OIDC_CLIENT_ID")
    OIDC_CLIENT_SECRET = os.getenv("OIDC_CLIENT_SECRET")
    OIDC_REDIRECT_URI = os.getenv("OIDC_REDIRECT_URI")

    @classmethod
    def load_oidc_config(cls):
        """ Fetch OpenID configuration dynamically and set values. """
        try:
            if not cls.OIDC_PROVIDER_URL:
                raise ValueError("OIDC_PROVIDER_URL is not set in environment variables.")

            response = requests.get(f"{cls.OIDC_PROVIDER_URL}/.well-known/openid-configuration")
            response.raise_for_status()
            oidc_config = response.json()

            cls.OIDC_AUTH_URL = oidc_config["authorization_endpoint"]
            cls.OIDC_TOKEN_URL = oidc_config["token_endpoint"]
            cls.OIDC_USERINFO_URL = oidc_config["userinfo_endpoint"]
            cls.OIDC_JWKS_URI = oidc_config["jwks_uri"]

        except requests.RequestException as e:
            raise ValueError(f"Failed to retrieve OpenID configuration: {str(e)}")


# Load OIDC Config only once after the class is defined
Config.load_oidc_config()
