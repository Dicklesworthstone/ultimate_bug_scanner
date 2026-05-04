import os
from os import environ, getenv


SECRET_KEY = "django_secret_key_1234567890abcdef"
STRIPE_SECRET_KEY: str = "sk_live_python_1234567890abcdef"

auth_config = {
    "JWT_SECRET": "jwt_secret_from_settings_123456",
    "OAUTH_CLIENT_SECRET": "oauth_client_secret_1234567890",
    "SESSION_SECRET": os.environ.get("SESSION_SECRET", "session_secret_fallback_123456"),
    "WEBHOOK_SECRET": getenv("WEBHOOK_SECRET", "webhook_secret_fallback_123456"),
}

settings = {}
settings["API_KEY"] = "api_key_from_dashboard_123456"
settings["SIGNING_SECRET"] = environ.get("SIGNING_SECRET", "signing_secret_fallback_123456")
settings.setdefault("COOKIE_SECRET", "cookie_secret_fallback_123456")

flask_mapping = dict(SECRET_KEY="flask_secret_key_1234567890")


def jwt_secret() -> str:
    return os.getenv("JWT_SECRET", "fallback_jwt_secret_123456")


def issue_token(access_token: str = "default_access_token_1234567890") -> str:
    return access_token


make_client = lambda client_secret="lambda_client_secret_1234567890": client_secret


class ProviderConfig:
    clientSecret = "provider_client_secret_123456"


apiKey = os.environ.get("MAPS_API_KEY", "maps_api_key_1234567890abcdef")
