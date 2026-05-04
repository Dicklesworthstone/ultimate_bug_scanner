import os
from os import environ, getenv


def required_env(name: str) -> str:
    value = os.environ[name]
    if not value:
        raise RuntimeError(f"Missing {name}")
    return value


SECRET_KEY = required_env("SECRET_KEY")
STRIPE_SECRET_KEY: str = required_env("STRIPE_SECRET_KEY")

auth_config = {
    "JWT_SECRET": required_env("JWT_SECRET"),
    "OAUTH_CLIENT_SECRET": required_env("OAUTH_CLIENT_SECRET"),
    "SESSION_SECRET": os.environ["SESSION_SECRET"],
    "WEBHOOK_SECRET": getenv("WEBHOOK_SECRET"),
}

settings = {}
settings["API_KEY"] = environ["API_KEY"]
settings["SIGNING_SECRET"] = required_env("SIGNING_SECRET")
settings.setdefault("COOKIE_SECRET", required_env("COOKIE_SECRET"))

flask_mapping = dict(SECRET_KEY=required_env("FLASK_SECRET_KEY"))


def jwt_secret() -> str:
    return required_env("JWT_SECRET")


def issue_token(access_token: str = required_env("ACCESS_TOKEN")) -> str:
    return access_token


def build_callback(retry_count: int = 3) -> int:
    return retry_count


class ProviderConfig:
    clientSecret = required_env("PROVIDER_CLIENT_SECRET")


apiKey = required_env("MAPS_API_KEY")
display_config = {
    "THEME_VARIANT": os.getenv("THEME_VARIANT", "dark"),
    "PUBLIC_BASE_URL": os.getenv("PUBLIC_BASE_URL", "https://example.com"),
}
