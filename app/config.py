import os
import secrets
from dotenv import load_dotenv

load_dotenv()

_PLACEHOLDER = "replace-with-a-random-64-char-hex-string"


def _load_secret_key() -> str:
    env_key = os.environ.get("SECRET_KEY", "").strip()
    if env_key and env_key != _PLACEHOLDER:
        return env_key

    key_file = "/data/secret_key"
    try:
        with open(key_file) as f:
            stored = f.read().strip()
            if stored:
                return stored
    except (FileNotFoundError, PermissionError):
        pass

    generated = secrets.token_hex(32)
    try:
        os.makedirs(os.path.dirname(key_file), exist_ok=True)
        with open(key_file, "w") as f:
            f.write(generated)
    except Exception:
        pass
    return generated


class Config:
    SECRET_KEY = _load_secret_key()

    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", "sqlite:////data/database.db"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    FLASK_ENV = os.getenv("FLASK_ENV", "production")
    FLASK_PORT = int(os.getenv("FLASK_PORT", 8000))

    JSON_SORT_KEYS = False

    PERMANENT_SESSION_LIFETIME = 28800

    SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "true").lower() != "false"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    WTF_CSRF_TIME_LIMIT = 3600

    FEED_REFRESH_INTERVAL = int(os.getenv("FEED_REFRESH_INTERVAL", 900))
