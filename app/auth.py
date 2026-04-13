import logging
import re
import threading
from collections import defaultdict
from datetime import datetime, timedelta
from functools import wraps

from flask import jsonify, redirect, request, session, url_for

from .models import db

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# In-memory sliding-window rate limiter
# ─────────────────────────────────────────────────────────────────────────────

_rate_lock = threading.Lock()
_rate_buckets: dict[tuple, list] = defaultdict(list)

_API_RATE_LIMIT = 30
_API_RATE_WINDOW = 60


def _is_rate_limited(ip: str, limit: int = _API_RATE_LIMIT, window: int = _API_RATE_WINDOW, bucket: str = "default") -> bool:
    now = datetime.utcnow()
    cutoff = now - timedelta(seconds=window)
    key = (ip, bucket)
    with _rate_lock:
        _rate_buckets[key] = [t for t in _rate_buckets[key] if t > cutoff]
        if len(_rate_buckets[key]) >= limit:
            return True
        _rate_buckets[key].append(now)
    return False


# ─────────────────────────────────────────────────────────────────────────────
# Decorators
# ─────────────────────────────────────────────────────────────────────────────

def web_login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "site_user_id" not in session:
            return redirect(url_for("radar.login"))
        return f(*args, **kwargs)
    return decorated


def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "site_user_id" not in session:
            return redirect(url_for("radar.login"))
        if session.get("site_role") != "admin":
            from flask import flash
            flash("Admin access required.", "error")
            return redirect(url_for("radar.index"))
        return f(*args, **kwargs)
    return decorated


# ─────────────────────────────────────────────────────────────────────────────
# Password strength validation
# ─────────────────────────────────────────────────────────────────────────────

_MIN_PASSWORD_LEN = 12


def validate_password_strength(password: str) -> list[str]:
    errors = []
    if len(password) < _MIN_PASSWORD_LEN:
        errors.append(f"Password must be at least {_MIN_PASSWORD_LEN} characters.")
    if not re.search(r"[A-Z]", password):
        errors.append("Password must contain at least one uppercase letter.")
    if not re.search(r"[a-z]", password):
        errors.append("Password must contain at least one lowercase letter.")
    if not re.search(r"[0-9]", password):
        errors.append("Password must contain at least one digit.")
    if not re.search(r"[!@#$%^&*()\-_=+\[\]{};:',.<>?/\\|`~]", password):
        errors.append("Password must contain at least one special character.")
    return errors
