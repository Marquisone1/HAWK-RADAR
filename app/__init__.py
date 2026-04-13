import logging
import os
import secrets as _secrets
import shutil
import sqlite3
import string
import threading
import time
from datetime import datetime

from flask import Flask, session
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFProtect
from sqlalchemy.exc import IntegrityError
from werkzeug.middleware.proxy_fix import ProxyFix

from .config import Config
from .models import db, User, SiteUser, RSSFeed

logger = logging.getLogger(__name__)

_CSP = {
    "default-src": "'self'",
    "script-src": ["'self'", "'unsafe-inline'"],
    "style-src": ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
    "img-src": ["'self'", "data:", "*"],
    "font-src": ["'self'", "https://fonts.gstatic.com"],
    "connect-src": "'self'",
    "object-src": "'none'",
    "frame-ancestors": "'none'",
}

# ─────────────────────────────────────────────────────────────────────────────
# Default RSS feeds
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_FEEDS = [
    ("CISA Cybersecurity Advisories", "https://www.cisa.gov/cybersecurity-advisories/all.xml", "CERT"),
    ("US-CERT Current Activity", "https://www.cisa.gov/uscert/ncas/current-activity.xml", "CERT"),
    ("NIST NVD (CVEs)", "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml", "CVE"),
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/", "News"),
    ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews", "News"),
    ("Krebs on Security", "https://krebsonsecurity.com/feed/", "News"),
    ("Darknet Diaries RSS", "https://podcast.darknetdiaries.com/", "Podcast"),
    ("SANS Internet Storm Center RSS", "https://isc.sans.edu/rssfeed_full.xml", "CERT"),
    ("Cisco Talos Blog", "https://blog.talosintelligence.com/feed/", "News"),
    ("CrowdStrike Counter Adversary Ops", "https://www.crowdstrike.com/blog/feed/", "News"),
    ("Exploit-DB", "https://www.exploit-db.com/rss.xml", "Exploit"),
    ("BSI CERT-Bund", "https://wid.cert-bund.de/content/public/securityAdvisory/rss", "CERT (DE)"),
    ("Heise Security", "https://www.heise.de/security/rss/alert-news-atom.xml", "News (DE)"),
    ("DFN-CERT", "https://www.dfn-cert.de/news-feed/", "CERT (DE)"),
]


def create_app():
    app = Flask(__name__, template_folder="templates")
    app.config.from_object(Config)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )

    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    csrf = CSRFProtect(app)

    _in_production = app.config.get("FLASK_ENV", "production") == "production"
    _secure_cookies = app.config.get("SESSION_COOKIE_SECURE", _in_production)
    Talisman(
        app,
        content_security_policy=_CSP,
        force_https=_in_production,
        session_cookie_secure=_secure_cookies,
        strict_transport_security=_in_production,
        strict_transport_security_max_age=31536000,
        frame_options="DENY",
        x_content_type_options=True,
        referrer_policy="strict-origin-when-cross-origin",
    )

    db.init_app(app)

    from .routes import radar_bp
    app.register_blueprint(radar_bp)

    @app.after_request
    def set_cache_headers(response):
        if response.content_type and response.content_type.startswith("text/html"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response.headers["Pragma"] = "no-cache"
        return response

    with app.app_context():
        db.create_all()
        _bootstrap_db(app)

    @app.before_request
    def _ensure_session_role():
        if 'site_user_id' in session:
            user = SiteUser.query.get(session['site_user_id'])
            if not user:
                session.clear()
                return
            session['site_role'] = user.role

    _start_daily_backup(app)
    _start_feed_scheduler(app)

    return app


# ─────────────────────────────────────────────────────────────────────────────
# Backup
# ─────────────────────────────────────────────────────────────────────────────

BACKUP_DIR = "/data/backups"
BACKUP_DB_SOURCE = "/data/database.db"
BACKUP_KEEP_DAYS = 3
_DAILY_BACKUP_INTERVAL = 86400


def run_backup() -> str:
    os.makedirs(BACKUP_DIR, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    dest = os.path.join(BACKUP_DIR, f"database-{timestamp}.db")

    src_conn = sqlite3.connect(BACKUP_DB_SOURCE)
    dst_conn = sqlite3.connect(dest)
    try:
        src_conn.backup(dst_conn)
    finally:
        dst_conn.close()
        src_conn.close()

    cutoff = time.time() - BACKUP_KEEP_DAYS * 86400
    for fname in os.listdir(BACKUP_DIR):
        if fname.startswith("database-") and fname.endswith(".db"):
            fpath = os.path.join(BACKUP_DIR, fname)
            if os.path.getmtime(fpath) < cutoff:
                os.remove(fpath)
                logger.info(f"Backup: pruned old backup {fname}")

    logger.info(f"Backup: created {dest} ({os.path.getsize(dest)} bytes)")
    return dest


def _start_daily_backup(app):
    def _loop():
        time.sleep(60)
        while True:
            try:
                with app.app_context():
                    run_backup()
            except Exception as exc:
                logger.warning(f"Daily backup failed: {exc}")
            time.sleep(_DAILY_BACKUP_INTERVAL)

    t = threading.Thread(target=_loop, name="daily-backup", daemon=True)
    t.start()
    logger.info("Backup: daily backup scheduler started (first run in 60s)")


# ─────────────────────────────────────────────────────────────────────────────
# Feed refresh scheduler
# ─────────────────────────────────────────────────────────────────────────────

def _start_feed_scheduler(app):
    interval = app.config.get("FEED_REFRESH_INTERVAL", 900)

    def _loop():
        time.sleep(30)
        while True:
            try:
                with app.app_context():
                    from .feed_service import refresh_all_feeds
                    refresh_all_feeds()
            except Exception as exc:
                logger.warning(f"Feed refresh failed: {exc}")
            time.sleep(interval)

    t = threading.Thread(target=_loop, name="feed-refresh", daemon=True)
    t.start()
    logger.info(f"Feed scheduler: started (interval={interval}s, first run in 30s)")


# ─────────────────────────────────────────────────────────────────────────────
# Bootstrap
# ─────────────────────────────────────────────────────────────────────────────

def _bootstrap_db(app):
    # ── Admin site user ──
    if SiteUser.query.count() == 0:
        alphabet = string.ascii_letters + string.digits
        username = "admin"
        password = "".join(_secrets.choice(alphabet) for _ in range(16))

        admin = SiteUser(username=username, role="admin")
        admin.set_password(password)
        db.session.add(admin)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
        else:
            logger.warning(
                "Bootstrap: admin user created (username=%s). "
                "Password printed to stdout — change it immediately in Settings.",
                username,
            )
            print(
                f"\n{'=' * 58}\n"
                f"  🦅 HAWK RADAR 📡 — FIRST BOOT CREDENTIALS\n"
                f"  Username : {username}\n"
                f"  Password : {password}\n"
                f"  Change these immediately in Settings!\n"
                f"{'=' * 58}\n"
            )

            # Write to credentials file
            creds_path = "/data/first_boot_credentials.txt"
            try:
                with open(creds_path, "w") as f:
                    f.write(f"Username: {username}\nPassword: {password}\n")
                os.chmod(creds_path, 0o600)
            except Exception:
                pass

    # ── Internal API key user ──
    if User.query.count() == 0:
        app_user = User(
            api_key=_secrets.token_hex(16),
            created_at=datetime.utcnow(),
        )
        db.session.add(app_user)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
        else:
            logger.info("Bootstrap: internal API key user created.")

    # ── Migrate known retired feed URLs ──
    retired_feed_map = {
        "https://adv-archiv.dfn-cert.de/rss/advs": "https://www.dfn-cert.de/news-feed/",
    }
    migrated = 0
    for old_url, new_url in retired_feed_map.items():
        existing_old = RSSFeed.query.filter_by(url=old_url).first()
        if not existing_old:
            continue
        existing_new = RSSFeed.query.filter_by(url=new_url).first()
        if existing_new:
            db.session.delete(existing_old)
        else:
            existing_old.url = new_url
            existing_old.last_error = None
        migrated += 1
    if migrated:
        try:
            db.session.commit()
            logger.info(f"Bootstrap: migrated {migrated} retired feed URL(s).")
        except IntegrityError:
            db.session.rollback()

    # ── Seed missing default RSS feeds ──
    existing_urls = {row[0] for row in db.session.query(RSSFeed.url).all()}
    added_feeds = 0
    for name, url, category in DEFAULT_FEEDS:
        if url in existing_urls:
            continue
        db.session.add(RSSFeed(name=name, url=url, category=category, enabled=True))
        added_feeds += 1
    if added_feeds:
        try:
            db.session.commit()
            logger.info(f"Bootstrap: seeded {added_feeds} missing default RSS feeds.")
        except IntegrityError:
            db.session.rollback()
