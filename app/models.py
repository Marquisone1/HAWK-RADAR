import json
from datetime import datetime

from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

db = SQLAlchemy()


# ─────────────────────────────────────────────────────────────────────────────
# API-key user (matches Lookout — reserved for future REST API)
# ─────────────────────────────────────────────────────────────────────────────

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    api_key = db.Column(db.String(255), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_used = db.Column(db.DateTime, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<User {self.id}: {self.api_key[:8]}...>"


# ─────────────────────────────────────────────────────────────────────────────
# Web-UI login user (identical to Lookout)
# ─────────────────────────────────────────────────────────────────────────────

class SiteUser(db.Model):
    __tablename__ = "site_users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="analyst")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self):
        return self.role == "admin"

    def __repr__(self):
        return f"<SiteUser {self.username} ({self.role})>"


# ─────────────────────────────────────────────────────────────────────────────
# RSS Feed source
# ─────────────────────────────────────────────────────────────────────────────

class RSSFeed(db.Model):
    __tablename__ = "rss_feeds"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    url = db.Column(db.String(2048), unique=True, nullable=False)
    category = db.Column(db.String(50), nullable=False, default="News")
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    last_fetched = db.Column(db.DateTime, nullable=True)
    last_error = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    items = db.relationship("FeedItem", backref="feed", lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f"<RSSFeed {self.name}>"


# ─────────────────────────────────────────────────────────────────────────────
# Individual feed item / alert
# ─────────────────────────────────────────────────────────────────────────────

class FeedItem(db.Model):
    __tablename__ = "feed_items"

    id = db.Column(db.Integer, primary_key=True)
    feed_id = db.Column(db.Integer, db.ForeignKey("rss_feeds.id"), nullable=False, index=True)
    guid = db.Column(db.String(2048), nullable=False)
    title = db.Column(db.Text, nullable=False)
    link = db.Column(db.String(2048), nullable=True)
    published = db.Column(db.DateTime, nullable=True, index=True)
    summary = db.Column(db.Text, nullable=True)
    content_html = db.Column(db.Text, nullable=True)
    severity = db.Column(db.String(20), nullable=False, default="unknown", index=True)
    tags_json = db.Column(db.Text, nullable=True)
    iocs_json = db.Column(db.Text, nullable=True)
    is_read = db.Column(db.Boolean, nullable=False, default=False)
    is_starred = db.Column(db.Boolean, nullable=False, default=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    __table_args__ = (
        db.UniqueConstraint("feed_id", "guid", name="uq_feed_guid"),
    )

    @property
    def tags(self):
        if self.tags_json:
            return json.loads(self.tags_json)
        return []

    @tags.setter
    def tags(self, value):
        self.tags_json = json.dumps(value) if value else None

    @property
    def iocs(self):
        if self.iocs_json:
            return json.loads(self.iocs_json)
        return {"ips": [], "domains": [], "cves": [], "hashes": []}

    @iocs.setter
    def iocs(self, value):
        self.iocs_json = json.dumps(value) if value else None

    @property
    def ioc_count(self):
        iocs = self.iocs
        return len(iocs.get('ips', [])) + len(iocs.get('domains', [])) + len(iocs.get('hashes', []))

    @property
    def cve_count(self):
        return len(self.iocs.get('cves', []))

    def __repr__(self):
        return f"<FeedItem {self.id}: {self.title[:40]}>"
