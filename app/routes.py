import logging
import os
import shutil
import sqlite3
import tempfile
from datetime import datetime, timedelta

from flask import (
    Blueprint,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)

from .auth import _is_rate_limited, require_admin, validate_password_strength, web_login_required
from .models import FeedItem, RSSFeed, SiteUser, User, db

logger = logging.getLogger(__name__)

radar_bp = Blueprint("radar", __name__)

SECTOR_KEYWORDS = {
    "financial": ["bank", "banking", "financial", "finance", "fintech", "payment", "swift"],
    "automotive": ["auto", "automotive", "vehicle", "car", "fleet", "mobility", "transport"],
    "healthcare": ["healthcare", "hospital", "medical", "pharma", "pharmaceutical", "clinic", "patient"],
    "energy": ["energy", "utility", "utilities", "power", "electric", "grid", "oil", "gas"],
    "telecom": ["telecom", "telco", "carrier", "broadband", "mobile network", "isp"],
    "retail": ["retail", "e-commerce", "ecommerce", "shop", "consumer", "supermarket"],
    "government": ["government", "federal", "state", "ministry", "municipal", "public sector"],
    "manufacturing": ["manufacturing", "factory", "industrial", "plant", "warehouse", "supply chain"],
    "technology": ["technology", "software", "cloud", "saas", "developer", "it services"],
}


def _apply_feed_item_filters(query, args, include_feed_id=True):
    severity = args.get("severity", "").strip().lower()
    feed_id = args.get("feed_id", default=None, type=int)
    tag = args.get("tag", "").strip().lower()
    search = args.get("search", "").strip()
    starred = args.get("starred", "").strip().lower()
    unread = args.get("unread", "").strip().lower()
    country = args.get("country", "").strip().lower()
    time_range = args.get("time_range", "").strip().lower()
    has_cves = args.get("has_cves", "").strip().lower()
    has_iocs = args.get("has_iocs", "").strip().lower()
    category = args.get("category", "").strip()
    sector = args.get("sector", "").strip().lower()

    if severity and severity != "all":
        query = query.filter(FeedItem.severity == severity)
    if feed_id and include_feed_id:
        query = query.filter(FeedItem.feed_id == feed_id)
    if country == "de":
        de_feeds = [f.id for f in RSSFeed.query.filter(RSSFeed.category.ilike("%DE%")).all()]
        if de_feeds:
            query = query.filter(FeedItem.feed_id.in_(de_feeds))
        else:
            query = query.filter(db.literal(False))
    if category:
        category_feeds = [f.id for f in RSSFeed.query.filter(RSSFeed.category.ilike(f"%{category}%")).all()]
        if category_feeds:
            query = query.filter(FeedItem.feed_id.in_(category_feeds))
        else:
            query = query.filter(db.literal(False))
    if time_range:
        delta_map = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30)}
        delta = delta_map.get(time_range)
        if delta:
            query = query.filter(FeedItem.published >= datetime.utcnow() - delta)
    if has_cves == "true":
        query = query.filter(FeedItem.iocs_json.ilike('%"cves"%'))
        query = query.filter(db.not_(FeedItem.iocs_json.ilike('%"cves": []%')))
    if has_iocs == "true":
        query = query.filter(
            db.or_(
                db.and_(FeedItem.iocs_json.ilike('%"ips"%'), db.not_(FeedItem.iocs_json.ilike('%"ips": []%'))),
                db.and_(FeedItem.iocs_json.ilike('%"domains"%'), db.not_(FeedItem.iocs_json.ilike('%"domains": []%'))),
                db.and_(FeedItem.iocs_json.ilike('%"hashes"%'), db.not_(FeedItem.iocs_json.ilike('%"hashes": []%'))),
            )
        )
    if sector and sector in SECTOR_KEYWORDS:
        sector_conditions = []
        for keyword in SECTOR_KEYWORDS[sector]:
            pattern = f"%{keyword}%"
            sector_conditions.extend(
                [
                    FeedItem.title.ilike(pattern),
                    FeedItem.summary.ilike(pattern),
                    FeedItem.tags_json.ilike(pattern),
                ]
            )
        query = query.filter(db.or_(*sector_conditions))
    if tag:
        query = query.filter(FeedItem.tags_json.contains(f'"{tag}"'))
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            db.or_(
                FeedItem.title.ilike(search_term),
                FeedItem.summary.ilike(search_term),
            )
        )
    if starred == "true":
        query = query.filter(FeedItem.is_starred.is_(True))
    if unread == "true":
        query = query.filter(FeedItem.is_read.is_(False))

    return query

# ─────────────────────────────────────────────────────────────────────────────
# Main radar dashboard
# ─────────────────────────────────────────────────────────────────────────────


@radar_bp.route("/", methods=["GET"])
@web_login_required
def index():
    return render_template("radar.html")


# ─────────────────────────────────────────────────────────────────────────────
# Feed items JSON endpoint (used by dashboard JS)
# ─────────────────────────────────────────────────────────────────────────────


@radar_bp.route("/web/feed-items", methods=["GET"])
@web_login_required
def web_feed_items():
    limit = request.args.get("limit", default=50, type=int)
    offset = request.args.get("offset", default=0, type=int)
    limit = max(1, min(limit, 200))
    offset = max(0, offset)
    time_range = request.args.get("time_range", "").strip().lower()

    q = _apply_feed_item_filters(FeedItem.query, request.args)

    total = q.count()

    # Filtered severity breakdown for live stats
    filtered_stats = {}
    for sev in ("critical", "high", "medium", "low", "unknown"):
        filtered_stats[sev] = q.filter(FeedItem.severity == sev).count()
    filtered_stats["unread"] = q.filter(FeedItem.is_read.is_(False)).count()
    time_labels = {"24h": "Last 24h", "7d": "Last 7d", "30d": "Last 30d"}
    if time_range in time_labels:
        filtered_stats["time_window_count"] = total
        filtered_stats["time_window_label"] = time_labels[time_range]
    else:
        filtered_stats["time_window_count"] = q.filter(FeedItem.published >= datetime.utcnow() - timedelta(hours=24)).count()
        filtered_stats["time_window_label"] = "Last 24h"

    items = q.order_by(FeedItem.published.desc()).offset(offset).limit(limit).all()

    # Build feed name lookup
    feed_names = {f.id: f.name for f in RSSFeed.query.all()}

    items_list = [
        {
            "id": item.id,
            "feed_id": item.feed_id,
            "feed_name": feed_names.get(item.feed_id, "Unknown"),
            "title": item.title,
            "link": item.link,
            "published": item.published.isoformat() if item.published else None,
            "summary": (item.summary or "")[:500],
            "severity": item.severity,
            "tags": item.tags,
            "iocs": item.iocs,
            "ioc_count": item.ioc_count,
            "cve_count": item.cve_count,
            "is_read": item.is_read,
            "is_starred": item.is_starred,
        }
        for item in items
    ]

    return jsonify({
        "total": total,
        "limit": limit,
        "offset": offset,
        "count": len(items_list),
        "items": items_list,
        "filtered_stats": filtered_stats,
    }), 200


# ─────────────────────────────────────────────────────────────────────────────
# Analytics JSON
# ─────────────────────────────────────────────────────────────────────────────


@radar_bp.route("/web/analytics", methods=["GET"])
@web_login_required
def web_analytics():
    from datetime import datetime as _dt, timedelta as _td

    total = FeedItem.query.count()
    now = _dt.utcnow()
    last_24h = FeedItem.query.filter(FeedItem.created_at >= now - _td(hours=24)).count()
    critical_count = FeedItem.query.filter(FeedItem.severity == "critical").count()
    unread_count = FeedItem.query.filter(FeedItem.is_read.is_(False)).count()

    # Items by severity
    severity_counts = {}
    for sev in ("critical", "high", "medium", "low", "unknown"):
        severity_counts[sev] = FeedItem.query.filter(FeedItem.severity == sev).count()

    # Items by day (last 30 days)
    thirty_days_ago = now - _td(days=30)
    recent_items = FeedItem.query.filter(FeedItem.published >= thirty_days_ago).all()

    by_day = {}
    tag_counts = {}
    ioc_type_counts = {"ips": 0, "domains": 0, "cves": 0, "hashes": 0}
    top_iocs_raw = {}

    for item in recent_items:
        if item.published:
            day = item.published.strftime("%Y-%m-%d")
            if day not in by_day:
                by_day[day] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0, "total": 0}
            sev_key = item.severity if item.severity in ("critical", "high", "medium", "low") else "unknown"
            by_day[day][sev_key] += 1
            by_day[day]["total"] += 1

        for t in item.tags:
            tag_counts[t] = tag_counts.get(t, 0) + 1

        iocs = item.iocs
        for ioc_type in ("ips", "domains", "cves", "hashes"):
            vals = iocs.get(ioc_type, [])
            ioc_type_counts[ioc_type] += len(vals)
            for val in vals[:5]:  # limit per item to prevent skew
                top_iocs_raw[val] = top_iocs_raw.get(val, 0) + 1

    by_day_sorted = sorted(by_day.items())
    top_tags = sorted(tag_counts.items(), key=lambda x: x[1], reverse=True)[:15]
    top_iocs = sorted(top_iocs_raw.items(), key=lambda x: x[1], reverse=True)[:15]

    # Feed stats
    feeds = RSSFeed.query.all()
    feed_stats = [
        {
            "id": f.id,
            "name": f.name,
            "category": f.category,
            "enabled": f.enabled,
            "item_count": FeedItem.query.filter_by(feed_id=f.id).count(),
            "last_fetched": f.last_fetched.isoformat() if f.last_fetched else None,
            "last_error": f.last_error,
        }
        for f in feeds
    ]

    return jsonify({
        "total": total,
        "last_24h": last_24h,
        "critical_count": critical_count,
        "unread_count": unread_count,
        "severity_counts": severity_counts,
        "by_day": [{"date": d, **counts} for d, counts in by_day_sorted],
        "top_tags": [{"tag": t, "count": c} for t, c in top_tags],
        "top_iocs": [{"ioc": i, "count": c} for i, c in top_iocs],
        "ioc_type_counts": ioc_type_counts,
        "feed_stats": feed_stats,
    }), 200


# ─────────────────────────────────────────────────────────────────────────────
# Feed status
# ─────────────────────────────────────────────────────────────────────────────


@radar_bp.route("/web/feed-status", methods=["GET"])
@web_login_required
def web_feed_status():
    feeds = RSSFeed.query.order_by(RSSFeed.name).all()
    filtered_query = _apply_feed_item_filters(FeedItem.query, request.args, include_feed_id=False)
    feed_counts = {
        feed_id: item_count
        for feed_id, item_count in filtered_query.with_entities(
            FeedItem.feed_id, db.func.count(FeedItem.id)
        ).group_by(FeedItem.feed_id).all()
    }
    feed_list = [
        {
            "id": f.id,
            "name": f.name,
            "url": f.url,
            "category": f.category,
            "enabled": f.enabled,
            "last_fetched": f.last_fetched.isoformat() if f.last_fetched else None,
            "last_error": f.last_error,
            "item_count": feed_counts.get(f.id, 0),
        }
        for f in feeds
    ]
    return jsonify({"feeds": feed_list}), 200


# ─────────────────────────────────────────────────────────────────────────────
# Manual feed refresh
# ─────────────────────────────────────────────────────────────────────────────


@radar_bp.route("/web/refresh", methods=["POST"])
@require_admin
def web_refresh():
    from .feed_service import refresh_all_feeds
    result = refresh_all_feeds()
    return jsonify(result), 200


# ─────────────────────────────────────────────────────────────────────────────
# Star / Read toggles
# ─────────────────────────────────────────────────────────────────────────────


@radar_bp.route("/web/item/<int:item_id>/star", methods=["POST"])
@web_login_required
def web_toggle_star(item_id):
    item = FeedItem.query.get(item_id)
    if not item:
        return jsonify({"error": "Not found"}), 404
    item.is_starred = not item.is_starred
    db.session.commit()
    return jsonify({"id": item_id, "is_starred": item.is_starred}), 200


@radar_bp.route("/web/item/<int:item_id>/read", methods=["POST"])
@web_login_required
def web_toggle_read(item_id):
    item = FeedItem.query.get(item_id)
    if not item:
        return jsonify({"error": "Not found"}), 404
    item.is_read = not item.is_read
    db.session.commit()
    return jsonify({"id": item_id, "is_read": item.is_read}), 200


# ─────────────────────────────────────────────────────────────────────────────
# F1: Full article content
# ─────────────────────────────────────────────────────────────────────────────


@radar_bp.route("/web/item/<int:item_id>/full", methods=["GET"])
@web_login_required
def web_item_full(item_id):
    item = FeedItem.query.get(item_id)
    if not item:
        return jsonify({"error": "Not found"}), 404
    feed_names = {f.id: f.name for f in RSSFeed.query.all()}
    return jsonify({
        "id": item.id,
        "title": item.title,
        "content_html": item.content_html or item.summary or "",
        "link": item.link,
        "published": item.published.isoformat() if item.published else None,
        "feed_name": feed_names.get(item.feed_id, "Unknown"),
        "severity": item.severity,
        "tags": item.tags,
        "iocs": item.iocs,
    }), 200


# ─────────────────────────────────────────────────────────────────────────────
# F6: Related items
# ─────────────────────────────────────────────────────────────────────────────


@radar_bp.route("/web/item/<int:item_id>/related", methods=["GET"])
@web_login_required
def web_item_related(item_id):
    item = FeedItem.query.get(item_id)
    if not item:
        return jsonify({"error": "Not found"}), 404

    strong_tag_whitelist = {
        "ransomware", "phishing", "apt", "zero-day", "supply-chain",
        "data-breach", "botnet", "ddos",
    }

    related_scores = {}  # id -> score
    feed_names = {f.id: f.name for f in RSSFeed.query.all()}

    iocs = item.iocs
    item_cves = set(iocs.get("cves", []))
    item_ips = set(iocs.get("ips", []))
    item_domains = set(iocs.get("domains", []))
    item_hashes = set(iocs.get("hashes", []))
    item_tags_set = set(item.tags)
    strong_tags = item_tags_set & strong_tag_whitelist

    # Match by shared CVEs (strongest signal)
    for cve in iocs.get("cves", [])[:8]:
        for m in FeedItem.query.filter(FeedItem.id != item_id, FeedItem.iocs_json.contains(cve)).limit(5).all():
            related_scores[m.id] = related_scores.get(m.id, 0) + 10

    # Match by shared IPs/domains/hashes
    for ioc_type in ("ips", "domains", "hashes"):
        for val in iocs.get(ioc_type, [])[:5]:
            for m in FeedItem.query.filter(FeedItem.id != item_id, FeedItem.iocs_json.contains(val)).limit(3).all():
                related_scores[m.id] = related_scores.get(m.id, 0) + 6

    # Match only by strong threat-family tags, not generic tags or title keywords.
    for tag in list(strong_tags)[:5]:
        for m in FeedItem.query.filter(FeedItem.id != item_id, FeedItem.tags_json.contains(f'"{tag}"')).order_by(FeedItem.published.desc()).limit(5).all():
            related_scores[m.id] = related_scores.get(m.id, 0) + 4

    if not related_scores:
        return jsonify({"related": []}), 200

    candidate_ids = list(related_scores.keys())
    related = FeedItem.query.filter(FeedItem.id.in_(candidate_ids)).all()

    ranked = []
    for r in related:
        r_iocs = r.iocs
        shared_cves = sorted(item_cves & set(r_iocs.get("cves", [])))[:3]
        shared_ips = sorted(item_ips & set(r_iocs.get("ips", [])))[:2]
        shared_domains = sorted(item_domains & set(r_iocs.get("domains", [])))[:2]
        shared_hashes = sorted(item_hashes & set(r_iocs.get("hashes", [])))[:2]
        shared_tags = sorted((item_tags_set & set(r.tags)) & strong_tag_whitelist)[:3]

        strong_signal_count = int(bool(shared_cves)) + int(bool(shared_ips or shared_domains or shared_hashes)) + int(bool(shared_tags))
        score = related_scores.get(r.id, 0)

        # Require an actual strong relationship: either a shared IOC/CVE,
        # or multiple strong tags with enough score to matter.
        if not (shared_cves or shared_ips or shared_domains or shared_hashes or (len(shared_tags) >= 2 and score >= 8)):
            continue
        if score < 8:
            continue

        reason_parts = []
        if shared_cves:
            reason_parts.append("shared CVE: " + ", ".join(shared_cves))
        if shared_ips:
            reason_parts.append("shared IP: " + ", ".join(shared_ips))
        if shared_domains:
            reason_parts.append("shared domain: " + ", ".join(shared_domains))
        if shared_hashes:
            reason_parts.append("shared hash: " + ", ".join(shared_hashes))
        if shared_tags:
            reason_parts.append("shared tag: " + ", ".join(shared_tags))

        ranked.append((score, strong_signal_count, r.published or datetime.min, r, " · ".join(reason_parts)))

    ranked.sort(key=lambda row: (row[0], row[1], row[2]), reverse=True)
    if not ranked:
        return jsonify({"related": []}), 200

    results = []
    for score, _signal_count, _published, r, reason in ranked[:6]:
        results.append({
            "id": r.id,
            "title": r.title,
            "link": r.link,
            "severity": r.severity,
            "published": r.published.isoformat() if r.published else None,
            "feed_name": feed_names.get(r.feed_id, "Unknown"),
            "tags": r.tags,
            "summary": (r.summary or "")[:200],
            "reason": reason,
            "score": score,
        })

    return jsonify({"related": results}), 200


# ─────────────────────────────────────────────────────────────────────────────
# U2: New items count since timestamp
# ─────────────────────────────────────────────────────────────────────────────


@radar_bp.route("/web/new-count", methods=["GET"])
@web_login_required
def web_new_count():
    from datetime import datetime as _dt
    since_str = request.args.get("since", "")
    if not since_str:
        return jsonify({"count": 0}), 200
    try:
        since = _dt.fromisoformat(since_str.replace("Z", "+00:00").replace("+00:00", ""))
    except (ValueError, TypeError):
        return jsonify({"count": 0}), 200
    count = FeedItem.query.filter(FeedItem.created_at > since).count()
    return jsonify({"count": count}), 200


# ─────────────────────────────────────────────────────────────────────────────
# Authentication
# ─────────────────────────────────────────────────────────────────────────────

_LOGIN_RATE_LIMIT = 10


@radar_bp.route("/login", methods=["GET", "POST"])
def login():
    if "site_user_id" in session:
        return redirect(url_for("radar.index"))

    error = None
    if request.method == "POST":
        if _is_rate_limited(request.remote_addr, limit=_LOGIN_RATE_LIMIT):
            error = "Too many login attempts. Please wait a moment and try again."
            return render_template("login.html", error=error), 429

        username = request.form.get("username", "").strip()[:80]
        password = request.form.get("password", "")

        user = SiteUser.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session.clear()
            session.permanent = True
            session["site_user_id"] = user.id
            session["site_username"] = user.username
            session["site_role"] = user.role
            logger.info(f"Successful login: user={username} role={user.role} ip={request.remote_addr}")

            # Remove first-boot credentials file on successful login
            _creds_file = "/data/first_boot_credentials.txt"
            try:
                if os.path.exists(_creds_file):
                    os.remove(_creds_file)
                    logger.info("First-boot credentials file removed after successful login.")
            except OSError:
                pass

            return redirect(url_for("radar.index"))

        logger.warning(f"Failed login attempt: ip={request.remote_addr}")
        error = "Invalid username or password."

    return render_template("login.html", error=error)


@radar_bp.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    response = redirect(url_for("radar.login"))
    # Prevent caching of authenticated pages after logout
    response.headers["Clear-Site-Data"] = '"cache", "storage"'
    return response


# ─────────────────────────────────────────────────────────────────────────────
# Dashboard (analytics page)
# ─────────────────────────────────────────────────────────────────────────────


@radar_bp.route("/dashboard", methods=["GET"])
@web_login_required
def dashboard():
    return render_template("dashboard.html")


# ─────────────────────────────────────────────────────────────────────────────
# Settings
# ─────────────────────────────────────────────────────────────────────────────

_SETTINGS_RATE_LIMIT = 10


@radar_bp.route("/settings", methods=["GET", "POST"])
@web_login_required
def settings():
    user = SiteUser.query.get(session["site_user_id"])

    if request.method == "POST":
        if _is_rate_limited(request.remote_addr, limit=_SETTINGS_RATE_LIMIT, bucket="settings"):
            flash("Too many requests. Please wait a moment and try again.", "error")
            return redirect(url_for("radar.settings")), 429

        new_username = request.form.get("username", "").strip()[:80]
        new_password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        errors = []

        if not new_username:
            errors.append("Username cannot be empty.")
        elif new_username != user.username:
            if SiteUser.query.filter_by(username=new_username).first():
                errors.append("That username is already taken.")

        if new_password:
            if new_password != confirm:
                errors.append("Passwords do not match.")
            else:
                errors.extend(validate_password_strength(new_password))

        if errors:
            for e in errors:
                flash(e, "error")
        else:
            user.username = new_username
            if new_password:
                user.set_password(new_password)
                logger.warning(f"Password changed for user id={user.id} ip={request.remote_addr}")
            db.session.commit()
            session["site_username"] = new_username
            flash("Settings saved successfully.", "success")
            return redirect(url_for("radar.settings"))

    return render_template(
        "settings.html",
        current_username=user.username,
        min_password_len=12,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Database backup / export / import
# ─────────────────────────────────────────────────────────────────────────────

_DB_PATH = "/data/database.db"
_BACKUP_DIR = "/data/backups"
_MAX_IMPORT_BYTES = 50 * 1024 * 1024


@radar_bp.route("/backup/export", methods=["GET"])
@require_admin
def backup_export():
    from datetime import datetime as _dt
    timestamp = _dt.utcnow().strftime("%Y%m%d-%H%M%S")
    filename = f"hawkradar-backup-{timestamp}.db"

    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    try:
        src = sqlite3.connect(_DB_PATH)
        dst = sqlite3.connect(tmp.name)
        try:
            src.backup(dst)
        finally:
            dst.close()
            src.close()
        logger.warning(f"DB exported by session user {session.get('site_user_id')}")
        return send_file(
            tmp.name,
            as_attachment=True,
            download_name=filename,
            mimetype="application/x-sqlite3",
        )
    except Exception as exc:
        os.unlink(tmp.name)
        logger.error(f"DB export failed: {exc}")
        flash("Export failed. See server logs.", "error")
        return redirect(url_for("radar.settings"))


@radar_bp.route("/backup/run", methods=["POST"])
@require_admin
def backup_run():
    from app import run_backup
    try:
        path = run_backup()
        fname = os.path.basename(path)
        size_kb = round(os.path.getsize(path) / 1024, 1)
        flash(f"Backup saved: {fname} ({size_kb} KB)", "success")
        logger.warning(f"Manual backup triggered by session user {session.get('site_user_id')}: {path}")
    except Exception as exc:
        logger.error(f"Manual backup failed: {exc}")
        flash(f"Backup failed: {exc}", "error")
    return redirect(url_for("radar.settings"))


@radar_bp.route("/backup/import", methods=["POST"])
@require_admin
def backup_import():
    uploaded = request.files.get("db_file")
    if not uploaded or not uploaded.filename:
        flash("No file selected.", "error")
        return redirect(url_for("radar.settings"))

    if not uploaded.filename.endswith(".db"):
        flash("Invalid file type. Only .db files are accepted.", "error")
        return redirect(url_for("radar.settings"))

    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    try:
        chunk_size = 64 * 1024
        total = 0
        while True:
            chunk = uploaded.stream.read(chunk_size)
            if not chunk:
                break
            total += len(chunk)
            if total > _MAX_IMPORT_BYTES:
                raise ValueError(f"Upload exceeds {_MAX_IMPORT_BYTES // (1024*1024)} MB limit")
            tmp.write(chunk)
        tmp.close()

        conn = sqlite3.connect(tmp.name)
        try:
            tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        finally:
            conn.close()

        required = {"site_users"}
        missing = required - {t.lower() for t in tables}
        if missing:
            raise ValueError(f"Uploaded file is missing required tables: {missing}")

        from app import run_backup
        try:
            run_backup()
        except Exception as exc:
            logger.warning(f"Pre-import backup failed (continuing anyway): {exc}")

        shutil.copyfile(tmp.name, _DB_PATH)
        logger.warning(
            f"DB restored from upload by session user {session.get('site_user_id')} "
            f"({total} bytes, tables: {tables})"
        )
        flash("Database restored successfully. Please log in again.", "success")
        session.clear()
        return redirect(url_for("radar.login"))

    except Exception as exc:
        logger.error(f"DB import failed: {exc}")
        flash(f"Import failed: {exc}", "error")
        return redirect(url_for("radar.settings"))
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass


@radar_bp.route("/backup/list", methods=["GET"])
@require_admin
def backup_list():
    try:
        files = []
        if os.path.isdir(_BACKUP_DIR):
            for fname in sorted(os.listdir(_BACKUP_DIR), reverse=True):
                if fname.startswith("database-") and fname.endswith(".db"):
                    fpath = os.path.join(_BACKUP_DIR, fname)
                    files.append({
                        "name": fname,
                        "size_kb": round(os.path.getsize(fpath) / 1024, 1),
                    })
        return jsonify({"backups": files})
    except Exception as exc:
        logger.exception("backup_list failed")
        return jsonify({"error": "Internal server error"}), 500


# ─────────────────────────────────────────────────────────────────────────────
# Admin — User Management
# ─────────────────────────────────────────────────────────────────────────────


@radar_bp.route("/admin", methods=["GET"])
@require_admin
def admin_panel():
    users = SiteUser.query.order_by(SiteUser.created_at.desc()).all()
    feeds = RSSFeed.query.order_by(RSSFeed.name).all()
    return render_template("admin.html", users=users, feeds=feeds)


@radar_bp.route("/admin/create", methods=["POST"])
@require_admin
def admin_create_user():
    username = request.form.get("username", "").strip()[:80]
    password = request.form.get("password", "")
    role = request.form.get("role", "analyst").strip()

    if role not in ("admin", "analyst"):
        role = "analyst"

    errors = []
    if not username:
        errors.append("Username cannot be empty.")
    elif SiteUser.query.filter_by(username=username).first():
        errors.append("Username already taken.")

    if not password:
        errors.append("Password is required.")
    else:
        errors.extend(validate_password_strength(password))

    if errors:
        for e in errors:
            flash(e, "error")
    else:
        new_user = SiteUser(username=username, role=role)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash(f"User '{username}' created as {role}.", "success")
        logger.info(f"Admin {session.get('site_username')} created user '{username}' (role={role})")

    return redirect(url_for("radar.admin_panel"))


@radar_bp.route("/admin/delete/<int:user_id>", methods=["POST"])
@require_admin
def admin_delete_user(user_id):
    if user_id == session.get("site_user_id"):
        flash("You cannot delete your own account.", "error")
        return redirect(url_for("radar.admin_panel"))

    user = SiteUser.query.get(user_id)
    if not user:
        flash("User not found.", "error")
    else:
        username = user.username
        db.session.delete(user)
        db.session.commit()
        flash(f"User '{username}' deleted.", "success")
        logger.warning(f"Admin {session.get('site_username')} deleted user '{username}' id={user_id}")

    return redirect(url_for("radar.admin_panel"))


@radar_bp.route("/admin/toggle-role/<int:user_id>", methods=["POST"])
@require_admin
def admin_toggle_role(user_id):
    if user_id == session.get("site_user_id"):
        flash("You cannot change your own role.", "error")
        return redirect(url_for("radar.admin_panel"))

    user = SiteUser.query.get(user_id)
    if not user:
        flash("User not found.", "error")
    else:
        user.role = "analyst" if user.role == "admin" else "admin"
        db.session.commit()
        flash(f"User '{user.username}' is now {user.role}.", "success")
        logger.info(f"Admin {session.get('site_username')} changed role of '{user.username}' to {user.role}")

    return redirect(url_for("radar.admin_panel"))


# ─────────────────────────────────────────────────────────────────────────────
# Admin — Feed Management
# ─────────────────────────────────────────────────────────────────────────────


@radar_bp.route("/admin/feed/add", methods=["POST"])
@require_admin
def admin_add_feed():
    name = request.form.get("feed_name", "").strip()[:200]
    url = request.form.get("feed_url", "").strip()[:2048]
    category = request.form.get("feed_category", "News").strip()[:50]

    errors = []
    if not name:
        errors.append("Feed name cannot be empty.")
    if not url:
        errors.append("Feed URL cannot be empty.")
    elif not url.startswith(("http://", "https://")):
        errors.append("Feed URL must start with http:// or https://")
    else:
        # SSRF protection: block private/internal IPs and hostnames
        from urllib.parse import urlparse
        import ipaddress
        import socket
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        blocked = False
        # Block common internal hostnames
        if hostname in ("localhost", "127.0.0.1", "0.0.0.0", "[::1]", ""):
            blocked = True
        elif hostname.endswith(".local") or hostname.endswith(".internal"):
            blocked = True
        else:
            # Try resolving and check if IP is private
            try:
                resolved = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
                for _family, _type, _proto, _canonname, sockaddr in resolved:
                    ip = ipaddress.ip_address(sockaddr[0])
                    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                        blocked = True
                        break
            except (socket.gaierror, ValueError):
                pass  # DNS resolution failure — allow, feedparser will handle the error

        if blocked:
            errors.append("Feed URL must not point to internal or private network addresses.")
        elif RSSFeed.query.filter_by(url=url).first():
            errors.append("A feed with this URL already exists.")

    if errors:
        for e in errors:
            flash(e, "error")
    else:
        feed = RSSFeed(name=name, url=url, category=category, enabled=True)
        db.session.add(feed)
        db.session.commit()
        flash(f"Feed '{name}' added.", "success")
        logger.info(f"Admin {session.get('site_username')} added feed '{name}' ({url})")

    return redirect(url_for("radar.admin_panel"))


@radar_bp.route("/admin/feed/<int:feed_id>/toggle", methods=["POST"])
@require_admin
def admin_toggle_feed(feed_id):
    feed = RSSFeed.query.get(feed_id)
    if not feed:
        flash("Feed not found.", "error")
    else:
        feed.enabled = not feed.enabled
        db.session.commit()
        state = "enabled" if feed.enabled else "disabled"
        flash(f"Feed '{feed.name}' {state}.", "success")
        logger.info(f"Admin {session.get('site_username')} {state} feed '{feed.name}'")

    return redirect(url_for("radar.admin_panel"))


@radar_bp.route("/admin/feed/<int:feed_id>/delete", methods=["POST"])
@require_admin
def admin_delete_feed(feed_id):
    feed = RSSFeed.query.get(feed_id)
    if not feed:
        flash("Feed not found.", "error")
    else:
        name = feed.name
        db.session.delete(feed)
        db.session.commit()
        flash(f"Feed '{name}' and all its items deleted.", "success")
        logger.warning(f"Admin {session.get('site_username')} deleted feed '{name}' id={feed_id}")

    return redirect(url_for("radar.admin_panel"))
