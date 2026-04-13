import logging
import re
import threading
from datetime import datetime, timezone
from html import unescape
from urllib.parse import urlparse

import feedparser
from bs4 import BeautifulSoup

from .models import db, RSSFeed, FeedItem

logger = logging.getLogger(__name__)

_refresh_lock = threading.Lock()

# ─────────────────────────────────────────────────────────────────────────────
# IOC extraction patterns
# ─────────────────────────────────────────────────────────────────────────────

_IPV4_RE = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)
_DOMAIN_RE = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|de|uk|ru|cn|info|biz|xyz|top|club|online|site|co|gov|edu|mil)\b',
    re.IGNORECASE,
)
_CVE_RE = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)
_MD5_RE = re.compile(r'\b[a-fA-F0-9]{32}\b')
_SHA1_RE = re.compile(r'\b[a-fA-F0-9]{40}\b')
_SHA256_RE = re.compile(r'\b[a-fA-F0-9]{64}\b')

# Common false-positive domains for IOC extraction
_FP_DOMAINS = {
    'www.w3.org', 'schema.org', 'xmlns.com', 'purl.org',
    'fonts.googleapis.com', 'fonts.gstatic.com', 'cdn.jsdelivr.net',
    'example.com', 'example.org', 'example.net',
}

_COMMON_BENIGN_DOMAINS = {
    'cisa.gov', 'nist.gov', 'dfn-cert.de', 'bsi.bund.de', 'heise.de',
    'crowdstrike.com', 'talosintelligence.com', 'bleepingcomputer.com',
    'thehackernews.com', 'krebsonsecurity.com', 'sans.org', 'sans.edu',
    'exploit-db.com', 'github.com', 'microsoft.com', 'google.com',
    'youtube.com', 'twitter.com', 'x.com', 'facebook.com', 'linkedin.com',
}

_SUSPICIOUS_DOMAIN_TLDS = {'ru', 'cn', 'top', 'xyz', 'club', 'online', 'site', 'biz', 'info'}
_DOMAIN_CONTEXT_KEYWORDS = {
    'domain', 'domains', 'ioc', 'iocs', 'indicator', 'indicators', 'malicious',
    'phishing', 'c2', 'callback', 'beacon', 'botnet', 'host', 'server',
    'dns', 'resolves', 'redirect', 'payload', 'download', 'contact', 'cnc'
}


def _registrable_domain(hostname: str) -> str:
    host = (hostname or '').lower().strip('.')
    if not host:
        return ''
    parts = host.split('.')
    if len(parts) <= 2:
        return host
    if host.endswith('.co.uk'):
        return '.'.join(parts[-3:])
    return '.'.join(parts[-2:])


def _build_ignored_domains(urls: list[str] | None = None) -> set[str]:
    ignored = set(_FP_DOMAINS)
    ignored.update(_COMMON_BENIGN_DOMAINS)

    for value in urls or []:
        if not value:
            continue
        hostname = urlparse(value).hostname or ''
        hostname = hostname.lower().strip('.')
        if not hostname:
            continue
        ignored.add(hostname)
        ignored.add(_registrable_domain(hostname))

    return {domain for domain in ignored if domain}


def _domain_has_ioc_context(text: str, start: int, end: int, domain: str) -> bool:
    domain_lower = domain.lower()
    if 'xn--' in domain_lower:
        return True

    parts = domain_lower.rsplit('.', 1)
    tld = parts[1] if len(parts) == 2 else ''
    if tld in _SUSPICIOUS_DOMAIN_TLDS:
        return True

    window_start = max(0, start - 80)
    window_end = min(len(text), end + 80)
    context = text[window_start:window_end].lower()
    return any(keyword in context for keyword in _DOMAIN_CONTEXT_KEYWORDS)


def extract_iocs(text: str, ignored_domains: set[str] | None = None) -> dict:
    if not text:
        return {"ips": [], "domains": [], "cves": [], "hashes": []}

    ips = list(set(_IPV4_RE.findall(text)))
    # Filter private/loopback IPs
    ips = [ip for ip in ips if not ip.startswith(('10.', '127.', '0.', '192.168.', '169.254.'))]

    ignored_domains = {domain.lower() for domain in (ignored_domains or set())}
    filtered_domains = []
    for match in _DOMAIN_RE.finditer(text):
        domain_lower = match.group(0).lower().strip('.')
        if not domain_lower:
            continue
        if domain_lower.startswith('www.'):
            continue
        domain_root = _registrable_domain(domain_lower)
        if domain_lower in ignored_domains or domain_root in ignored_domains:
            continue
        if not _domain_has_ioc_context(text, match.start(), match.end(), domain_lower):
            continue
        filtered_domains.append(domain_lower)
    domains = filtered_domains
    # Deduplicate case-insensitive
    domains = list(set(domains))

    cves = list(set(m.upper() for m in _CVE_RE.findall(text)))

    hashes = []
    hashes.extend(list(set(_SHA256_RE.findall(text))))
    hashes.extend(list(set(_SHA1_RE.findall(text))))
    hashes.extend(list(set(_MD5_RE.findall(text))))
    # Deduplicate (SHA256 substrings may match shorter patterns)
    seen = set()
    unique_hashes = []
    for h in hashes:
        h_lower = h.lower()
        if h_lower not in seen:
            seen.add(h_lower)
            unique_hashes.append(h_lower)
    hashes = unique_hashes

    return {"ips": ips[:50], "domains": domains[:50], "cves": cves[:50], "hashes": hashes[:50]}


# ─────────────────────────────────────────────────────────────────────────────
# Tag extraction
# ─────────────────────────────────────────────────────────────────────────────

_TAG_KEYWORDS = {
    "ransomware": ["ransomware", "ransom", "lockbit", "blackcat", "clop", "akira", "rhysida"],
    "phishing": ["phishing", "spear-phishing", "credential harvest", "fake login"],
    "apt": ["apt-", "advanced persistent threat", "state-sponsored", "nation-state", "apt28", "apt29", "lazarus", "cozy bear", "fancy bear"],
    "zero-day": ["zero-day", "0-day", "zero day", "zeroday"],
    "malware": ["malware", "trojan", "backdoor", "rootkit", "worm", "spyware", "infostealer", "stealer", "rat "],
    "ddos": ["ddos", "denial of service", "distributed denial"],
    "supply-chain": ["supply chain", "supply-chain", "solarwinds", "codecov"],
    "cve": ["cve-"],
    "exploit": ["exploit", "proof of concept", "poc", "rce", "remote code execution"],
    "vulnerability": ["vulnerability", "vulnerabilities", "patch", "security update", "security advisory"],
    "data-breach": ["data breach", "data leak", "leaked", "exposed data", "compromised data"],
    "botnet": ["botnet", "bot net", "command and control", "c2 server"],
}


def extract_tags(title: str, summary: str) -> list[str]:
    combined = f"{title} {summary}".lower()
    tags = []
    for tag, keywords in _TAG_KEYWORDS.items():
        if any(kw in combined for kw in keywords):
            tags.append(tag)
    return tags


# ─────────────────────────────────────────────────────────────────────────────
# Severity classification
# ─────────────────────────────────────────────────────────────────────────────

_CRITICAL_KEYWORDS = [
    "critical", "emergency", "actively exploited", "active exploitation",
    "zero-day", "0-day", "rce", "remote code execution", "unauthenticated",
    "wormable", "cvss 9", "cvss 10", "severity: critical",
]
_HIGH_KEYWORDS = [
    "high", "exploit", "ransomware", "vulnerability", "patch now",
    "security update", "malware", "backdoor", "data breach",
    "privilege escalation", "code execution", "cvss 7", "cvss 8",
]
_MEDIUM_KEYWORDS = [
    "medium", "moderate", "advisory", "update available",
    "phishing", "social engineering", "information disclosure",
    "denial of service", "cvss 4", "cvss 5", "cvss 6",
]
_LOW_KEYWORDS = [
    "low", "informational", "best practice", "guidance",
    "awareness", "training", "cvss 1", "cvss 2", "cvss 3",
]

_SECURITY_SIGNAL_KEYWORDS = [
    "security advisory", "security bulletin", "incident response", "threat",
    "schwachstelle", "schwachstellen", "angriff", "ausfuhren beliebigen programmcodes",
    "denial-of-service-angriff", "eskalation von privilegien", "umgehen von sicherheitsvorkehrungen",
]

_STRONG_TAGS = {"ransomware", "apt", "zero-day", "data-breach", "botnet", "exploit"}
_MEDIUM_TAGS = {"phishing", "ddos", "supply-chain", "vulnerability", "cve", "malware"}


def classify_severity(title: str, summary: str, tags: list[str] | None = None, iocs: dict | None = None) -> str:
    combined = f"{title} {summary}".lower()
    if any(kw in combined for kw in _CRITICAL_KEYWORDS):
        return "critical"
    if any(kw in combined for kw in _HIGH_KEYWORDS):
        return "high"
    if any(kw in combined for kw in _MEDIUM_KEYWORDS):
        return "medium"
    if any(kw in combined for kw in _LOW_KEYWORDS):
        return "low"

    tags = tags or []
    iocs = iocs or {"ips": [], "domains": [], "cves": [], "hashes": []}

    # Fallback scoring to reduce "unknown" when article has security indicators.
    score = 0
    cve_count = len(iocs.get("cves", []))
    ioc_count = len(iocs.get("ips", [])) + len(iocs.get("domains", [])) + len(iocs.get("hashes", []))

    if cve_count:
        score += min(cve_count * 3, 6)
    if ioc_count:
        score += min(ioc_count, 4)

    tag_set = set(tags)
    if tag_set & _STRONG_TAGS:
        score += 3
    if tag_set & _MEDIUM_TAGS:
        score += 2

    if any(kw in combined for kw in _SECURITY_SIGNAL_KEYWORDS):
        score += 2

    if score >= 8:
        return "high"
    if score >= 4:
        return "medium"
    if score >= 2:
        return "low"
    return "unknown"


# ─────────────────────────────────────────────────────────────────────────────
# Feed parsing
# ─────────────────────────────────────────────────────────────────────────────

def _strip_html(html_text: str) -> str:
    if not html_text:
        return ""
    soup = BeautifulSoup(html_text, "html.parser")
    return unescape(soup.get_text(separator=" ", strip=True))


def _parse_date(entry) -> datetime | None:
    for field in ("published_parsed", "updated_parsed"):
        parsed = getattr(entry, field, None)
        if parsed:
            try:
                from time import mktime
                return datetime.fromtimestamp(mktime(parsed), tz=timezone.utc).replace(tzinfo=None)
            except Exception:
                continue
    return None


def fetch_feed(feed: RSSFeed) -> int:
    """Fetch and parse a single RSS feed. Returns count of new items added."""
    logger.info(f"Fetching feed: {feed.name} ({feed.url})")
    new_count = 0

    try:
        parsed = feedparser.parse(feed.url)

        if parsed.bozo and not parsed.entries:
            error_msg = str(getattr(parsed, 'bozo_exception', 'Unknown parse error'))
            feed.last_error = error_msg[:500]
            feed.last_fetched = datetime.utcnow()
            db.session.commit()
            logger.warning(f"Feed parse error for {feed.name}: {error_msg[:200]}")
            return 0

        for entry in parsed.entries:
            guid = entry.get("id") or entry.get("link") or entry.get("title", "")
            if not guid:
                continue

            # Skip if already exists
            existing = FeedItem.query.filter_by(feed_id=feed.id, guid=guid[:2048]).first()
            if existing:
                continue

            title = entry.get("title", "Untitled")[:2000]
            link = entry.get("link", "")[:2048]
            published = _parse_date(entry)

            # Get content — prefer content:encoded, then summary
            content_html = ""
            if hasattr(entry, "content") and entry.content:
                content_html = entry.content[0].get("value", "")
            elif hasattr(entry, "summary"):
                content_html = entry.summary or ""

            summary_text = _strip_html(content_html)[:5000] if content_html else ""
            if not summary_text and hasattr(entry, "summary"):
                summary_text = _strip_html(entry.summary or "")[:5000]

            # Classify and extract
            tags = extract_tags(title, summary_text)
            ignored_domains = _build_ignored_domains([feed.url, link])
            iocs = extract_iocs(f"{title} {summary_text}", ignored_domains=ignored_domains)
            severity = classify_severity(title, summary_text, tags=tags, iocs=iocs)

            item = FeedItem(
                feed_id=feed.id,
                guid=guid[:2048],
                title=title,
                link=link,
                published=published or datetime.utcnow(),
                summary=summary_text[:5000],
                content_html=content_html[:50000] if content_html else None,
                severity=severity,
            )
            item.tags = tags
            item.iocs = iocs

            db.session.add(item)
            new_count += 1

        feed.last_fetched = datetime.utcnow()
        feed.last_error = None
        db.session.commit()
        logger.info(f"Feed {feed.name}: {new_count} new items")

    except Exception as exc:
        db.session.rollback()
        try:
            feed.last_error = str(exc)[:500]
            feed.last_fetched = datetime.utcnow()
            db.session.commit()
        except Exception:
            db.session.rollback()
        logger.exception(f"Error fetching feed {feed.name}")

    return new_count


def refresh_all_feeds() -> dict:
    """Refresh all enabled feeds. Returns summary stats."""
    with _refresh_lock:
        feeds = RSSFeed.query.filter_by(enabled=True).all()
        total_new = 0
        errors = 0
        for feed in feeds:
            try:
                count = fetch_feed(feed)
                total_new += count
            except Exception as exc:
                errors += 1
                logger.warning(f"Feed refresh error for {feed.name}: {exc}")

        logger.info(f"Feed refresh complete: {len(feeds)} feeds, {total_new} new items, {errors} errors")
        return {"feeds_checked": len(feeds), "new_items": total_new, "errors": errors}
