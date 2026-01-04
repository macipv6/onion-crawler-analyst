#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Onion Crawler – erweitert (mit Forensik, Media-Reporting, CTI-Features)
- Tor (SOCKS5h), robots.txt
- OpenSearch Index (Textauszug, Sprache, Hash) + erweiterte Metadaten
- Renderer (safe; Skip bei Risiko/Blocklist) – optional
- Foren-Login-Crawler (Links sammeln) – separat in forum_crawler.py
- Links-Persistenz (SQLite + JSON); Clearnet-Links speicherbar; optionales Clearnet-Crawling per ENV
- Neo4j: Rich Graph (optional)
- Media-Links: zusätzlich JSONL + SQLite + optional OpenSearch
- Indicator-Store (Wallets, PGP), STIX-Export, Alerts, Stats, Template-FP, Contacts
- Import von data_copy/links_*.json in OpenSearch (Links-Index) und Neo4j
"""
import os
import re
import time
import json
import hashlib
import sqlite3
from pathlib import Path
from urllib.parse import urlparse, urljoin

import requests
import yaml
import tldextract
from bs4 import BeautifulSoup
from langdetect import detect, LangDetectException
from opensearchpy import OpenSearch

# Forensik-Helfer (optional)
import forensic

try:
    from robotexclusionrulesparser import RobotExclusionRulesParser
except Exception:
    RobotExclusionRulesParser = None

# -------- Heuristics / Regex --------
RE_BTC = re.compile(r'\b(bc1[0-9a-zA-Z]{8,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b')
RE_ETH = re.compile(r'\b0x[a-fA-F0-9]{40}\b')
RE_XMR = re.compile(r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b')
RE_PGP = re.compile(r'-----BEGIN PGP PUBLIC KEY BLOCK-----.*?-----END PGP PUBLIC KEY BLOCK-----', re.S)
RE_USERNAME = re.compile(r'@([a-zA-Z0-9_]{3,32})')

TOPIC_KEYWORDS = {
    "drugs":   ["weed", "cocaine", "lsd", "mdma", "psychedelic"],
    "fraud":   ["cvv", "fullz", "dump", "skimmer", "cashout"],
    "exploit": ["exploit", "0day", "rce", "cve", "shellcode"],
    "market":  ["market", "escrow", "vendor", "listing"],
    "crypto":  ["bitcoin", "monero", "ethereum", "wallet"],
    "forum":   ["thread", "sticky", "moderator", "ban", "pm"],
}


def classify_topics(text: str) -> list[str]:
    t = (text or "").lower()
    return sorted({k for k, kws in TOPIC_KEYWORDS.items() if any(w in t for w in kws)})


def find_wallets(text: str):
    return {
        "BTC": list(set(RE_BTC.findall(text or ""))),
        "ETH": list(set(RE_ETH.findall(text or ""))),
        "XMR": list(set(RE_XMR.findall(text or ""))),
    }


def find_pgp_keys(text: str):
    return RE_PGP.findall(text or "")


def guess_mirrors(url: str, links: set[str]):
    ext = tldextract.extract(url)
    root = f"{ext.domain}"
    mirrors = []
    for l in links:
        e = tldextract.extract(l)
        if e.domain == root and (e.suffix != ext.suffix or e.subdomain != ext.subdomain):
            mirrors.append(l)
    return list(set(mirrors))


# -------- ENV --------
TOR_SOCKS_HOST = os.getenv("TOR_SOCKS_HOST", "tor")
TOR_SOCKS_PORT = int(os.getenv("TOR_SOCKS_PORT", "9050"))

OS_HOSTS = [h.strip() for h in os.getenv("OS_HOST", "http://opensearch:9200").split(",") if h.strip()]
OS_INDEX = os.getenv("OS_INDEX", "onion_pages")
OS_USERNAME = os.getenv("OS_USERNAME")
OS_PASSWORD = os.getenv("OS_PASSWORD")

# Media-Reporting
MEDIA_REPORT_ENABLE = os.getenv("MEDIA_REPORT_ENABLE", "true").lower() == "true"
OS_MEDIA_INDEX = os.getenv("OS_MEDIA_INDEX", "onion_media_links")

# Links-Index für importierte/zusätzliche Linkdaten
OS_LINKS_INDEX = os.getenv("OS_LINKS_INDEX", "onion_links")

RENDER_URL = os.getenv("RENDERER_URL", "http://renderer:8080").rstrip("/")
RENDER_ENABLE = os.getenv("RENDER_ENABLE", "true").lower() == "true"
RENDER_MODE = os.getenv("RENDER_MODE", "safe")
RENDER_SKIP_ON_RISK = os.getenv("RENDER_SKIP_ON_RISK", "true").lower() == "true"
RISK_RENDER_THRESHOLD = int(os.getenv("RISK_RENDER_THRESHOLD", "60"))
RENDER_BLOCKLIST = os.getenv("RENDER_BLOCKLIST", "")

MAX_PAGES = int(os.getenv("CRAWL_MAX_PAGES", "500"))
MAX_PER_HOST = int(os.getenv("CRAWL_MAX_PER_HOST", "50"))
MAX_DEPTH = int(os.getenv("CRAWL_MAX_DEPTH", "2"))
REQUEST_TIMEOUT = int(os.getenv("CRAWL_REQUEST_TIMEOUT", "60"))
HOST_DELAY = int(os.getenv("CRAWL_HOST_DELAY", "30"))
USER_AGENT = os.getenv("USER_AGENT", "OnionCrawler/0.1 (+legal; login-forums; no-captcha-bypass)")

FORUMS_ENABLE = os.getenv("FORUMS_ENABLE", "false").lower() == "true"
FORUMS_CONFIG = os.getenv("FORUMS_CONFIG", "/app/forums.yaml")

DATA_DIR = Path(os.getenv("DATA_DIR", "/app/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Legacy-Link-Dateien (data_copy/links_*.json)
DATA_COPY_DIR = Path(os.getenv("DATA_COPY_DIR", "data_copy"))
IMPORT_DATA_COPY = os.getenv("IMPORT_DATA_COPY", "true").lower() == "true"

STORE_CLEARNET_LINKS = os.getenv("STORE_CLEARNET_LINKS", "false").lower() == "true"
CRAWL_CLEARNET = os.getenv("CRAWL_CLEARNET", "false").lower() == "true"
_allow = os.getenv("CLEARNET_ALLOWLIST", "").strip()
_deny = os.getenv("CLEARNET_DENYLIST", "").strip()
CLEARNET_ALLOWLIST = {h.strip().lower() for h in _allow.split(",") if h.strip()}
CLEARNET_DENYLIST = {h.strip().lower() for h in _deny.split(",") if h.strip()}

NEO4J_URI = os.getenv("NEO4J_URI")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "neo4j")
NEO4J_ENABLE_SCHEMA_INIT = os.getenv("NEO4J_ENABLE_SCHEMA_INIT", "false").lower() == "true"
try:
    from neo4j_writer import Neo4jWriter
except Exception:
    Neo4jWriter = None

SEEDS_FILE = "seeds.txt"

# -------- Plugins --------
from plugins.favicon import extract_favicon_url, sha256_bytes
from plugins.tls_fingerprint import get_tls_sha256
from plugins.risk import risk_score, compile_patterns

from plugins.classifier import classify_page
from plugins.template_fp import template_fingerprint
from plugins.contact_extractor import extract_contacts
from plugins.indicator_store import upsert_indicators
from plugins.file_analyzer import handle_non_html_response
from plugins.stix_export import export_if_interesting
from plugins.alerts import maybe_alert
from plugins.stats import on_page_indexed, flush as flush_stats

# Media-Link-Erkennung/Recording
RE_MEDIA_PROVIDERS = [
    ("pimpandhost", "image", re.compile(r'^https?://(?:www\.)?pimpandhost\.com/image/[A-Za-z0-9_-]+$', re.I)),
    ("pixhost",     "image", re.compile(r'^https?://(?:www\.)?pixhost\.to/show/\d+/\d+[^/]+\.(?:jpg|jpeg|png|gif|webp)$', re.I)),
    ("jumploads",   "file",  re.compile(r'^https?://(?:www\.)?jumploads\.com/file/[A-Za-z0-9._-]+$', re.I)),
]
RE_MEDIA_EXT = re.compile(r'\.(?:jpg|jpeg|png|gif|webp|mp4|mkv|avi|mov|webm)(?:[?#]|$)', re.I)
MEDIA_FILE_PATH = DATA_DIR / "media_links.jsonl"


def detect_media_provider(url: str):
    for name, cat, rx in RE_MEDIA_PROVIDERS:
        if rx.match(url):
            return name, cat
    if RE_MEDIA_EXT.search(url):
        return "generic", "image_or_video"
    return None, None


# -------- HTTP via Tor --------
S = requests.Session()
proxy = f"socks5h://{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}"
S.proxies = {"http": proxy, "https": proxy}
S.headers.update({"User-Agent": USER_AGENT})

# -------- Frontier (SQLite) --------
os.makedirs("state", exist_ok=True)
DB_PATH = "state/frontier.db"
conn = sqlite3.connect(DB_PATH, check_same_thread=False)
cur = conn.cursor()

cur.execute(
    """CREATE TABLE IF NOT EXISTS urls (
  url TEXT PRIMARY KEY,
  depth INTEGER,
  status TEXT,
  discovered_at INTEGER,
  host TEXT
)"""
)
cur.execute(
    """CREATE TABLE IF NOT EXISTS hosts (
  host TEXT PRIMARY KEY,
  last_fetch INTEGER DEFAULT 0,
  seen_count INTEGER DEFAULT 0
)"""
)
cur.execute(
    """CREATE TABLE IF NOT EXISTS links (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source_url TEXT,
  target_url TEXT,
  context TEXT,
  discovered_at INTEGER
)"""
)

# Media-Links-Tabelle
cur.execute(
    """CREATE TABLE IF NOT EXISTS media_links (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  url TEXT,
  host TEXT,
  provider TEXT,
  category TEXT,
  source_url TEXT,
  discovered_at INTEGER,
  status TEXT DEFAULT 'new'
)"""
)
cur.execute("CREATE INDEX IF NOT EXISTS idx_media_url ON media_links(url)")
cur.execute("CREATE INDEX IF NOT EXISTS idx_media_ts ON media_links(discovered_at)")

# Importierte Legacy-Link-Dateien
cur.execute(
    """CREATE TABLE IF NOT EXISTS imported_files (
  filename TEXT PRIMARY KEY,
  imported_at INTEGER
)"""
)

conn.commit()


def host_of(url: str) -> str:
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def is_onion(url: str) -> bool:
    try:
        return host_of(url).endswith(".onion")
    except Exception:
        return False


def clearnet_allowed(host: str) -> bool:
    if not host:
        return False
    h = host.lower()
    if CLEARNET_DENYLIST and h in CLEARNET_DENYLIST:
        return False
    if CLEARNET_ALLOWLIST:
        return h in CLEARNET_ALLOWLIST
    return True


def normalize_url(base, href):
    try:
        u = urljoin(base, href)
        u = re.sub(r"#.*$", "", u)
        return u
    except Exception:
        return None


def can_fetch_polite(host: str) -> bool:
    now = int(time.time())
    with conn:
        row = conn.execute("SELECT last_fetch FROM hosts WHERE host = ?", (host,)).fetchone()
        last = row[0] if row else 0
        if now - last >= HOST_DELAY:
            conn.execute(
                "INSERT OR IGNORE INTO hosts(host,last_fetch,seen_count) VALUES(?,0,0)",
                (host,),
            )
            conn.execute("UPDATE hosts SET last_fetch=? WHERE host=?", (now, host))
            return True
    return False


def host_seen_count(host: str) -> int:
    row = conn.execute("SELECT seen_count FROM hosts WHERE host=?", (host,)).fetchone()
    return int(row[0]) if row else 0


def inc_host_seen(host: str):
    with conn:
        conn.execute(
            "INSERT OR IGNORE INTO hosts(host,last_fetch,seen_count) VALUES(?,0,0)",
            (host,),
        )
        conn.execute("UPDATE hosts SET seen_count=seen_count+1 WHERE host=?", (host,))


def mark_visited(url, depth, status):
    with conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO urls(url,depth,status,discovered_at,host)
            VALUES (?,?,?,strftime('%s','now'),COALESCE((SELECT host FROM urls WHERE url=?),(?)))
        """,
            (url, depth, status, url, host_of(url)),
        )


def add_seed(url, depth: int = 0):
    if not is_onion(url):
        if not CRAWL_CLEARNET or not clearnet_allowed(host_of(url)):
            return
    with conn:
        conn.execute(
            """
            INSERT OR IGNORE INTO urls(url, depth, status, discovered_at, host)
            VALUES (?, ?, 'queued', strftime('%s','now'), ?)
        """,
            (url, depth, host_of(url)),
        )


def pop_next():
    with conn:
        rows = conn.execute(
            """
            SELECT url, depth, host FROM urls
            WHERE status='queued'
            ORDER BY discovered_at ASC
            LIMIT 200
        """
        ).fetchall()
    for url, depth, host in rows:
        if MAX_PER_HOST > 0 and host_seen_count(host) >= MAX_PER_HOST:
            with conn:
                conn.execute(
                    "UPDATE urls SET status='skipped_hostlimit' WHERE url=?", (url,)
                )
            continue
        if can_fetch_polite(host):
            return url, depth, host
    return None, None, None


# -------- robots.txt --------
_robots_cache = {}


def robots_allowed(url: str, ua: str = USER_AGENT) -> bool:
    if not RobotExclusionRulesParser:
        return True
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if not host:
        return True
    key = f"{parsed.scheme}://{host}"
    entry = _robots_cache.get(key)
    if entry is None:
        robots_url = f"{parsed.scheme}://{host}/robots.txt"
        try:
            r = S.get(robots_url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
            if r.status_code == 200 and "text" in r.headers.get("content-type", "").lower():
                rp = RobotExclusionRulesParser()
                rp.parse(r.text)
                entry = _robots_cache[key] = rp
            elif r.status_code in (403, 401):
                entry = _robots_cache[key] = "deny_all"
            else:
                entry = _robots_cache[key] = "allow_all"
        except Exception:
            entry = _robots_cache[key] = "allow_all"
    if entry == "deny_all":
        return False
    if entry in (None, "allow_all"):
        return True
    try:
        return entry.is_allowed(ua, url)
    except Exception:
        return True


# -------- OpenSearch --------
def build_os_client():
    auth = (OS_USERNAME, OS_PASSWORD) if (OS_USERNAME and OS_PASSWORD) else None
    return OpenSearch(
        hosts=OS_HOSTS,
        http_auth=auth,
        verify_certs=False,
        timeout=30,
        max_retries=5,
        retry_on_timeout=True,
    )


os_client = build_os_client()


def wait_for_opensearch(timeout: int = 180):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            os_client.info()
            print("OpenSearch reachable.")
            return
        except Exception as e:
            print("Waiting for OpenSearch…", type(e).__name__)
            time.sleep(3)
    raise RuntimeError("OpenSearch not reachable")


def ensure_index():
    if not os_client.indices.exists(index=OS_INDEX):
        body = {
            "settings": {"number_of_shards": 1, "number_of_replicas": 0},
            "mappings": {
                "properties": {
                    "url": {"type": "keyword"},
                    "host": {"type": "keyword"},
                    "title": {"type": "text"},
                    "lang": {"type": "keyword"},
                    "extracted_at": {"type": "date"},
                    "hash": {"type": "keyword"},
                    "text": {"type": "text"},
                    "depth": {"type": "integer"},
                    "status": {"type": "integer"},
                    "risk": {"type": "integer"},
                    "render_blocked": {"type": "boolean"},
                    "favicon_hash": {"type": "keyword"},
                    "tls_sha256": {"type": "keyword"},
                    "headers_fp": {"type": "keyword"},
                    "topics": {"type": "keyword"},
                    "tech": {"type": "keyword"},
                    "usernames": {"type": "keyword"},
                    "mirrors": {"type": "keyword"},
                    "links": {"type": "keyword"},
                    "wallets_btc": {"type": "keyword"},
                    "wallets_eth": {"type": "keyword"},
                    "wallets_xmr": {"type": "keyword"},
                    "pgp_fingerprints": {"type": "keyword"},
                    "pgp_count": {"type": "integer"},
                    "preview_path": {"type": "keyword"},
                    "thumbnail_path": {"type": "keyword"},
                    "preview_url": {"type": "keyword"},
                    "thumbnail_url": {"type": "keyword"},
                    "category": {"type": "keyword"},
                    "category_score": {"type": "integer"},
                    "template_fp": {"type": "keyword"},
                    "contacts_email": {"type": "keyword"},
                    "contacts_matrix": {"type": "keyword"},
                    "contacts_jabber": {"type": "keyword"},
                    "contacts_telegram": {"type": "keyword"},
                }
            },
        }
        os_client.indices.create(index=OS_INDEX, body=body)
        print(f"Created index {OS_INDEX}")


def index_doc(doc: dict):
    try:
        os_client.index(index=OS_INDEX, body=doc)
    except Exception as e:
        print("Indexing failed:", type(e).__name__, str(e)[:200])


def ensure_media_index():
    if not OS_MEDIA_INDEX:
        return
    try:
        if not os_client.indices.exists(index=OS_MEDIA_INDEX):
            body = {
                "settings": {"number_of_shards": 1, "number_of_replicas": 0},
                "mappings": {
                    "properties": {
                        "url": {"type": "keyword"},
                        "host": {"type": "keyword"},
                        "provider": {"type": "keyword"},
                        "category": {"type": "keyword"},
                        "source_url": {"type": "keyword"},
                        "detected_at": {"type": "date"},
                    }
                },
            }
            os_client.indices.create(index=OS_MEDIA_INDEX, body=body)
            print(f"Created index {OS_MEDIA_INDEX}")
    except Exception as e:
        print("ensure_media_index failed:", type(e).__name__, str(e)[:200])


def ensure_links_index():
    if not OS_LINKS_INDEX:
        return
    try:
        if not os_client.indices.exists(index=OS_LINKS_INDEX):
            body = {
                "settings": {"number_of_shards": 1, "number_of_replicas": 0},
                "mappings": {
                    "properties": {
                        "source_url": {"type": "keyword"},
                        "target_url": {"type": "keyword"},
                        "context": {"type": "keyword"},
                        "ts": {"type": "date"},
                    }
                },
            }
            os_client.indices.create(index=OS_LINKS_INDEX, body=body)
            print(f"Created index {OS_LINKS_INDEX}")
    except Exception as e:
        print("ensure_links_index failed:", type(e).__name__, str(e)[:200])


def index_link_doc(source_url: str, target_url: str, context: str, ts: int | None):
    if not OS_LINKS_INDEX:
        return
    try:
        doc = {
            "source_url": source_url,
            "target_url": target_url,
            "context": context,
            "ts": ts * 1000 if ts else int(time.time() * 1000),
        }
        os_client.index(index=OS_LINKS_INDEX, body=doc)
    except Exception as e:
        print("link indexing failed:", type(e).__name__, str(e)[:200])


def record_media_links(source: str, links: list[str]):
    if not MEDIA_REPORT_ENABLE:
        return
    now = int(time.time())
    rows, to_index = [], []

    MEDIA_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(MEDIA_FILE_PATH, "a", encoding="utf-8") as f:
            for u in links:
                prov, cat = detect_media_provider(u)
                if not prov:
                    continue
                host = host_of(u)
                rec = {
                    "url": u,
                    "host": host,
                    "provider": prov,
                    "category": cat,
                    "source_url": source,
                    "detected_at": now,
                }
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                rows.append((u, host, prov, cat, source, now))
                to_index.append(
                    {
                        "url": u,
                        "host": host,
                        "provider": prov,
                        "category": cat,
                        "source_url": source,
                        "detected_at": now * 1000,
                    }
                )
    except Exception as e:
        print("write media file failed:", type(e).__name__, str(e)[:120])

    if rows:
        with conn:
            conn.executemany(
                """
                INSERT INTO media_links (url, host, provider, category, source_url, discovered_at)
                VALUES (?,?,?,?,?,?)
            """,
                rows,
            )

    if to_index and OS_MEDIA_INDEX:
        try:
            ensure_media_index()
            for doc in to_index:
                os_client.index(index=OS_MEDIA_INDEX, body=doc)
        except Exception as e:
            print("media index fail:", type(e).__name__, str(e)[:200])


# -------- Persist Links --------
def persist_links(source: str, targets: list[str], context: str = "page", current_depth: int = 0):
    now = int(time.time())
    uniq = [t for t in set(targets) if t.startswith("http")]
    if not uniq:
        return

    # Medien-Links zusätzlich erfassen
    try:
        record_media_links(source, uniq)
    except Exception as e:
        print("record_media_links failed:", type(e).__name__)

    with conn:
        conn.executemany(
            "INSERT INTO links(source_url,target_url,context,discovered_at) VALUES(?,?,?,?)",
            [(source, t, context, now) for t in uniq],
        )
    out = {"source": source, "targets": uniq, "context": context, "ts": now}
    (DATA_DIR / f"links_{now}.json").write_text(
        json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    next_depth = current_depth + 1
    if next_depth <= MAX_DEPTH:
        for t in uniq:
            h = host_of(t)
            enqueue = False
            if is_onion(t):
                enqueue = True
            elif CRAWL_CLEARNET and clearnet_allowed(h):
                enqueue = True
            if enqueue:
                with conn:
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO urls(url, depth, status, discovered_at, host)
                        VALUES (?, ?, 'queued', strftime('%s','now'), ?)
                    """,
                        (t, next_depth, h),
                    )


# -------- Fetch / Extract --------
def fetch(url: str):
    if not robots_allowed(url):
        return None, 451, None, None
    r = S.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)

    try:
        if getattr(forensic, "FORENSIC_ENABLE", False):
            forensic.capture_and_register(url, r, tor_meta={}, db_path=None, extra=None)
    except Exception:
        pass

    ctype = r.headers.get("content-type", "").lower()
    if "text/html" not in ctype:
        # Non-HTML – Metadaten erfassen
        try:
            handle_non_html_response(url, r, os_client=os_client, index_name="onion_files")
        except Exception:
            pass
        return None, r.status_code, None, r.headers

    soup = BeautifulSoup(r.text, "html.parser")
    title = soup.title.string.strip() if soup.title and soup.title.string else ""
    text = soup.get_text(" ", strip=True)
    lang = None
    if text:
        try:
            lang = detect(text)
        except LangDetectException:
            lang = None
    h = hashlib.sha256((text or "").encode("utf-8", "ignore")).hexdigest()
    doc = {
        "url": r.url,
        "host": host_of(r.url),
        "title": title,
        "lang": lang,
        "hash": h,
        "text": (text or "")[:20000],
    }
    return doc, r.status_code, r.text, r.headers


def extract_links(base_url: str, html: str):
    soup = BeautifulSoup(html, "html.parser")
    for a in soup.find_all("a", href=True):
        u = normalize_url(base_url, a["href"])
        if u and u.startswith("http"):
            yield u


def parse_meta_and_body(html: str, base_url: str):
    soup = BeautifulSoup(html, "html.parser")
    links = set()
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if href.startswith("http"):
            links.add(urljoin(base_url, href))
    meta = {
        "generator": (soup.find("meta", attrs={"name": "generator"}) or {}).get("content"),
        "title": (soup.title.string.strip() if soup.title else None),
    }
    body_text = soup.get_text(" ", strip=True)[:200000]
    return links, meta, body_text


# -------- Renderer --------
def render_preview(page_url: str, mode: str):
    if not RENDER_ENABLE:
        return {}
    try:
        r = requests.get(
            f"{RENDER_URL}/shot", params={"url": page_url, "mode": mode}, timeout=90
        )
        if r.status_code == 200:
            j = r.json()
            preview_url = f"{RENDER_URL}/shots/{j.get('file')}"
            thumb = j.get("thumbnail")
            thumb_url = f"{RENDER_URL}/shots/{thumb}" if thumb else None
            return {
                "preview_path": j.get("path"),
                "thumbnail_path": j.get("path").replace(".png", ".thumb.jpg")
                if j.get("path")
                else None,
                "preview_url": preview_url,
                "thumbnail_url": thumb_url,
            }
    except Exception:
        pass
    return {}


# -------- Seeds & Forums --------
def load_seeds():
    if not os.path.exists(SEEDS_FILE):
        print("No seeds.txt found – create it and add legal, public onion URLs.")
        return
    for line in Path(SEEDS_FILE).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        add_seed(line, depth=0)


def forum_login_and_collect():
    if not FORUMS_ENABLE or not os.path.exists(FORUMS_CONFIG):
        return
    try:
        from forum_crawler import run_forums

        socks = f"socks5h://{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}"
        cfg = yaml.safe_load(open(FORUMS_CONFIG, "r", encoding="utf-8"))
        forum_results = run_forums(cfg, socks_url=socks, ua=USER_AGENT)
        for item in forum_results:
            persist_links(
                item["source"], item["links"], context=f"forum:{item['forum']}"
            )
        print(f"Foren: {len(forum_results)} Seiten verarbeitet, Links persistiert.")
    except Exception as e:
        print("Forum-Modul Fehler:", type(e).__name__, str(e)[:200])


# -------- Import von data_copy/links_*.json --------
def import_legacy_links(neo):
    if not IMPORT_DATA_COPY:
        return
    if not DATA_COPY_DIR.exists() or not DATA_COPY_DIR.is_dir():
        return

    ensure_links_index()

    files = sorted(DATA_COPY_DIR.glob("links_*.json"))
    if not files:
        return

    print(f"Importing legacy links from {DATA_COPY_DIR} …")

    for f in files:
        fname = f.name
        row = conn.execute(
            "SELECT 1 FROM imported_files WHERE filename=?", (fname,)
        ).fetchone()
        if row:
            continue  # bereits importiert

        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except Exception as e:
            print("Failed to read legacy links file:", fname, type(e).__name__)
            continue

        source = data.get("source")
        targets = data.get("targets") or []
        context = data.get("context") or "legacy"
        ts = data.get("ts")

        if not source or not isinstance(targets, list):
            print("Legacy file invalid:", fname)
            continue

        # In OpenSearch Links-Index schreiben
        for t in targets:
            if not isinstance(t, str) or not t.startswith("http"):
                continue
            index_link_doc(source, t, context, ts)

        # In Neo4j verknüpfen (falls aktiv)
        if neo and targets:
            try:
                neo.add_links_mixed(source, [t for t in targets if isinstance(t, str)])
            except Exception as e:
                print("Neo4j legacy link import failed:", fname, type(e).__name__)

        with conn:
            conn.execute(
                "INSERT OR IGNORE INTO imported_files(filename, imported_at) VALUES(?,strftime('%s','now'))",
                (fname,),
            )

    print("Legacy link import finished.")


# -------- Main --------
def run():
    load_seeds()
    wait_for_opensearch()
    ensure_index()

    # Neo4j (optional)
    neo = None
    if NEO4J_URI and Neo4jWriter is not None:
        try:
            neo = Neo4jWriter(
                NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD, init_schema=NEO4J_ENABLE_SCHEMA_INIT
            )
            print("Neo4j connected.")
        except Exception as e:
            print("Neo4j connect failed:", type(e).__name__)
            neo = None

    # Legacy-Linkdaten aus data_copy importieren
    import_legacy_links(neo)

    forum_login_and_collect()
    blocklist_patterns = compile_patterns(RENDER_BLOCKLIST)

    indexed = 0
    while indexed < MAX_PAGES:
        url, depth, host = pop_next()
        if not url:
            time.sleep(2)
            continue
        try:
            doc, status, html, headers = fetch(url)
            mark_visited(url, depth, str(status))
            if not doc:
                print(f"Skipped non-HTML {url} ({status})")
                continue

            links_set, meta, body = parse_meta_and_body(html or "", doc["url"])
            topics = classify_topics(body)
            wallets = find_wallets((html or "") + " " + (body or ""))
            has_wallets = any(len(v) > 0 for v in wallets.values())
            pgps = [
                {
                    "armored": a,
                    "fingerprint": hashlib.sha1(
                        a.encode("utf-8", "ignore")
                    ).hexdigest().upper(),
                }
                for a in find_pgp_keys(html or "")
            ]
            users = list(
                {
                    u.strip("@")
                    for u in RE_USERNAME.findall((html or "") + " " + (body or ""))
                }
            )

            hdr_canon = "\n".join(
                f"{k.lower().strip()}:{headers.get(k)}"
                for k in sorted(headers.keys(), key=str.lower)
            )
            headers_fp = hashlib.sha256(
                hdr_canon.encode("utf-8", "ignore")
            ).hexdigest().upper()

            fav_hash = None
            try:
                fav_url = extract_favicon_url(html or "", doc["url"])
                if fav_url:
                    fr = S.get(fav_url, timeout=15)
                    if fr.ok and fr.content:
                        fav_hash = sha256_bytes(fr.content)
            except Exception:
                pass

            try:
                tls_fp = get_tls_sha256(
                    doc["url"], socks_host=TOR_SOCKS_HOST, socks_port=TOR_SOCKS_PORT
                )
            except Exception:
                tls_fp = None

            tech = []
            server = headers.get("Server")
            xpb = headers.get("X-Powered-By")
            if server:
                tech.append(server.split("/")[0].lower())
            if xpb:
                tech.extend(
                    [p.strip().split("/")[0].lower() for p in xpb.split(",")]
                )
            if meta.get("generator"):
                tech.append((meta["generator"] or "").split()[0])
            tech = list({t for t in tech if t})

            mirrors = guess_mirrors(doc["url"], links_set)

            score, hard_block = risk_score(
                body,
                topics,
                has_wallets,
                forum_context=False,
                blocklist_patterns=blocklist_patterns,
            )
            render_blocked = bool(
                RENDER_SKIP_ON_RISK
                and (score >= RISK_RENDER_THRESHOLD or hard_block)
            )

            # Erweiterte Klassifizierung / Template / Kontakte
            category, cat_score = classify_page(body)
            tpl_fp = template_fingerprint(html or "")
            contacts = extract_contacts((html or "") + " " + (body or ""))

            if category:
                topics = sorted(set(topics + [category]))

            doc.update(
                {
                    "depth": depth,
                    "status": status,
                    "extracted_at": int(time.time() * 1000),
                    "risk": score,
                    "render_blocked": render_blocked,
                    "favicon_hash": fav_hash,
                    "tls_sha256": tls_fp,
                    "headers_fp": headers_fp,
                    "topics": topics,
                    "tech": tech,
                    "usernames": users,
                    "mirrors": mirrors,
                    "links": list(links_set),
                    "wallets_btc": wallets.get("BTC", []),
                    "wallets_eth": wallets.get("ETH", []),
                    "wallets_xmr": wallets.get("XMR", []),
                    "pgp_fingerprints": [
                        p["fingerprint"] for p in pgps if p.get("fingerprint")
                    ],
                    "pgp_count": len(pgps),
                    "category": category,
                    "category_score": cat_score,
                    "template_fp": tpl_fp,
                    "contacts_email": contacts["email"],
                    "contacts_matrix": contacts["matrix"],
                    "contacts_jabber": contacts["jabber"],
                    "contacts_telegram": contacts["telegram"],
                }
            )

            inc_host_seen(host)
            index_doc(doc)

            if RENDER_ENABLE and not render_blocked:
                pre = render_preview(doc["url"], mode=RENDER_MODE)
                if pre:
                    doc.update(pre)
                    index_doc(doc)
            else:
                if render_blocked:
                    print(
                        f"Render skipped due to risk/blocklist (risk={score}) → {doc['url']}"
                    )

            found_links = list(extract_links(doc["url"], html or ""))
            if not STORE_CLEARNET_LINKS:
                found_links = [l for l in found_links if is_onion(l)]
            persist_links(doc["url"], found_links, context="page", current_depth=depth)

            # Neo4j-Bundle
            if neo:
                try:
                    site = {
                        "url": doc["url"],
                        "title": doc.get("title"),
                        "lang": doc.get("lang"),
                        "server": server,
                        "x_powered_by": xpb,
                        "generator": meta.get("generator"),
                        "topics": topics,
                        "tech": tech,
                        "wallets": wallets,
                        "pgp_keys": pgps,
                        "usernames": users,
                        "mirrors": mirrors,
                        "links": list(links_set),
                        "risk": score,
                        "favicon_hash": fav_hash,
                        "tls_sha256": tls_fp,
                        "headers_fp": headers_fp,
                    }
                    neo.upsert_site_bundle(site)
                    if found_links:
                        neo.add_links_mixed(doc["url"], found_links)
                except Exception:
                    pass

            # Indicator-Store (Wallet/PGP-Reuse)
            try:
                upsert_indicators(doc["url"], wallets, pgps)
            except Exception:
                pass

            # STIX-Export für besonders interessante/high-risk Seiten
            try:
                export_if_interesting(doc, wallets, pgps)
            except Exception:
                pass

            # Alerts (High-Risk Notification)
            try:
                maybe_alert(doc)
            except Exception:
                pass

            # Stats
            try:
                on_page_indexed(doc, wallets, pgps)
            except Exception:
                pass

            indexed += 1
            print(
                f"[{indexed}/{MAX_PAGES}] Indexed {doc['url']} (lang={doc['lang']} risk={score})"
            )

        except requests.RequestException as e:
            mark_visited(url, depth, "ERR:REQUEST")
            print("Request error:", url, type(e).__name__)
            time.sleep(3)
        except Exception as e:
            mark_visited(url, depth, f"ERR:{type(e).__name__}")
            print("Error:", url, type(e).__name__, str(e)[:200])
            time.sleep(3)

    if neo:
        try:
            neo.close()
        except Exception:
            pass

    try:
        flush_stats()
    except Exception:
        pass


if __name__ == "__main__":
    print("Starting Onion Crawler")
    print("Tor proxy:", f"socks5h://{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}")
    print("OpenSearch hosts:", OS_HOSTS, "index:", OS_INDEX)
    print(
        f"Limits: pages={MAX_PAGES} depth={MAX_DEPTH} host_delay={HOST_DELAY}s "
        f"per_host={MAX_PER_HOST} timeout={REQUEST_TIMEOUT}s"
    )
    print(
        "Renderer:",
        "enabled" if RENDER_ENABLE else "disabled",
        RENDER_URL if RENDER_ENABLE else "",
    )
    print(
        "Forums:",
        "enabled" if FORUMS_ENABLE else "disabled",
        FORUMS_CONFIG if FORUMS_ENABLE else "",
    )
    print(
        "Media reporting:",
        "enabled" if MEDIA_REPORT_ENABLE else "disabled",
        OS_MEDIA_INDEX if OS_MEDIA_INDEX else "",
    )
    print("Links index:", OS_LINKS_INDEX)
    print("Neo4j:", "enabled" if (NEO4J_URI and Neo4jWriter) else "disabled")
    print("Legacy link import:", "enabled" if IMPORT_DATA_COPY else "disabled", "from", DATA_COPY_DIR)
    run()
