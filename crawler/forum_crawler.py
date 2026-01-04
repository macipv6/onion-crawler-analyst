# -*- coding: utf-8 -*-
"""
Forum Crawler – Tor-enforced & Debug Logging (Clearnet via Tor ok)
- Erzwingt socks5h (DNS via Tor). Ohne Tor -> kein Request.
- Sammelt Links aus start_urls; nutzt optionale Selektoren, + generische <a>.
- Ausführliches Logging (Status, Exceptions, Selektor-Treffer).
- Höhere Timeouts + leichte Retries (Backoff), gut für Tor.
- Rückgabe kompatibel: [{"forum","source","links"}]
"""

from __future__ import annotations
import os, re, time, math
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

DEBUG = os.getenv("FORUMS_DEBUG", "true").lower() == "true"
DEFAULT_TIMEOUT = int(os.getenv("FORUMS_TIMEOUT", "60"))  # Tor braucht Luft
MAX_RETRIES = int(os.getenv("FORUMS_RETRIES", "3"))
RETRY_BACKOFF = float(os.getenv("FORUMS_BACKOFF", "1.8"))
USER_AGENT = os.getenv("USER_AGENT", "OnionCrawler/0.2 (+forums; debug)")
SESSION_HEADERS = {"User-Agent": USER_AGENT, "Accept": "*/*", "Accept-Language": "en,de;q=0.9"}

def log(*a):
    if DEBUG:
        print("[forums]", *a, flush=True)

def _tor_required(socks_url: Optional[str]) -> bool:
    return bool(socks_url and socks_url.lower().strip().startswith("socks5h://"))

def _sess(socks_url: str) -> requests.Session:
    s = requests.Session()
    s.proxies = {"http": socks_url, "https": socks_url}
    s.headers.update(SESSION_HEADERS)
    return s

def _req(session: requests.Session, method: str, url: str, timeout: int = DEFAULT_TIMEOUT) -> Optional[requests.Response]:
    # leichte Retries mit Backoff; HEAD->GET-Fallback bei 405/4xx
    delay = 0.0
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            if delay:
                time.sleep(delay)
            r = session.request(method, url, timeout=timeout, allow_redirects=True)
            if method == "HEAD" and (r.status_code >= 400 or not r.headers):
                # viele Foren mögen HEAD nicht -> GET
                r = session.get(url, timeout=timeout, allow_redirects=True)
            return r
        except requests.RequestException as e:
            log(f"{method} {url} -> {type(e).__name__}: {str(e)[:160]}")
            delay = delay * RETRY_BACKOFF + 0.5
    return None

def _norm_link(base: str, href: str) -> Optional[str]:
    if not href: return None
    href = href.strip()
    if href.startswith(("javascript:", "mailto:", "#")): return None
    try:
        u = urljoin(base, href)
        if "#" in u: u = u.split("#", 1)[0]
        return u
    except Exception:
        return None

def _selector_counts(soup: BeautifulSoup, selectors: List[str]) -> Dict[str, int]:
    out = {}
    for sel in selectors or []:
        try:
            out[sel] = len(soup.select(sel))
        except Exception:
            out[sel] = -1  # ungültiger Selektor
    return out

def collect_links(session: requests.Session, start_urls: List[str], selectors: List[str],
                  max_depth: int = 1, onion_only: bool = True):
    seen = set()
    q = [(u, 0) for u in (start_urls or [])]
    out = []
    if not q:
        log("WARN: keine start_urls übergeben.")
        return out

    while q:
        url, d = q.pop(0)
        if url in seen or d > max_depth:
            continue
        seen.add(url)

        r = _req(session, "GET", url)
        if r is None:
            log(f"GET {url} -> keine Antwort (Timeout/Proxy/Netz?)")
            continue
        log(f"GET {url} -> {r.status_code} CT={r.headers.get('Content-Type')} LEN={len(r.text) if r.text else 0}")
        if r.status_code >= 400 or not r.text:
            continue

        soup = BeautifulSoup(r.text, "html.parser")
        sel_counts = _selector_counts(soup, selectors)
        if selectors:
            log(f"Selektoren auf {url}: {sel_counts}")

        links = set()

        # gezielte Selektoren
        for sel in selectors or []:
            try:
                for a in soup.select(sel):
                    if a.has_attr("href"):
                        u = _norm_link(url, a["href"])
                        if u: links.add(u)
            except Exception as e:
                log(f"Selektor-Fehler '{sel}' auf {url}: {type(e).__name__}")

        # generische A-Tags
        for a in soup.find_all("a", href=True):
            u = _norm_link(url, a["href"])
            if u: links.add(u)

        cleaned = []
        for l in links:
            if onion_only and ".onion" not in l:
                continue
            cleaned.append(l)
            if d + 1 <= max_depth:
                q.append((l, d + 1))

        log(f"Links auf {url}: total={len(links)} (gefiltert={len(cleaned)}) depth={d}/{max_depth}")
        out.append({"source": url, "links": cleaned})
    return out

def _probe_site(session: requests.Session, base_url: str) -> Tuple[int, Optional[str]]:
    # Nur für Log/Reachability
    r = _req(session, "HEAD", base_url)
    if r is None:
        r = _req(session, "GET", base_url)
    if r is None:
        log(f"Probe {base_url}: keine Antwort")
        return -1, None
    log(f"Probe {base_url}: {r.status_code} {r.headers.get('Server')} {r.headers.get('X-Powered-By')}")
    return r.status_code, r.headers.get("Content-Type")

def run_forums(config: Dict[str, Any], socks_url: Optional[str], ua: str):
    results = []

    if not _tor_required(socks_url):
        log("ERROR: Tor (socks5h) erforderlich. Abbruch ohne Requests.")
        return results

    # eigener UA aus env überschreibt gerne den mitgegebenen
    if ua and ua != USER_AGENT:
        SESSION_HEADERS["User-Agent"] = ua

    forums = config.get("forums", [])
    if not forums:
        log("WARN: config.forums leer.")
        return results

    for f in forums:
        base = (f.get("base") or "").strip()
        name = (f.get("name") or (urlparse(base).hostname or base)).strip() or "Forum"
        crawl = f.get("crawl") or {}
        start_urls = crawl.get("start_urls") or []
        selectors = crawl.get("link_selectors") or []
        max_depth = int(crawl.get("max_depth", 1))
        onion_only = bool(crawl.get("follow_onion_only", True))

        log(f"== Verarbeite Forum '{name}' base={base}")
        if not base:
            log("WARN: base fehlt – überspringe.")
            continue
        if not start_urls:
            log("WARN: keine crawl.start_urls definiert – überspringe Link-Sammlung.")

        s = _sess(socks_url)

        # Reachability-Log
        _probe_site(s, base)

        # Link-Sammlung
        if start_urls:
            try:
                res = collect_links(s, start_urls, selectors, max_depth, onion_only)
                for page in res:
                    results.append({"forum": name, **page})
                log(f"ERGEBNIS '{name}': Seiten={len(res)} (gesamt Links-Einträge)")
            except Exception as e:
                log(f"ERROR collect_links '{name}': {type(e).__name__}: {str(e)[:200]}")

    return results
