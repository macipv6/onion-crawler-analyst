import time, json, re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from ..storage import Storage
from ..queue import LinkQueue

def session_via_tor(socks_url:str, ua:str)->requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": ua})
    s.proxies = {"http": socks_url, "https": socks_url}
    s.timeout = 45
    return s

def extract_csrf(session, login_url, selector):
    r = session.get(login_url)
    r.raise_for_status()
    soup = BeautifulSoup(r.text, "html.parser")
    node = soup.select_one(selector) if selector else None
    token = node["value"] if node and node.has_attr("value") else None
    return token, r

def login_forum(session, base, spec:dict):
    login = spec["login"]
    csrf_token = None
    if "csrf" in login:
        csrf_token, _ = extract_csrf(session, login["url"], login["csrf"].get("selector"))

    data = {}
    data[login["form"]["username_field"]] = spec["username"]
    data[login["form"]["password_field"]] = spec["password"]
    for k,v in (login["form"].get("extra_fields") or {}).items():
        data[k] = v
    if csrf_token and login.get("csrf",{}).get("field_name"):
        data[login["csrf"]["field_name"]] = csrf_token

    if login.get("method","POST").upper() == "POST":
        r = session.post(login["url"], data=data)
    else:
        r = session.get(login["url"], params=data)
    r.raise_for_status()

    check = spec.get("post_login_check")
    if check:
        rr = session.get(check["url"])
        rr.raise_for_status()
        ok = all(s in rr.text for s in check.get("must_contain", []))
        if not ok:
            raise RuntimeError("Forum-Login fehlgeschlagen: Prüf-Strings nicht gefunden.")
    return True

def collect_links(session, base, start_urls, selectors, max_depth=2, follow_onion_only=True):
    seen=set()
    to_visit=[(u,0) for u in start_urls]
    results=[]
    while to_visit:
        url, depth = to_visit.pop(0)
        if url in seen or depth>max_depth: continue
        seen.add(url)
        try:
            r = session.get(url)
            if r.status_code>=400: continue
            soup = BeautifulSoup(r.text, "html.parser")
            page_links=set()
            for sel in selectors:
                for a in soup.select(sel):
                    if a.has_attr("href"):
                        page_links.add(urljoin(url, a["href"]))
            # generisch alle A-Links beimischen
            for a in soup.find_all("a", href=True):
                page_links.add(urljoin(url, a["href"]))
            # filtern
            filtered=[]
            for l in page_links:
                if follow_onion_only and ".onion" not in l: 
                    continue
                if l.startswith("javascript:") or l.startswith("mailto:"):
                    continue
                filtered.append(l)
                if (l not in seen) and (depth+1<=max_depth):
                    to_visit.append((l, depth+1))
            results.append({"source": url, "links": filtered})
        except Exception:
            continue
    return results

def crawl_forums(config_forums:list, tor_proxy:str, ua:str, storage:Storage, queue:LinkQueue):
    for f in config_forums:
        if "username" not in f or "password" not in f:
            # Anmeldedaten können aus ENV kommen (z. B. FORUM_BeispielForum_USER/PASS)
            continue
        sess = session_via_tor(tor_proxy, ua)
        login_forum(sess, f["base"], f)
        results = collect_links(sess, f["base"],
                                f["crawl"]["start_urls"],
                                f["crawl"]["link_selectors"],
                                f["crawl"].get("max_depth",2),
                                f["crawl"].get("follow_onion_only", True))
        # speichern + in Queue
        for page in results:
            storage.save_links(page["source"], page["links"], context=f"forum:{f['name']}")
            for link in page["links"]:
                queue.add(link, priority=120)  # etwas höher priorisieren
