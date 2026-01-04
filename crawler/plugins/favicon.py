# -*- coding: utf-8 -*-
import hashlib
from bs4 import BeautifulSoup
from urllib.parse import urljoin

def extract_favicon_url(html: str, base_url: str) -> str | None:
    try:
        soup = BeautifulSoup(html, "html.parser")
        icon = soup.find("link", rel=lambda v: v and "icon" in v.lower())
        href = icon["href"] if icon and icon.has_attr("href") else "/favicon.ico"
        return urljoin(base_url, href)
    except Exception:
        return None

def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest().upper()
