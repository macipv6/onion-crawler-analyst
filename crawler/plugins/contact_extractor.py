# plugins/contact_extractor.py
import re

RE_EMAIL = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,10}\b')
RE_MATRIX = re.compile(r'@[a-zA-Z0-9._\-]+:[a-zA-Z0-9.\-]+\b')
RE_JABBER = re.compile(r'\b[a-zA-Z0-9._%+-]+@(?:jabber|xmpp|jabber\.org|xmpp\.net)[A-Za-z0-9.\-]*\b', re.I)
RE_TELEGRAM = re.compile(r'\bhttps?://t\.me/[A-Za-z0-9_]{3,64}\b')

def extract_contacts(text: str) -> dict:
    if not text:
        return {"email": [], "matrix": [], "jabber": [], "telegram": []}
    t = text
    emails = sorted(set(RE_EMAIL.findall(t)))
    matrix_ids = sorted(set(RE_MATRIX.findall(t)))
    jabber_ids = sorted(set(RE_JABBER.findall(t)))
    tg_links = sorted(set(RE_TELEGRAM.findall(t)))
    return {
        "email": emails,
        "matrix": matrix_ids,
        "jabber": jabber_ids,
        "telegram": tg_links,
    }
