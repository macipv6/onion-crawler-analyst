# plugins/classifier.py
import re

BASIC_RULES = [
    ("marketplace", ["escrow", "vendor", "listing", "cart", "ship", "shipping", "buyer", "seller"]),
    ("forum", ["thread", "sticky", "reply", "quote", "moderator", "ban", "pm", "profile"]),
    ("whistleblowing", ["leak", "whistleblower", "dump", "leaked data", "documents"]),
    ("exploit", ["exploit", "0day", "cve-", "shellcode", "rce", "lpe"]),
    ("scam", ["cashout", "clone card", "spoofing", "phishing"]),
]

def classify_page(text: str) -> tuple[str | None, int]:
    if not text:
        return None, 0
    t = text.lower()
    best_cat = None
    best_score = 0
    for cat, kws in BASIC_RULES:
        score = 0
        for kw in kws:
            if kw in t:
                score += 10
        if score > best_score:
            best_score = score
            best_cat = cat
    # kleiner Bonus für sehr lange Seiten
    if len(t) > 5000 and best_cat:
        best_score += 5
    return best_cat, best_score
