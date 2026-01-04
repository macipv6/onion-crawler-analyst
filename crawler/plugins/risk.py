# -*- coding: utf-8 -*-
import re

DEFAULT_BLOCKLIST = [r"csam", r"child\s*(abuse|sexual|porn)", r"exploit\s*kid", r"bestiality"]
DEFAULT_WEAK_SIGNALS = [r"hitman", r"weapon\s*for\s*sale", r"hacking\s*for\s*hire"]

def compile_patterns(words_csv: str | None):
    if not words_csv:
        return [re.compile(p, re.I) for p in DEFAULT_BLOCKLIST]
    items = [w.strip() for w in words_csv.split(",") if w.strip()]
    return [re.compile(re.escape(i), re.I) for i in items]

def topic_base_score(topics: list[str]) -> int:
    # simple heuristic per topic bucket
    score = 0
    for t in topics or []:
        if t in ("exploit", "fraud"): score += 25
        elif t in ("market",): score += 10
        elif t in ("drugs",): score += 15
        elif t in ("forum", "crypto"): score += 5
    return min(score, 60)

def risk_score(text: str, topics: list[str], wallets_present: bool, forum_context: bool,
               blocklist_patterns: list[re.Pattern] | None = None) -> tuple[int, bool]:
    t = (text or "")
    bl = blocklist_patterns or [re.compile(p, re.I) for p in DEFAULT_BLOCKLIST]
    # Hard block: any blocklist match → mark
    hard = any(p.search(t) for p in bl)
    score = topic_base_score(topics)
    if wallets_present:
        score += 10
    if forum_context:
        score += 5
    # weak signals
    if any(re.search(p, t, re.I) for p in DEFAULT_WEAK_SIGNALS):
        score += 5
    return (min(score, 100), hard)

