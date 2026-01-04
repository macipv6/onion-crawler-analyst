# plugins/stats.py
import os
import json
import time
from pathlib import Path

DATA_DIR = Path(os.getenv("DATA_DIR", "/app/data"))
STATS_PATH = DATA_DIR / "stats.json"

_state = {
    "pages_indexed": 0,
    "hosts": set(),
    "with_wallets": 0,
    "with_pgp": 0,
    "high_risk": 0,
    "started_at": int(time.time()),
}

def on_page_indexed(doc: dict, wallets: dict, pgps: list[dict]):
    _state["pages_indexed"] += 1
    host = doc.get("host")
    if host:
        _state["hosts"].add(host)
    if any(len(v) for v in (wallets or {}).values()):
        _state["with_wallets"] += 1
    if (pgps or []):
        _state["with_pgp"] += 1
    if int(doc.get("risk") or 0) >= 70:
        _state["high_risk"] += 1

def flush():
    out = dict(_state)
    out["hosts"] = sorted(out["hosts"])
    out["finished_at"] = int(time.time())
    STATS_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATS_PATH.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
