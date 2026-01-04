# plugins/alerts.py
import os
import json
import time
from pathlib import Path
from typing import Dict

import requests

DATA_DIR = Path(os.getenv("DATA_DIR", "/app/data"))
ALERTS_PATH = DATA_DIR / "alerts.jsonl"

ALERT_MIN_RISK = int(os.getenv("ALERT_MIN_RISK", "80"))
ALERT_WEBHOOK_URL = os.getenv("ALERT_WEBHOOK_URL")  # optional, z. B. Slack/Teams/Webhook


def maybe_alert(doc: Dict):
    """
    Wird von main.py aufgerufen.
    Wenn risk >= ALERT_MIN_RISK → Zeile in alerts.jsonl + optional HTTP-Webhook.
    """
    risk = int(doc.get("risk") or 0)
    if risk < ALERT_MIN_RISK:
        return

    alert = {
        "ts": int(time.time()),
        "url": doc.get("url"),
        "host": doc.get("host"),
        "risk": risk,
        "topics": doc.get("topics") or [],
        "wallets_btc": doc.get("wallets_btc") or [],
        "wallets_eth": doc.get("wallets_eth") or [],
        "wallets_xmr": doc.get("wallets_xmr") or [],
    }

    ALERTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(ALERTS_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(alert, ensure_ascii=False) + "\n")

    if ALERT_WEBHOOK_URL:
        try:
            requests.post(ALERT_WEBHOOK_URL, json=alert, timeout=5)
        except Exception:
            # Alert darf den Crawler nicht umwerfen
            pass

