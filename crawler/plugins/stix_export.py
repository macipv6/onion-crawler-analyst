# plugins/stix_export.py
import os
import json
import time
import uuid
from pathlib import Path
from typing import Dict, List

DATA_DIR = Path(os.getenv("DATA_DIR", "/app/data"))
STIX_DIR = DATA_DIR / "stix"
STIX_DIR.mkdir(parents=True, exist_ok=True)

RISK_THRESHOLD = int(os.getenv("STIX_RISK_THRESHOLD", "70"))


def _rand_id(prefix: str) -> str:
    return f"{prefix}--{uuid.uuid4()}"


def export_if_interesting(
    doc: Dict,
    wallets: Dict[str, List[str]],
    pgps: List[Dict],
):
    """
    Wird von main.py aufgerufen (nach Indexing).
    Erzeugt STIX-Bundle für Seiten mit risk >= RISK_THRESHOLD.
    """
    risk = int(doc.get("risk") or 0)
    if risk < RISK_THRESHOLD:
        return

    now = int(time.time())
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))

    url = doc.get("url")
    host = doc.get("host")
    topics = doc.get("topics") or []
    lang = doc.get("lang")

    infra_id = _rand_id("infrastructure")
    infra_type = "hosting-malware" if risk >= 80 else "hosting-target-list"

    infra = {
        "type": "infrastructure",
        "id": infra_id,
        "spec_version": "2.1",
        "name": host or url,
        "infrastructure_types": [infra_type],
        "created": ts,
        "modified": ts,
        "description": f"Onion site {url} (risk={risk}, topics={topics}, lang={lang})",
    }

    objs = [infra]

    # Wallet Indicators
    for wtype, addrs in (wallets or {}).items():
        for addr in addrs:
            ind_id = _rand_id("indicator")
            objs.append(
                {
                    "type": "indicator",
                    "id": ind_id,
                    "spec_version": "2.1",
                    "pattern_type": "stix",
                    "pattern": f"[ cryptocurrency-wallet:address = '{addr}' ]",
                    "created": ts,
                    "modified": ts,
                    "description": f"{wtype} wallet observed on {url}",
                }
            )

    # PGP Indicators
    for p in pgps or []:
        fp = p.get("fingerprint")
        if not fp:
            continue
        ind_id = _rand_id("indicator")
        objs.append(
            {
                "type": "indicator",
                "id": ind_id,
                "spec_version": "2.1",
                "pattern_type": "stix",
                "pattern": f"[ pgp:key_fingerprint = '{fp}' ]",
                "created": ts,
                "modified": ts,
                "description": f"PGP key fingerprint observed on {url}",
            }
        )

    bundle = {"type": "bundle", "id": _rand_id("bundle"), "objects": objs}
    out = STIX_DIR / f"stix_{now}_{uuid.uuid4().hex[:8]}.json"
    out.write_text(json.dumps(bundle, ensure_ascii=False, indent=2), encoding="utf-8")
