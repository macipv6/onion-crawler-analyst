# plugins/file_analyzer.py
import os
import time
import json
import hashlib
from pathlib import Path

try:
    import yara  # optional
except Exception:
    yara = None

DATA_DIR = Path(os.getenv("DATA_DIR", "/app/data"))
FILES_DIR = DATA_DIR / "files"
FILES_DIR.mkdir(parents=True, exist_ok=True)
META_PATH = DATA_DIR / "files_meta.jsonl"

YARA_RULES_PATH = os.getenv("YARA_RULES_PATH")  # optional
_yara_rules = None

def _load_yara():
    global _yara_rules
    if not yara or not YARA_RULES_PATH or not os.path.exists(YARA_RULES_PATH):
        return None
    try:
        _yara_rules = yara.compile(filepath=YARA_RULES_PATH)
    except Exception:
        _yara_rules = None

def handle_non_html_response(url: str, response, os_client=None, index_name: str = "onion_files"):
    """
    response: requests.Response
    """
    ctype = response.headers.get("content-type", "").lower()
    now = int(time.time())
    content = response.content or b""
    size = len(content)
    sha256 = hashlib.sha256(content).hexdigest().upper()
    sha1 = hashlib.sha1(content).hexdigest().upper()
    md5 = hashlib.md5(content).hexdigest().upper()

    # YARA-Scan (optional)
    matches = []
    if yara and (YARA_RULES_PATH or _yara_rules):
        if _yara_rules is None:
            _load_yara()
        if _yara_rules:
            try:
                m = _yara_rules.match(data=content)
                matches = [str(rule.rule) for rule in m]
            except Exception:
                matches = []

    # File nicht unbedingt komplett speichern, nur Metadaten
    rec = {
        "url": url,
        "host": response.url,
        "content_type": ctype,
        "size": size,
        "sha256": sha256,
        "sha1": sha1,
        "md5": md5,
        "yara_matches": matches,
        "detected_at": now * 1000,
    }

    META_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(META_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    if os_client and index_name:
        try:
            if not os_client.indices.exists(index=index_name):
                body = {
                    "settings": {"number_of_shards": 1, "number_of_replicas": 0},
                    "mappings": {"properties": {
                        "url": {"type": "keyword"},
                        "host": {"type": "keyword"},
                        "content_type": {"type": "keyword"},
                        "size": {"type": "long"},
                        "sha256": {"type": "keyword"},
                        "sha1": {"type": "keyword"},
                        "md5": {"type": "keyword"},
                        "yara_matches": {"type": "keyword"},
                        "detected_at": {"type": "date"}
                    }},
                }
                os_client.indices.create(index=index_name, body=body)
            os_client.index(index=index_name, body=rec)
        except Exception:
            pass
