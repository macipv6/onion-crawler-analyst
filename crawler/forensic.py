# forensic.py
# -*- coding: utf-8 -*-
"""
Forensic helpers (no screenshots)
- save_raw_response(...) -> saves raw headers/body, computes hashes
- write manifest.json, optional WARC
- register_evidence(...) -> ensures sqlite 'evidence' table and inserts a record
"""

from __future__ import annotations
import os, json, time, uuid, hashlib, sqlite3
from pathlib import Path
from typing import Dict, Any, Optional

DATA_DIR = Path(os.getenv("DATA_DIR", "/app/data")); DATA_DIR.mkdir(parents=True, exist_ok=True)
STATE_DIR = Path(os.getenv("STATE_DIR", "state")); STATE_DIR.mkdir(parents=True, exist_ok=True)
FRONTIER_DB = STATE_DIR / "frontier.db"
FORUM_DB = STATE_DIR / "forums.db"
EVIDENCE_DIR = Path(os.getenv("FORENSIC_DIR", STATE_DIR / "evidence")); EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

FORENSIC_ENABLE = os.getenv("FORENSIC_ENABLE", "true").lower() == "true"
FORENSIC_WARC = os.getenv("FORENSIC_WARC", "false").lower() == "true"

def sha256_bytes(b: bytes) -> str: return hashlib.sha256(b).hexdigest()
def sha512_bytes(b: bytes) -> str: return hashlib.sha512(b).hexdigest()

def _evidence_path(eid: str) -> Path:
    p = EVIDENCE_DIR / time.strftime("%Y%m%d") / eid
    p.mkdir(parents=True, exist_ok=True)
    return p

def save_raw_response(url: str, resp, tor_meta: Optional[Dict[str,Any]] = None) -> Dict[str, Any]:
    if not FORENSIC_ENABLE:
        return {}
    eid = str(uuid.uuid4())
    out = _evidence_path(eid)

    # Headers (order-preserving best-effort)
    try:
        hdr_lines = [f"HTTP/1.1 {resp.status_code}"]
        for k, v in resp.headers.items():
            hdr_lines.append(f"{k}: {v}")
        hdr_blob = ("\r\n".join(hdr_lines) + "\r\n\r\n").encode("iso-8859-1", errors="replace")
    except Exception:
        hdr_blob = b""

    body = resp.content if hasattr(resp, "content") else (resp.text.encode("utf-8","ignore") if hasattr(resp,"text") else b"")
    raw_hdr_path = out / "response_headers.raw.txt"
    raw_body_path = out / "response_body.raw.bin"
    manifest_path = out / "manifest.json"

    raw_hdr_path.write_bytes(hdr_blob)
    raw_body_path.write_bytes(body)

    body_sha256 = sha256_bytes(body)
    body_sha512 = sha512_bytes(body)
    hdr_sha256 = sha256_bytes(hdr_blob)
    hdr_body_sha256 = sha256_bytes(hdr_blob + body)

    manifest = {
        "evidence_id": eid,
        "url": url,
        "resolved_url": getattr(resp, "url", url),
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "http": {
            "status": getattr(resp, "status_code", None),
            "reason": getattr(resp, "reason", None),
            "headers_path": str(raw_hdr_path),
        },
        "hashes": {
            "headers_sha256": hdr_sha256,
            "body_sha256": body_sha256,
            "body_sha512": body_sha512,
            "headers_body_sha256": hdr_body_sha256
        },
        "file_paths": {
            "headers": str(raw_hdr_path),
            "body": str(raw_body_path),
            "manifest": str(manifest_path)
        },
        "tor": tor_meta or {},
        "collector": {
            "host": os.uname().nodename if hasattr(os, "uname") else None,
            "container": os.getenv("CONTAINER_IMAGE", None),
            "code_version": os.getenv("CODE_VERSION", None)
        }
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")

    if FORENSIC_WARC:
        try:
            from warcio.warcwriter import WARCWriter
            import io
            warc_path = out / "response.warc.gz"
            stream = warc_path.open("wb")
            writer = WARCWriter(stream, gzip=True)
            http_headers = [(k, v) for k, v in resp.headers.items()]
            rec = writer.create_warc_record(getattr(resp, "url", url), 'response',
                                            payload=io.BytesIO(body), http_headers=http_headers)
            writer.write_record(rec)
            stream.close()
            # append WARC info to manifest
            m = json.loads(manifest_path.read_text(encoding="utf-8"))
            m["file_paths"]["warc"] = str(warc_path)
            m["hashes"]["warc_sha256"] = sha256_bytes(warc_path.read_bytes())
            manifest_path.write_text(json.dumps(m, indent=2, ensure_ascii=False), encoding="utf-8")
        except Exception:
            pass

    return {
        "evidence_id": eid,
        "manifest_path": str(manifest_path),
        "body_path": str(raw_body_path),
        "headers_path": str(raw_hdr_path),
        "hashes": {
            "headers_sha256": hdr_sha256,
            "body_sha256": body_sha256,
            "body_sha512": body_sha512,
            "headers_body_sha256": hdr_body_sha256
        }
    }

def register_evidence(db_path: Optional[str], metadata: Dict[str, Any]) -> None:
    if not db_path:
        db_path = str(FORUM_DB if FORUM_DB.exists() else FRONTIER_DB)
    try:
        conn = sqlite3.connect(db_path)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS evidence (
            id TEXT PRIMARY KEY,
            url TEXT,
            resolved_url TEXT,
            ts_utc TEXT,
            http_status INTEGER,
            server TEXT,
            x_powered_by TEXT,
            forum_software TEXT,
            forum_version TEXT,
            tls_cert_sha256 TEXT,
            body_sha256 TEXT,
            headers_body_sha256 TEXT,
            manifest_path TEXT,
            raw_body_path TEXT,
            raw_headers_path TEXT,
            tor_exit_fp TEXT,
            tor_circuit_id TEXT
        )
        """)
        eid = metadata.get("evidence_id")
        url = metadata.get("url")
        resolved = metadata.get("resolved_url")
        ts = metadata.get("timestamp_utc")
        http_status = metadata.get("http", {}).get("status")
        server = metadata.get("http", {}).get("server") or metadata.get("server")
        xpb = metadata.get("http", {}).get("x_powered_by") or metadata.get("x_powered_by")
        forum_sw = metadata.get("forum_software") or metadata.get("software")
        forum_ver = metadata.get("forum_version") or metadata.get("version")
        tls_sha = metadata.get("tls_sha256")
        body_sha = metadata.get("hashes", {}).get("body_sha256")
        hb_sha = metadata.get("hashes", {}).get("headers_body_sha256")
        manifest = metadata.get("file_paths", {}).get("manifest") or metadata.get("manifest_path")
        raw_body = metadata.get("file_paths", {}).get("body") or metadata.get("body_path")
        raw_hdr = metadata.get("file_paths", {}).get("headers") or metadata.get("headers_path")
        tor_exit = metadata.get("tor", {}).get("exit", {}).get("fingerprint") if isinstance(metadata.get("tor"), dict) else None
        tor_circ = metadata.get("tor", {}).get("circuit_id") if isinstance(metadata.get("tor"), dict) else None

        conn.execute("""
        INSERT OR REPLACE INTO evidence(
            id, url, resolved_url, ts_utc, http_status, server, x_powered_by,
            forum_software, forum_version, tls_cert_sha256, body_sha256, headers_body_sha256,
            manifest_path, raw_body_path, raw_headers_path, tor_exit_fp, tor_circuit_id
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (eid, url, resolved, ts, http_status, server, xpb, forum_sw, forum_ver,
              tls_sha, body_sha, hb_sha, manifest, raw_body, raw_hdr, tor_exit, tor_circ))
        conn.commit(); conn.close()
    except Exception as e:
        print("forensic.register_evidence DB error:", type(e).__name__, str(e)[:200])

def capture_and_register(url: str, resp, tor_meta: Optional[Dict[str,Any]] = None, db_path: Optional[str] = None, extra: Optional[Dict[str,Any]] = None) -> Dict[str,Any]:
    try:
        meta = save_raw_response(url, resp, tor_meta=tor_meta)
        mpath = meta.get("manifest_path")
        manifest = {}
        if mpath and Path(mpath).exists():
            manifest = json.loads(Path(mpath).read_text(encoding="utf-8"))
        manifest["http"]["server"] = resp.headers.get("Server")
        manifest["http"]["x_powered_by"] = resp.headers.get("X-Powered-By") or resp.headers.get("X-Generator")
        if extra:
            manifest.update(extra)
        if mpath:
            Path(mpath).write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
        register_evidence(db_path, {**manifest, **(extra or {})})
        return {
            "evidence_id": meta.get("evidence_id"),
            "url": manifest.get("url"),
            "resolved_url": manifest.get("resolved_url"),
            "timestamp_utc": manifest.get("timestamp_utc"),
            "http": {
                "status": manifest.get("http", {}).get("status"),
                "server": manifest.get("http", {}).get("server"),
                "x_powered_by": manifest.get("http", {}).get("x_powered_by")
            },
            "hashes": manifest.get("hashes"),
            "file_paths": manifest.get("file_paths"),
            "tor": manifest.get("tor", {})
        }
    except Exception as e:
        print("forensic.capture_and_register error:", type(e).__name__, str(e)[:200])
        return {}
