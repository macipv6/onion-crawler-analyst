# analyst/main.py
import os
import datetime
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from opensearchpy import OpenSearch
from opensearchpy.exceptions import NotFoundError

from .scanner import router as scanner_router

# ----------------------------------------------------
# Konfiguration
# ----------------------------------------------------
OS_HOST = os.getenv("OS_HOST", "http://opensearch:9200")
OS_USERNAME = os.getenv("OS_USERNAME") or None
OS_PASSWORD = os.getenv("OS_PASSWORD") or None

OS_INDEX_PAGES = os.getenv("OS_INDEX_PAGES", "onion_pages")
OS_INDEX_SCANS = os.getenv("OS_INDEX_SCANS", "onion_scans")
INDEX_PLUGIN = "onion_plugin_activity"

BASE_DIR = "/app/analyst"
HTML_DASHBOARD = os.path.join(BASE_DIR, "onion-dashboard.html")

app = FastAPI(title="Onion Analyst UI")

# Scanner-API (Dir-Scan / Port-Check über Tor etc.)
app.include_router(scanner_router)

# Optional: /static mounten, falls vorhanden
static_dir = os.path.join(BASE_DIR, "static")
if os.path.isdir(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


def get_os_client() -> OpenSearch:
    auth = (OS_USERNAME, OS_PASSWORD) if OS_USERNAME and OS_PASSWORD else None
    return OpenSearch(
        hosts=[OS_HOST],
        http_auth=auth,
        verify_certs=False,
        timeout=20,
        max_retries=3,
        retry_on_timeout=True,
    )


os_client = get_os_client()


# ----------------------------------------------------
# Helper
# ----------------------------------------------------
def _epoch_ms_to_iso(ts: Optional[Any]) -> Optional[str]:
    if ts is None:
        return None
    try:
        v = float(ts) / 1000.0
        dt = datetime.datetime.utcfromtimestamp(v)
        return dt.replace(microsecond=0).isoformat() + "Z"
    except Exception:
        return None


def _normalize_onion_host(value: str) -> str:
    """
    Host ohne http://, also z.B.:
    - http://abcd.onion/  -> abcd.onion
    - abcd.onion          -> abcd.onion
    """
    v = value.strip()
    if "://" in v:
        try:
            v = v.split("://", 1)[1]
        except Exception:
            pass
    return v.split("/", 1)[0]


def _load_plugins_for_doc(url: Optional[str], host: Optional[str]) -> Dict[str, Dict[str, Any]]:
    """
    Lädt Plugin-Aktivitäten aus INDEX_PLUGIN für eine bestimmte Seite.
    Erwartete Felder (flexibel):
      - plugin oder plugin_name
      - hits (int)
      - ts / run_at / timestamp (epoch_ms oder ISO – wir versuchen epoch_ms)
      - url / host (zum Matchen)
    """
    if not url and not host:
        return {}

    must: List[Dict[str, Any]] = []

    if url:
        must.append({"term": {"url.keyword": url}})
    elif host:
        must.append({"term": {"host.keyword": host}})

    if not must:
        return {}

    body = {
        "size": 100,
        "query": {
            "bool": {
                "must": must,
            }
        },
    }

    try:
        res = os_client.search(index=INDEX_PLUGIN, body=body)
    except Exception:
        return {}

    hits = res.get("hits", {}).get("hits", [])
    if not hits:
        return {}

    plugins: Dict[str, Dict[str, Any]] = {}

    for h in hits:
        src = h.get("_source", {}) or {}
        name = src.get("plugin") or src.get("plugin_name") or "unknown"

        hits_val = src.get("hits")
        if hits_val is None:
            hits_val = 1

        ts_raw = src.get("ts") or src.get("run_at") or src.get("timestamp")
        ts_iso = _epoch_ms_to_iso(ts_raw) if ts_raw is not None else None

        plugins[name] = {
            "hits": hits_val,
            "last_run": ts_iso,
        }

    return plugins


def _doc_to_onion_response(doc: Dict[str, Any]) -> Dict[str, Any]:
    """
    Mappt ein Dokument aus 'onion_pages' auf die Struktur,
    die das Frontend erwartet, inkl. Plugin-Aktivität.
    """
    url = doc.get("url")
    host = doc.get("host")
    title = doc.get("title")

    emails = doc.get("contacts_email", []) or []
    usernames = doc.get("usernames", []) or []
    wallets_btc = doc.get("wallets_btc", []) or []
    wallets_xmr = doc.get("wallets_xmr", []) or []
    wallets_eth = doc.get("wallets_eth", []) or []
    pgp_fps = doc.get("pgp_fingerprints", []) or []

    tags = doc.get("topics", []) or []

    tech = {
        "server": doc.get("server"),
        "hosting_ip": doc.get("ip"),
        "ports": doc.get("ports", []) or [],
        "fingerprint": doc.get("tls_sha256"),
    }

    osint = {
        "clearweb_profiles": doc.get("clearweb_profiles", []) or [],
        "linked_domains": doc.get("linked_domains", []) or [],
    }

    plugins = _load_plugins_for_doc(url, host)
    extracted_iso = _epoch_ms_to_iso(doc.get("extracted_at"))

    return {
        "title": title,
        "url": url,
        "host": host,
        "onion": host,
        "last_seen": extracted_iso,
        "status": doc.get("status"),
        "tags": tags,
        "emails": emails,
        "usernames": usernames,
        "btc_addresses": wallets_btc,
        "xmr_addresses": wallets_xmr,
        "eth_addresses": wallets_eth,
        "pgp_keys": pgp_fps,
        "tech": tech,
        "osint": osint,
        "plugins": plugins,
        "risk": doc.get("risk"),
    }


def _build_fuzzy_query(value: str) -> Dict[str, Any]:
    """
    Tolerante Query für URL/Host:
    - exakte URL/Host (term)
    - Varianten ohne Query-String / Slash
    - wildcard auf url / host
    """
    value = value.strip()
    should: List[Dict[str, Any]] = []

    should.append({"term": {"url.keyword": value}})
    should.append({"term": {"host.keyword": value}})

    if value.startswith("http://") or value.startswith("https://"):
        base_no_query = value.split("?", 1)[0].rstrip("/")
        should.append({"term": {"url.keyword": base_no_query}})
        should.append({"wildcard": {"url.keyword": f"*{base_no_query}*"}})

    host_candidate = None
    if "://" in value:
        try:
            host_candidate = value.split("://", 1)[1].split("/", 1)[0]
        except Exception:
            host_candidate = None

    if host_candidate:
        should.append({"term": {"host.keyword": host_candidate}})
        should.append({"wildcard": {"host.keyword": f"*{host_candidate}*"}})
        should.append({"wildcard": {"url.keyword": f"*{host_candidate}*"}})
    else:
        should.append({"wildcard": {"host.keyword": f"*{value}*"}})
        should.append({"wildcard": {"url.keyword": f"*{value}*"}})

    return {
        "bool": {
            "should": should,
            "minimum_should_match": 1,
        }
    }


def _search_single_onion(value: str) -> Dict[str, Any]:
    """
    Manuelle Suche nach einer Seite (für /api/onions/lookup).
    value kann sein:
      - komplette URL (http/https)
      - Host (z.B. account.proton.me)
      - reine .onion-Adresse
    """
    value = value.strip()
    if not value:
        raise HTTPException(status_code=400, detail="Empty query")

    body = {
        "size": 1,
        "query": _build_fuzzy_query(value),
        "sort": [{"extracted_at": "desc"}],
    }

    res = os_client.search(index=OS_INDEX_PAGES, body=body)
    hits = res.get("hits", {}).get("hits", [])

    if not hits:
        raise HTTPException(status_code=404, detail="Onion not found")

    return hits[0]["_source"]


# ----------------------------------------------------
# Routes: UI
# ----------------------------------------------------
@app.get("/", include_in_schema=False)
async def dashboard_root():
    if not os.path.isfile(HTML_DASHBOARD):
        raise HTTPException(status_code=500, detail="onion-dashboard.html not found")
    return FileResponse(HTML_DASHBOARD, media_type="text/html")


@app.get("/onion-dashboard", include_in_schema=False)
async def dashboard_alias():
    if not os.path.isfile(HTML_DASHBOARD):
        raise HTTPException(status_code=500, detail="onion-dashboard.html not found")
    return FileResponse(HTML_DASHBOARD, media_type="text/html")


# ----------------------------------------------------
# Routes: API – Health & Pages
# ----------------------------------------------------
@app.get("/api/health")
async def api_health():
    try:
        info = os_client.info()
        return {
            "ok": True,
            "cluster_name": info.get("cluster_name"),
            "version": info.get("version", {}).get("number"),
            "host": OS_HOST,
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}


@app.get("/api/onions/list")
async def api_list_onions(
    offset: int = Query(0, ge=0),
    size: int = Query(1, ge=1, le=100),
):
    """
    Liefert eine Seitenliste aus onion_pages, sortiert nach extracted_at (neueste zuerst).
    Wird von den Pfeiltasten wie folgt benutzt:
      GET /api/onions/list?offset=N&size=1
    """
    body = {
        "from": offset,
        "size": size,
        "sort": [{"extracted_at": "desc"}],
        "query": {"match_all": {}},
        "track_total_hits": True,
    }

    try:
        res = os_client.search(index=OS_INDEX_PAGES, body=body)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Search error: {e}")

    hits = res.get("hits", {}).get("hits", [])
    total = res.get("hits", {}).get("total", {}).get("value", 0)

    items: List[Dict[str, Any]] = []
    for h in hits:
        src = h["_source"]
        items.append(_doc_to_onion_response(src))

    return {
        "offset": offset,
        "size": size,
        "returned": len(items),
        "total": total,
        "items": items,
    }


@app.get("/api/onions/lookup")
async def api_lookup_onion(q: str = Query(..., description="URL, Host oder Onion-Adresse")):
    """
    Manuelle Suche, z.B. für Eingaben im Suchfeld.
    """
    try:
        doc = _search_single_onion(q)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Search error: {e}")

    return JSONResponse(_doc_to_onion_response(doc))


# ----------------------------------------------------
# Routes: Scan-Status
# ----------------------------------------------------
@app.get("/api/onions/{onion}/scan-status")
async def api_scan_status(onion: str):
    """
    Liefert zusammengefassten Scan-Status aus onion_scans für einen Host.
    Wir suchen nach Dokumenten, bei denen 'onion' entweder:
      - exakt der Host ist (hiddenxxx.onion)
      - oder http://Host
      - oder http://Host/
    ist.
    """
    host = _normalize_onion_host(onion)
    if not host:
        raise HTTPException(status_code=400, detail="Empty onion host")

    candidates = [host, f"http://{host}", f"http://{host}/"]
    should = [{"term": {"onion.keyword": v}} for v in candidates]

    body = {
        "size": 50,
        "query": {
            "bool": {
                "should": should,
                "minimum_should_match": 1,
            }
        },
        "sort": [
            {"finished_at": {"order": "desc"}},
            {"started_at": {"order": "desc"}},
        ],
    }

    try:
        res = os_client.search(index=OS_INDEX_SCANS, body=body)
    except NotFoundError:
        # Index existiert noch nicht -> einfach "keine Scan-Daten"
        return {"has_scans": False, "scans": []}
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Scan status query failed: {e}",
        )

    hits = res.get("hits", {}).get("hits", [])
    if not hits:
        return {"has_scans": False, "scans": []}

    scans_by_type: Dict[str, Dict[str, Any]] = {}

    for h in hits:
        src = h.get("_source", {}) or {}
        scan_type = src.get("scan_type") or "unknown"
        if scan_type in scans_by_type:
            # durch Sortierung ist der erste Treffer pro scan_type immer der aktuellste
            continue

        tool = src.get("tool")
        started_at = src.get("started_at")
        finished_at = src.get("finished_at")
        entry_count = src.get("entry_count")
        port_count = src.get("port_count")
        error = src.get("error")

        # einfacher Status:
        status = "ok"
        if error:
            status = "error"
        elif (entry_count is not None and entry_count == 0) or (port_count is not None and port_count == 0):
            status = "empty"

        scans_by_type[scan_type] = {
            "scan_type": scan_type,
            "tool": tool,
            "started_at": started_at,
            "finished_at": finished_at,
            "status": status,
            "entry_count": entry_count,
            "port_count": port_count,
        }

    return {
        "has_scans": True,
        "scans": list(scans_by_type.values()),
    }
