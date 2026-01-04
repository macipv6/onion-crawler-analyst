# analyst/scanner.py
import os
import datetime
import json
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from opensearchpy import OpenSearch

# -------------------------------
# Konfiguration
# -------------------------------
OS_HOST = os.getenv("OS_HOST", "http://opensearch:9200")
OS_USERNAME = os.getenv("OS_USERNAME") or None
OS_PASSWORD = os.getenv("OS_PASSWORD") or None
OS_INDEX_SCANS = os.getenv("OS_INDEX_SCANS", "onion_scans")
OS_INDEX_PAGES = os.getenv("OS_INDEX_PAGES", "onion_pages")

FFUF_WORDLIST = os.getenv("FFUF_WORDLIST", "/app/analyst/wordlists/onion_small.txt")
FFUF_THREADS = int(os.getenv("FFUF_THREADS", "5"))
FFUF_TIMEOUT = int(os.getenv("FFUF_TIMEOUT", "20"))

NMAP_PORTS = os.getenv("NMAP_PORTS", "1-1000")

SCAN_MAX_RETRIES = int(os.getenv("SCAN_MAX_RETRIES", "2"))

router = APIRouter(prefix="/api/onions", tags=["onion-scans"])


def get_os_client() -> OpenSearch:
    auth = (OS_USERNAME, OS_PASSWORD) if OS_USERNAME and OS_PASSWORD else None
    return OpenSearch(
        hosts=[OS_HOST],
        http_auth=auth,
        verify_certs=False,
        timeout=30,
        max_retries=3,
        retry_on_timeout=True,
    )


os_client = get_os_client()


# -------------------------------
# Modelle
# -------------------------------
class DirEntry(BaseModel):
    path: str
    status: int
    length: Optional[int] = None


class DirScanResult(BaseModel):
    onion: str
    started_at: datetime.datetime
    finished_at: datetime.datetime
    tool: str
    entries: List[DirEntry]


class NmapScript(BaseModel):
    id: str
    output: str


class NmapPort(BaseModel):
    port: int
    proto: str
    state: str
    service: Optional[str] = None
    scripts: List[NmapScript] = []


class NmapScanResult(BaseModel):
    onion: str
    started_at: datetime.datetime
    finished_at: datetime.datetime
    ports: List[NmapPort]
    raw_xml: Optional[str] = None


# -------------------------------
# Helper
# -------------------------------
def _normalize_onion_on_url(onion: str) -> str:
    onion = onion.strip()
    if onion.startswith("http://") or onion.startswith("https://"):
        return onion.rstrip("/")
    return f"http://{onion.rstrip('/')}"


def _normalize_onion_host(onion: str) -> str:
    """Für nmap und Index-Feld: Host ohne http:// und ohne Pfad"""
    o = onion.strip()
    if o.startswith("http://") or o.startswith("https://"):
        o = o.split("://", 1)[1]
    return o.split("/", 1)[0]


def _index_scan_result(scan_type: str, onion: str, payload: Dict[str, Any]) -> None:
    """
    Schreibt ein Scan-Dokument in den Index OS_INDEX_SCANS.
    onion = Host ohne Schema, z.B. hiddenxyz.onion
    """
    doc = {
        "scan_type": scan_type,
        "onion": onion,
        **payload,
    }
    os_client.index(index=OS_INDEX_SCANS, body=doc, refresh=True)


# -------------------------------
# ffuf Dirbusting via Tor/proxychains
# -------------------------------
def _run_ffuf_dirscan_sync(base_url: str) -> List[DirEntry]:
    """
    Führt ffuf aus und gibt eine Liste DirEntry zurück.
    Wirft HTTPException bei Fehlern, inkl. stderr-Info.
    """
    if not os.path.isfile(FFUF_WORDLIST):
        raise HTTPException(
            status_code=500,
            detail=f"FFUF wordlist not found: {FFUF_WORDLIST}",
        )

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        out_file = tmp.name

    cmd = [
        "proxychains4",
        "ffuf",
        "-u",
        f"{base_url}/FUZZ",
        "-w",
        FFUF_WORDLIST,
        "-of",
        "json",
        "-o",
        out_file,
        "-t",
        str(FFUF_THREADS),
        "-timeout",
        str(FFUF_TIMEOUT),
        "-sa",  # stop on all errors
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
        )
    except subprocess.TimeoutExpired as e:
        raise HTTPException(status_code=504, detail=f"ffuf scan timed out: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"ffuf failed to start: {e}")

    try:
        with open(out_file, "r", encoding="utf-8") as f:
            raw = f.read()
    finally:
        try:
            os.unlink(out_file)
        except OSError:
            pass

    if not raw.strip():
        stderr = (proc.stderr or "").strip()
        raise HTTPException(
            status_code=500,
            detail=f"ffuf output empty (rc={proc.returncode}). stderr: {stderr[:300]}",
        )

    try:
        data = json.loads(raw)
    except Exception as e:
        stderr = (proc.stderr or "").strip()
        raise HTTPException(
            status_code=500,
            detail=f"ffuf output parse error (rc={proc.returncode}): {e}; stderr: {stderr[:300]}",
        )

    results = data.get("results", []) or []
    entries: List[DirEntry] = []

    for r in results:
        url = r.get("url") or ""
        status = int(r.get("status", 0))
        length = r.get("length")

        path = "/"
        if "://" in url:
            try:
                path = "/" + url.split("://", 1)[1].split("/", 1)[1]
            except Exception:
                path = "/"

        entries.append(
            DirEntry(
                path=path,
                status=status,
                length=length,
            )
        )

    return entries


# -------------------------------
# gobuster Dirbusting via Tor/proxychains
# -------------------------------
def _run_gobuster_dirscan_sync(base_url: str) -> List[DirEntry]:
    if not os.path.isfile(FFUF_WORDLIST):
        raise HTTPException(
            status_code=500,
            detail=f"Wordlist not found: {FFUF_WORDLIST}",
        )

    cmd = [
        "proxychains4",
        "gobuster",
        "dir",
        "-u",
        base_url,
        "-w",
        FFUF_WORDLIST,
        "-q",  # quiet (kein Progress)
        "-z",  # keine Fortschrittsanzeige
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
        )
    except subprocess.TimeoutExpired as e:
        raise HTTPException(status_code=504, detail=f"gobuster scan timed out: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"gobuster failed to start: {e}")

    entries: List[DirEntry] = []

    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        # typische Zeile: /admin (Status: 200) [Size: 1234]
        if not line.startswith("/"):
            continue
        try:
            path = line.split(" ", 1)[0]
            status_part = line.split("Status:", 1)[1].split(")", 1)[0]
            status = int(status_part.strip())
        except Exception:
            continue

        entries.append(DirEntry(path=path, status=status))

    # Wenn wirklich gar nichts gefunden wurde, kann das trotzdem "ok" sein
    return entries


# -------------------------------
# nmap Port + --script vuln via Tor/proxychains
# -------------------------------
def _run_nmap_vuln_sync(onion_host: str) -> NmapScanResult:
    started = datetime.datetime.utcnow()

    cmd = [
        "proxychains4",
        "nmap",
        "-sT",
        "-Pn",
        "-T2",
        "--script",
        "vuln",
        "-p",
        NMAP_PORTS,
        "-oX",
        "-",
        onion_host,
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=1800,
        )
    except subprocess.TimeoutExpired as e:
        raise HTTPException(status_code=504, detail=f"nmap scan timed out: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"nmap failed to start: {e}")

    if not proc.stdout.strip():
        stderr = (proc.stderr or "").strip()
        raise HTTPException(
            status_code=500,
            detail=f"nmap produced no XML output (rc={proc.returncode}). stderr: {stderr[:300]}",
        )

    xml = proc.stdout
    ports: List[NmapPort] = []

    try:
        root = ET.fromstring(xml)
        for host in root.findall("host"):
            ports_el = host.find("ports")
            if ports_el is None:
                continue
            for p in ports_el.findall("port"):
                portid = int(p.attrib.get("portid", "0"))
                proto = p.attrib.get("protocol", "tcp")
                state_el = p.find("state")
                state = state_el.attrib.get("state") if state_el is not None else "unknown"
                service_el = p.find("service")
                service = (
                    service_el.attrib.get("name") if service_el is not None else None
                )

                scripts: List[NmapScript] = []
                for s in p.findall("script"):
                    sid = s.attrib.get("id", "")
                    out = s.attrib.get("output", "")
                    scripts.append(NmapScript(id=sid, output=out))

                ports.append(
                    NmapPort(
                        port=portid,
                        proto=proto,
                        state=state,
                        service=service,
                        scripts=scripts,
                    )
                )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"nmap XML parse error: {e}")

    finished = datetime.datetime.utcnow()

    return NmapScanResult(
        onion=onion_host,
        started_at=started,
        finished_at=finished,
        ports=ports,
        raw_xml=xml,
    )


# -------------------------------
# Single-Tool Scan mit Retry + Index
# -------------------------------
def _scan_ffuf(onion: str, max_retries: int = SCAN_MAX_RETRIES) -> Dict[str, Any]:
    onion_host = _normalize_onion_host(onion)
    base_url = _normalize_onion_on_url(onion)
    started = datetime.datetime.utcnow()
    attempts = 0
    last_error: Optional[str] = None
    entries: List[DirEntry] = []

    while attempts < max_retries:
        attempts += 1
        try:
            entries = _run_ffuf_dirscan_sync(base_url)
            last_error = None
            break
        except HTTPException as e:
            last_error = str(e.detail)
        except Exception as e:
            last_error = str(e)

    finished = datetime.datetime.utcnow()
    status = "ok" if last_error is None else "error"

    payload: Dict[str, Any] = {
        "status": status,
        "url": base_url,
        "started_at": started.isoformat(),
        "finished_at": finished.isoformat(),
        "attempts": attempts,
    }

    if status == "ok":
        payload["entry_count"] = len(entries)
        payload["entries"] = [e.model_dump() for e in entries]
    else:
        payload["error"] = last_error or "unknown error"

    _index_scan_result("dir_ffuf", onion_host, payload)

    return {
        "status": status,
        "onion": onion_host,
        "url": base_url,
        "started_at": started,
        "finished_at": finished,
        "attempts": attempts,
        "entries": entries,
        "error": last_error,
    }


def _scan_gobuster(onion: str, max_retries: int = SCAN_MAX_RETRIES) -> Dict[str, Any]:
    onion_host = _normalize_onion_host(onion)
    base_url = _normalize_onion_on_url(onion)
    started = datetime.datetime.utcnow()
    attempts = 0
    last_error: Optional[str] = None
    entries: List[DirEntry] = []

    while attempts < max_retries:
        attempts += 1
        try:
            entries = _run_gobuster_dirscan_sync(base_url)
            last_error = None
            break
        except HTTPException as e:
            last_error = str(e.detail)
        except Exception as e:
            last_error = str(e)

    finished = datetime.datetime.utcnow()
    status = "ok" if last_error is None else "error"

    payload: Dict[str, Any] = {
        "status": status,
        "url": base_url,
        "started_at": started.isoformat(),
        "finished_at": finished.isoformat(),
        "attempts": attempts,
    }

    if status == "ok":
        payload["entry_count"] = len(entries)
        payload["entries"] = [e.model_dump() for e in entries]
    else:
        payload["error"] = last_error or "unknown error"

    _index_scan_result("dir_gobuster", onion_host, payload)

    return {
        "status": status,
        "onion": onion_host,
        "url": base_url,
        "started_at": started,
        "finished_at": finished,
        "attempts": attempts,
        "entries": entries,
        "error": last_error,
    }


def _scan_nmap(onion: str, max_retries: int = SCAN_MAX_RETRIES) -> Dict[str, Any]:
    onion_host = _normalize_onion_host(onion)
    started = datetime.datetime.utcnow()
    attempts = 0
    last_error: Optional[str] = None
    result: Optional[NmapScanResult] = None

    while attempts < max_retries:
        attempts += 1
        try:
            result = _run_nmap_vuln_sync(onion_host)
            last_error = None
            break
        except HTTPException as e:
            last_error = str(e.detail)
        except Exception as e:
            last_error = str(e)

    finished = datetime.datetime.utcnow()
    status = "ok" if last_error is None else "error"

    payload: Dict[str, Any] = {
        "status": status,
        "started_at": started.isoformat(),
        "finished_at": finished.isoformat(),
        "attempts": attempts,
    }

    if status == "ok" and result is not None:
        payload["port_count"] = len(result.ports)
        payload["ports"] = [p.model_dump() for p in result.ports]
        payload["raw_xml"] = result.raw_xml
    else:
        payload["error"] = last_error or "unknown error"

    _index_scan_result("nmap_vuln", onion_host, payload)

    return {
        "status": status,
        "onion": onion_host,
        "started_at": started,
        "finished_at": finished,
        "attempts": attempts,
        "ports": [] if result is None else result.ports,
        "error": last_error,
    }


# -------------------------------
# Auto-Scan-Helper für Background-Worker
# -------------------------------
REQUIRED_SCAN_TYPES = {"dir_ffuf", "dir_gobuster", "nmap_vuln"}


def find_unscanned_hosts(limit: int = 10) -> List[str]:
    """
    Sucht in onion_pages nach Hosts, für die NICHT alle REQUIRED_SCAN_TYPES
    in onion_scans vorhanden sind.
    Erwartet ein Feld 'host' im Index onion_pages.
    """
    body = {
        "size": 0,
        "aggs": {
            "hosts": {
                "terms": {
                    "field": "host.keyword",
                    "size": 1000,
                }
            }
        },
    }

    try:
        res = os_client.search(index=OS_INDEX_PAGES, body=body)
    except Exception as e:
        print(f"[AUTO-SCAN] host aggregation error: {e}")
        return []

    buckets = res.get("aggregations", {}).get("hosts", {}).get("buckets", [])
    candidates: List[str] = []

    for b in buckets:
        host = b.get("key")
        if not host:
            continue
        # Optional: nur .onion
        if not host.endswith(".onion"):
            continue

        # Prüfen, welche scan_types es schon gibt
        q = {
            "size": 100,
            "query": {
                "term": {
                    "onion.keyword": host
                }
            },
        }

        try:
            scan_res = os_client.search(index=OS_INDEX_SCANS, body=q)
        except Exception:
            # wenn der Index noch nicht existiert, ist alles ungescannt
            candidates.append(host)
            if len(candidates) >= limit:
                break
            continue

        hits = scan_res.get("hits", {}).get("hits", [])
        existing_types = {h["_source"].get("scan_type") for h in hits if "_source" in h}
        existing_types.discard(None)

        if not REQUIRED_SCAN_TYPES.issubset(existing_types):
            candidates.append(host)

        if len(candidates) >= limit:
            break

    return candidates


def run_all_scans_for_onion(onion_host: str) -> Dict[str, Any]:
    """
    Führt ffuf, gobuster und nmap für einen Host aus.
    onion_host: z.B. abcdefg.onion (ohne http://)
    """
    results: Dict[str, Any] = {}
    base_url = _normalize_onion_on_url(onion_host)
    host_only = _normalize_onion_host(onion_host)

    print(f"[AUTO-SCAN] ffuf for {base_url}")
    ffuf_res = _scan_ffuf(host_only)
    results["ffuf"] = ffuf_res

    print(f"[AUTO-SCAN] gobuster for {base_url}")
    gobuster_res = _scan_gobuster(host_only)
    results["gobuster"] = gobuster_res

    print(f"[AUTO-SCAN] nmap --script vuln for {host_only}")
    nmap_res = _scan_nmap(host_only)
    results["nmap"] = nmap_res

    return results


# -------------------------------
# FastAPI-Routen – Status (inkl. Prozent, Samples, Timeline)
# -------------------------------
@router.get("/{onion}/scan-status")
def get_scan_status(onion: str) -> Dict[str, Any]:
    """
    Liefert pro Host und Scan-Typ die *letzte* Scan-Zusammenfassung.

    Zusätzlich:
      - dir_ffuf / dir_gobuster: sample_entries (erste 10 Pfade)
      - nmap_vuln: sample_ports (erste 10 Ports)
      - progress: Prozent, success/fail/pending
      - timeline: Liste der letzten Scans (Typ, Status, Zeit)
    """
    host = _normalize_onion_host(onion) or onion.strip()
    if not host:
        raise HTTPException(status_code=400, detail="Empty onion host")

    query = {
        "size": 200,
        "query": {
            "term": {
                "onion.keyword": host
            }
        },
        "sort": [
            {"finished_at": {"order": "desc"}},
            {"started_at": {"order": "desc"}},
        ],
    }

    try:
        res = os_client.search(index=OS_INDEX_SCANS, body=query)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Scan status query failed: {e}",
        )

    hits = res.get("hits", {}).get("hits", [])
    types: Dict[str, Dict[str, Any]] = {}
    timeline: List[Dict[str, Any]] = []
    last_scan_ts: Optional[str] = None

    for h in hits:
        src = h.get("_source", {})
        scan_type = src.get("scan_type")
        if not scan_type:
            continue

        finished = src.get("finished_at") or src.get("started_at")

        # Timeline-Eintrag aufbauen
        timeline.append(
            {
                "scan_type": scan_type,
                "status": src.get("status", "unknown"),
                "started_at": src.get("started_at"),
                "finished_at": finished,
                "attempts": src.get("attempts", 1),
                "entry_count": src.get("entry_count"),
                "port_count": src.get("port_count"),
                "error": src.get("error"),
            }
        )

        if finished and (last_scan_ts is None or finished > last_scan_ts):
            last_scan_ts = finished

        # Nur den jeweils neuesten Eintrag je scan_type behalten
        prev = types.get(scan_type)
        if prev:
            prev_finished = prev.get("finished_at") or prev.get("started_at")
            if prev_finished and finished and finished <= prev_finished:
                continue

        entry: Dict[str, Any] = {
            "status": src.get("status", "unknown"),
            "started_at": src.get("started_at"),
            "finished_at": finished,
            "attempts": src.get("attempts", 1),
            "entry_count": src.get("entry_count"),
            "port_count": src.get("port_count"),
            "error": src.get("error"),
        }

        # Sample-Details aus den gespeicherten Daten ziehen
        if scan_type in ("dir_ffuf", "dir_gobuster"):
            entries = src.get("entries") or []
            entry["sample_entries"] = entries[:10]

        if scan_type == "nmap_vuln":
            ports = src.get("ports") or []
            entry["sample_ports"] = ports[:10]

        types[scan_type] = entry

    # Progress / Prozent berechnen
    tool_keys = ["dir_ffuf", "dir_gobuster", "nmap_vuln"]
    total_tools = len(tool_keys)
    completed_types = [t for t in tool_keys if t in types]
    completed_count = len(completed_types)

    success_count = 0
    failure_count = 0
    for t in completed_types:
        s = types[t]
        if s.get("status") == "ok":
            success_count += 1
        else:
            failure_count += 1

    pending_count = total_tools - completed_count
    percent = int((completed_count / total_tools) * 100) if total_tools else 0

    if completed_count == 0:
        overall_status = "no_scans"
    elif failure_count == 0:
        overall_status = "ok"
    elif success_count == 0:
        overall_status = "error"
    else:
        overall_status = "partial_error"

    return {
        "onion": host,
        "status": overall_status,
        "last_scan": last_scan_ts,
        "progress": {
            "total_tools": total_tools,
            "completed": completed_count,
            "success": success_count,
            "failed": failure_count,
            "pending": pending_count,
            "percent": percent,
        },
        "types": types,
        "timeline": timeline[:50],
    }


@router.post("/{onion}/scan")
def trigger_full_scan(onion: str) -> Dict[str, Any]:
    """
    Startet ffuf + gobuster + nmap für einen Host und gibt danach den Status zurück.
    """
    onion_host = _normalize_onion_host(onion)
    base_url = _normalize_onion_on_url(onion_host)

    print(f"[MANUAL-SCAN] Trigger scan for {base_url}")

    # Alle drei Scans mit Retry und Fehler-Protokollierung
    _scan_ffuf(onion_host)
    _scan_gobuster(onion_host)
    _scan_nmap(onion_host)

    # Danach aktuellen Status aus dem Index holen (inkl. Prozentanzeige)
    status = get_scan_status(onion_host)
    return status
