#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse, csv, json, os, re, sys
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlparse
import sqlite3
from collections import defaultdict

DEFAULT_DB = "state/frontier.db"
DEFAULT_JSONL = "data/media_links.jsonl"
DEFAULT_OUT = "data/reports"

def parse_args():
    ap = argparse.ArgumentParser(description="Export deduplizierte Medien-Links (Provider-Reports, Rollups).")
    ap.add_argument("--db", default=DEFAULT_DB, help="Pfad zur SQLite DB (state/frontier.db)")
    ap.add_argument("--jsonl", default=DEFAULT_JSONL, help="Zusätzliche JSONL-Quelle (data/media_links.jsonl)")
    ap.add_argument("--out", default=DEFAULT_OUT, help="Ausgabeordner")
    ap.add_argument("--from", dest="date_from", default=None, help="ab Datum (YYYY-MM-DD)")
    ap.add_argument("--to", dest="date_to", default=None, help="bis Datum inkl. (YYYY-MM-DD)")
    ap.add_argument("--providers", default=None, help="Kommagetrennte Provider-Filter (z.B. pimpandhost,pixhost)")
    ap.add_argument("--formats", default="csv,jsonl,txt", help="Ausgabeformate: csv,jsonl,txt")
    ap.add_argument("--dedupe", default="url", choices=["url","domain"], help="Deduplizierungsschlüssel")
    ap.add_argument("--rollup", action="store_true", help="Tages-Rollup erzeugen (summary_daily.csv)")
    return ap.parse_args()

def to_utc_date(ts: int) -> str:
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d")
    except Exception:
        return None

def normalize_for_dedupe(u: str, mode: str) -> str:
    """mode=url -> vollständige URL; mode=domain -> netloc + dateiname (ohne query)"""
    try:
        pu = urlparse(u)
        if mode == "url":
            # entferne Fragment, behalte Query (nützlich bei signierten Links)
            return f"{pu.scheme}://{pu.netloc}{pu.path}".lower() + (f"?{pu.query}" if pu.query else "")
        # domain mode
        fname = pu.path.rsplit("/", 1)[-1] if "/" in pu.path else pu.path
        return f"{pu.netloc.lower()}::{fname.lower()}"
    except Exception:
        return u

def mkdirp(p: Path):
    p.mkdir(parents=True, exist_ok=True)

def load_sqlite(db_path: str, date_from: str, date_to: str, providers: set|None):
    rows = []
    if not os.path.exists(db_path):
        return rows
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    where = []
    params = []
    if date_from:
        where.append("discovered_at >= strftime('%s', ?)")
        params.append(date_from + " 00:00:00")
    if date_to:
        where.append("discovered_at <= strftime('%s', ?)")
        params.append(date_to + " 23:59:59")
    if providers:
        placeholders = ",".join(["?"]*len(providers))
        where.append(f"provider IN ({placeholders})")
        params += list(providers)
    q = "SELECT url, host, provider, category, source_url, discovered_at FROM media_links"
    if where:
        q += " WHERE " + " AND ".join(where)
    for url, host, prov, cat, src, ts in cur.execute(q, params):
        rows.append({
            "url": url, "host": host or "", "provider": prov or "unknown",
            "category": cat or "unknown", "source_url": src or "", "detected_at": int(ts)
        })
    con.close()
    return rows

def load_jsonl(jsonl_path: str, date_from: str, date_to: str, providers: set|None):
    rows = []
    if not os.path.exists(jsonl_path):
        return rows
    dt_from = datetime.strptime(date_from, "%Y-%m-%d").date() if date_from else None
    dt_to = datetime.strptime(date_to, "%Y-%m-%d").date() if date_to else None
    with open(jsonl_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                j = json.loads(line)
                prov = j.get("provider") or "unknown"
                if providers and prov not in providers:
                    continue
                ts = int(j.get("detected_at") or 0)
                d = datetime.fromtimestamp(ts, tz=timezone.utc).date() if ts else None
                if dt_from and (not d or d < dt_from): continue
                if dt_to and (not d or d > dt_to): continue
                rows.append({
                    "url": j.get("url",""),
                    "host": j.get("host",""),
                    "provider": prov,
                    "category": j.get("category","unknown"),
                    "source_url": j.get("source_url",""),
                    "detected_at": ts
                })
            except Exception:
                continue
    return rows

def write_csv(path: Path, items: list[dict]):
    if not items:
        return
    keys = ["detected_at_iso","provider","category","url","source_url","host"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(keys)
        for it in items:
            iso = datetime.fromtimestamp(it["detected_at"], tz=timezone.utc).isoformat()
            w.writerow([iso, it["provider"], it["category"], it["url"], it["source_url"], it["host"]])

def write_jsonl(path: Path, items: list[dict]):
    with open(path, "w", encoding="utf-8") as f:
        for it in items:
            f.write(json.dumps(it, ensure_ascii=False) + "\n")

def write_txt(path: Path, items: list[dict]):
    with open(path, "w", encoding="utf-8") as f:
        for it in items:
            f.write(it["url"] + "\n")

def main():
    a = parse_args()
    out_dir = Path(a.out)
    mkdirp(out_dir)
    prov_filter = set([p.strip() for p in a.providers.split(",") if p.strip()]) if a.providers else None
    fmts = {x.strip() for x in a.formats.split(",") if x.strip()}

    # Laden
    data = []
    data += load_sqlite(a.db, a.date_from, a.date_to, prov_filter)
    data += load_jsonl(a.jsonl, a.date_from, a.date_to, prov_filter)

    # Dedupe
    seen = set()
    deduped = []
    for it in data:
        key = normalize_for_dedupe(it["url"], a.dedupe)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(it)

    # Gruppierung pro Provider
    by_provider = defaultdict(list)
    for it in deduped:
        by_provider[it["provider"]].append(it)

    # Ausgaben
    mkdirp(out_dir / "providers")
    date_suffix = ""
    if a.date_from or a.date_to:
        date_suffix = f"{a.date_from or ''}_{a.date_to or ''}".strip("_")

    # 1) Gesamt-Unique-Liste
    if "txt" in fmts:
        write_txt(out_dir / f"media_links_unique{('_'+date_suffix if date_suffix else '')}.txt", deduped)
    if "csv" in fmts:
        write_csv(out_dir / f"media_links_unique{('_'+date_suffix if date_suffix else '')}.csv", deduped)
    if "jsonl" in fmts:
        write_jsonl(out_dir / f"media_links_unique{('_'+date_suffix if date_suffix else '')}.jsonl", deduped)

    # 2) Provider-spezifische Dateien
    for prov, items in by_provider.items():
        safe = re.sub(r'[^a-z0-9]+', '_', prov.lower())
        if "txt" in fmts:
            write_txt(out_dir / "providers" / f"{safe}{('_'+date_suffix if date_suffix else '')}.txt", items)
        if "csv" in fmts:
            write_csv(out_dir / "providers" / f"{safe}{('_'+date_suffix if date_suffix else '')}.csv", items)
        if "jsonl" in fmts:
            write_jsonl(out_dir / "providers" / f"{safe}{('_'+date_suffix if date_suffix else '')}.jsonl", items)

    # 3) Tages-Rollup (optional)
    if a.rollup:
        summary = defaultdict(lambda: defaultdict(int))  # day -> (prov|cat) -> count
        for it in deduped:
            day = to_utc_date(it["detected_at"]) or "unknown"
            k = f"{it['provider']}|{it['category']}"
            summary[day][k] += 1
        rows = []
        for day in sorted(summary.keys()):
            for key, cnt in sorted(summary[day].items()):
                prov, cat = key.split("|", 1)
                rows.append({"day": day, "provider": prov, "category": cat, "count": cnt})
        # CSV
        p = out_dir / f"summary_daily{('_'+date_suffix if date_suffix else '')}.csv"
        with open(p, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["day","provider","category","count"])
            for r in rows:
                w.writerow([r["day"], r["provider"], r["category"], r["count"]])

    print(f"Export fertig: {out_dir}")

if __name__ == "__main__":
    main()
