# plugins/indicator_store.py
import os
import sqlite3
import time
from pathlib import Path
from typing import Dict, List, Tuple

DATA_DIR = Path(os.getenv("DATA_DIR", "/app/data"))
STATE_DIR = Path("state")
STATE_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = STATE_DIR / "indicators.db"

_conn = sqlite3.connect(DB_PATH, check_same_thread=False)
_cur = _conn.cursor()

# Tabellen
_cur.execute("""
CREATE TABLE IF NOT EXISTS wallets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  address TEXT UNIQUE,
  type TEXT
)
""")

_cur.execute("""
CREATE TABLE IF NOT EXISTS wallet_usage (
  wallet_id INTEGER,
  url TEXT,
  first_seen INTEGER,
  last_seen INTEGER,
  PRIMARY KEY(wallet_id, url)
)
""")

_cur.execute("""
CREATE TABLE IF NOT EXISTS pgp (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  fingerprint TEXT UNIQUE
)
""")

_cur.execute("""
CREATE TABLE IF NOT EXISTS pgp_usage (
  pgp_id INTEGER,
  url TEXT,
  first_seen INTEGER,
  last_seen INTEGER,
  PRIMARY KEY(pgp_id, url)
)
""")

_conn.commit()


def _get_or_create_wallet(address: str, wtype: str) -> int:
    cur = _conn.cursor()
    cur.execute("SELECT id FROM wallets WHERE address=?", (address,))
    row = cur.fetchone()
    if row:
        return row[0]
    cur.execute("INSERT INTO wallets(address,type) VALUES(?,?)", (address, wtype))
    _conn.commit()
    return cur.lastrowid


def _get_or_create_pgp(fp: str) -> int:
    cur = _conn.cursor()
    cur.execute("SELECT id FROM pgp WHERE fingerprint=?", (fp,))
    row = cur.fetchone()
    if row:
        return row[0]
    cur.execute("INSERT INTO pgp(fingerprint) VALUES(?)", (fp,))
    _conn.commit()
    return cur.lastrowid


def upsert_indicators(url: str, wallets: Dict[str, list], pgps: List[dict]):
    """
    Wird von main.py für jede Seite aufgerufen.
    Speichert Wallet- und PGP-Usage für spätere Korrelationen.
    """
    if not url:
        return
    now = int(time.time())
    cur = _conn.cursor()

    # Wallets
    for wtype, addr_list in (wallets or {}).items():
        for addr in addr_list:
            if not addr:
                continue
            wid = _get_or_create_wallet(addr, wtype)
            cur.execute(
                """
                INSERT INTO wallet_usage(wallet_id,url,first_seen,last_seen)
                VALUES (?,?,?,?)
                ON CONFLICT(wallet_id,url) DO UPDATE SET last_seen=excluded.last_seen
                """,
                (wid, url, now, now),
            )

    # PGP
    for p in pgps or []:
        fp = p.get("fingerprint")
        if not fp:
            continue
        pid = _get_or_create_pgp(fp)
        cur.execute(
            """
            INSERT INTO pgp_usage(pgp_id,url,first_seen,last_seen)
            VALUES (?,?,?,?)
            ON CONFLICT(pgp_id,url) DO UPDATE SET last_seen=excluded.last_seen
            """,
            (pid, url, now, now),
        )

    _conn.commit()


# ------------------------
# Correlation-Helper (für CLI / Notebook / spätere Tools)
# ------------------------

def find_sites_by_wallet(address: str) -> List[Tuple[str, int, int]]:
    """
    Alle Sites, die dieselbe Wallet-Adresse nutzen.
    Rückgabe: [(url, first_seen, last_seen), ...]
    """
    cur = _conn.cursor()
    cur.execute(
        """
        SELECT u.url, u.first_seen, u.last_seen
        FROM wallets w
        JOIN wallet_usage u ON u.wallet_id = w.id
        WHERE w.address = ?
        ORDER BY u.first_seen ASC
        """,
        (address,),
    )
    return cur.fetchall()


def find_wallets_with_reuse(min_sites: int = 2) -> List[Tuple[str, str, int]]:
    """
    Wallets, die auf >= min_sites verschiedenen Sites auftauchen.
    Rückgabe: [(address, type, site_count), ...]
    """
    cur = _conn.cursor()
    cur.execute(
        """
        SELECT w.address, w.type, COUNT(u.url) as c
        FROM wallets w
        JOIN wallet_usage u ON u.wallet_id = w.id
        GROUP BY w.id
        HAVING c >= ?
        ORDER BY c DESC
        """,
        (min_sites,),
    )
    return cur.fetchall()


def find_sites_by_pgp(fingerprint: str) -> List[Tuple[str, int, int]]:
    cur = _conn.cursor()
    cur.execute(
        """
        SELECT u.url, u.first_seen, u.last_seen
        FROM pgp p
        JOIN pgp_usage u ON u.pgp_id = p.id
        WHERE p.fingerprint = ?
        ORDER BY u.first_seen ASC
        """,
        (fingerprint,),
    )
    return cur.fetchall()


def find_pgp_with_reuse(min_sites: int = 2) -> List[Tuple[str, int]]:
    cur = _conn.cursor()
    cur.execute(
        """
        SELECT p.fingerprint, COUNT(u.url) as c
        FROM pgp p
        JOIN pgp_usage u ON u.pgp_id = p.id
        GROUP BY p.id
        HAVING c >= ?
        ORDER BY c DESC
        """,
        (min_sites,),
    )
    return cur.fetchall()
