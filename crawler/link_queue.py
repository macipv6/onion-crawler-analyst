import sqlite3, time, threading, os
from urllib.parse import urlparse

DDL = """
CREATE TABLE IF NOT EXISTS queue(
  url TEXT PRIMARY KEY,
  added_at INTEGER,
  priority INTEGER DEFAULT 100,
  tries INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS visited(
  url TEXT PRIMARY KEY,
  status INTEGER,
  last_seen INTEGER
);
"""

class LinkQueue:
    def __init__(self, db_path:str):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self.db.executescript(DDL)
        self.lock = threading.Lock()

    def add(self, url:str, priority:int=100):
        if not url or not urlparse(url).scheme:
            return
        with self.lock:
            self.db.execute("INSERT OR IGNORE INTO queue(url,added_at,priority) VALUES(?,?,?)",
                            (url, int(time.time()), priority))
            self.db.commit()

    def batch_add(self, urls, priority:int=100):
        with self.lock:
            self.db.executemany("INSERT OR IGNORE INTO queue(url,added_at,priority) VALUES(?,?,?)",
                                [(u, int(time.time()), priority) for u in urls])
            self.db.commit()

    def pop(self):
        with self.lock:
            cur = self.db.execute("SELECT url FROM queue ORDER BY priority ASC, added_at ASC LIMIT 1")
            row = cur.fetchone()
            if not row:
                return None
            url = row[0]
            self.db.execute("DELETE FROM queue WHERE url=?", (url,))
            self.db.commit()
            return url

    def mark_visited(self, url:str, status:int=200):
        with self.lock:
            self.db.execute("INSERT OR REPLACE INTO visited(url,status,last_seen) VALUES(?,?,?)",
                            (url, status, int(time.time())))
            self.db.commit()

    def seen(self, url:str)->bool:
        cur = self.db.execute("SELECT 1 FROM visited WHERE url=?", (url,))
        return cur.fetchone() is not None
