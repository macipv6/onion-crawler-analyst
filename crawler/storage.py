import os, json, sqlite3, time, hashlib

DDL = """
CREATE TABLE IF NOT EXISTS links(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source_url TEXT,
  target_url TEXT,
  context TEXT,
  discovered_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_links_target ON links(target_url);

CREATE TABLE IF NOT EXISTS pages(
  url TEXT PRIMARY KEY,
  title TEXT,
  lang TEXT,
  text_hash TEXT,
  stored_at INTEGER
);
"""

class Storage:
    def __init__(self, sqlite_path:str, json_dir:str):
        self.db = sqlite3.connect(sqlite_path, check_same_thread=False)
        self.db.executescript(DDL)
        self.json_dir = json_dir
        os.makedirs(json_dir, exist_ok=True)

    def save_links(self, source_url:str, targets:list[str], context:str=""):
        now = int(time.time())
        self.db.executemany(
            "INSERT INTO links(source_url,target_url,context,discovered_at) VALUES(?,?,?,?)",
            [(source_url, t, context, now) for t in set(targets)]
        )
        self.db.commit()
        # Zusätzlich JSON export
        fname = os.path.join(self.json_dir, f"links_{now}.json")
        with open(fname, "w", encoding="utf-8") as f:
            json.dump({"source": source_url, "targets": list(set(targets)), "context": context, "ts": now}, f, ensure_ascii=False, indent=2)

    def save_page(self, url:str, title:str=None, lang:str=None, text:str=None):
        h = hashlib.sha256((text or "").encode("utf-8","ignore")).hexdigest() if text else None
        self.db.execute(
            "INSERT OR REPLACE INTO pages(url,title,lang,text_hash,stored_at) VALUES(?,?,?,?,?)",
            (url, title, lang, h, int(time.time()))
        )
        self.db.commit()
