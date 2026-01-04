# neo4j_writer.py
from __future__ import annotations

from typing import Iterable, Dict, List
from neo4j import GraphDatabase


class Neo4jWriter:
    """
    Schlanker Writer für dein Onion-Crawler-Graphschema.

    Nodes:
      - (s:Site {url, title, lang, risk, server, x_powered_by, generator,
                 favicon_hash, tls_sha256, headers_fp, template_fp, created_at, updated_at})
      - (w:Wallet {address, type, created_at})
      - (k:PGP {fingerprint, created_at})
      - (t:Topic {name})
      - (tech:Tech {name})
      - (u:Username {name})

    Relationships:
      - (s)-[:USES_WALLET]->(w)
      - (s)-[:USES_PGP]->(k)
      - (s)-[:HAS_TOPIC]->(t)
      - (s)-[:USES_TECH]->(tech)
      - (s)-[:MENTIONS_USER]->(u)
      - (s)-[:MIRROR_OF]->(m:Site)
      - (s)-[:LINKS_TO]->(t:Site)
    """

    def __init__(self, uri: str, user: str, password: str, init_schema: bool = False):
        self._driver = GraphDatabase.driver(uri, auth=(user, password))
        if init_schema:
            self._init_schema()

    def close(self):
        self._driver.close()

    def ping(self) -> bool:
        with self._driver.session() as session:
            rec = session.run("RETURN 1 AS ok").single()
            return bool(rec and rec["ok"] == 1)

    def _init_schema(self):
        """
        Legt Constraints an (idempotent).
        """
        stmts = [
            "CREATE CONSTRAINT IF NOT EXISTS FOR (s:Site) REQUIRE s.url IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (w:Wallet) REQUIRE w.address IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (k:PGP) REQUIRE k.fingerprint IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (t:Topic) REQUIRE t.name IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (x:Tech) REQUIRE x.name IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (u:Username) REQUIRE u.name IS UNIQUE",
        ]
        with self._driver.session() as session:
            for cy in stmts:
                session.run(cy)

    # ---------------- Public API ----------------

    def upsert_site_bundle(self, site: Dict):
        """
        Erwartet denselben Dict wie aus main.py:

        site = {
          "url": str,
          "title": str|None,
          "lang": str|None,
          "server": str|None,
          "x_powered_by": str|None,
          "generator": str|None,
          "topics": list[str],
          "tech": list[str],
          "wallets": {"BTC":[...], "ETH":[...], ...},
          "pgp_keys": [{"fingerprint": "...", ...}, ...],
          "usernames": list[str],
          "mirrors": list[str],
          "links": list[str],
          "risk": int,
          "favicon_hash": str|None,
          "tls_sha256": str|None,
          "headers_fp": str|None,
          "template_fp": str|None,
        }
        """
        with self._driver.session() as session:
            session.execute_write(self._upsert_site_bundle_tx, site)

    def add_links_mixed(self, source_url: str, targets: Iterable[str]):
        """
        Fügt nur Kanten (Site)-[:LINKS_TO]->(Site) hinzu.
        Wird u. a. für Legacy-Import (data_copy/links_*.json) verwendet.
        """
        with self._driver.session() as session:
            session.execute_write(self._add_links_mixed_tx, source_url, list(targets))

    # ---------------- TX-Funktionen ----------------

    @staticmethod
    def _upsert_site_bundle_tx(tx, site: Dict):
        url = site.get("url")
        if not url:
            return

        title = site.get("title")
        lang = site.get("lang")
        risk = int(site.get("risk") or 0)
        server = site.get("server")
        xpb = site.get("x_powered_by")
        generator = site.get("generator")
        favicon_hash = site.get("favicon_hash")
        tls_sha256 = site.get("tls_sha256")
        headers_fp = site.get("headers_fp")
        template_fp = site.get("template_fp")

        topics: List[str] = site.get("topics") or []
        techs: List[str] = site.get("tech") or []
        wallets: Dict[str, List[str]] = site.get("wallets") or {}
        pgps: List[Dict] = site.get("pgp_keys") or []
        usernames: List[str] = site.get("usernames") or []
        mirrors: List[str] = site.get("mirrors") or []
        links: List[str] = site.get("links") or []

        # Site Node
        tx.run(
            """
            MERGE (s:Site {url: $url})
            ON CREATE SET s.created_at = timestamp()
            SET s.title        = $title,
                s.lang         = $lang,
                s.risk         = $risk,
                s.server       = $server,
                s.x_powered_by = $xpb,
                s.generator    = $generator,
                s.favicon_hash = $favicon_hash,
                s.tls_sha256   = $tls_sha256,
                s.headers_fp   = $headers_fp,
                s.template_fp  = $template_fp,
                s.updated_at   = timestamp()
            """,
            url=url,
            title=title,
            lang=lang,
            risk=risk,
            server=server,
            xpb=xpb,
            generator=generator,
            favicon_hash=favicon_hash,
            tls_sha256=tls_sha256,
            headers_fp=headers_fp,
            template_fp=template_fp,
        )

        # Topics
        for t in topics:
            if not t:
                continue
            tx.run(
                """
                MERGE (c:Topic {name: $name})
                MERGE (s:Site {url: $url})-[:HAS_TOPIC]->(c)
                """,
                name=t,
                url=url,
            )

        # Tech
        for t in techs:
            if not t:
                continue
            tx.run(
                """
                MERGE (tech:Tech {name: $name})
                MERGE (s:Site {url: $url})-[:USES_TECH]->(tech)
                """,
                name=t,
                url=url,
            )

        # Wallets
        for wtype, addr_list in wallets.items():
            for addr in addr_list:
                if not addr:
                    continue
                tx.run(
                    """
                    MERGE (w:Wallet {address: $addr})
                    ON CREATE SET w.type = $wtype, w.created_at = timestamp()
                    SET w.type = COALESCE(w.type, $wtype)
                    MERGE (s:Site {url: $url})-[:USES_WALLET]->(w)
                    """,
                    addr=addr,
                    wtype=wtype,
                    url=url,
                )

        # PGP Keys
        for p in pgps:
            fp = p.get("fingerprint")
            if not fp:
                continue
            tx.run(
                """
                MERGE (k:PGP {fingerprint: $fp})
                ON CREATE SET k.created_at = timestamp()
                MERGE (s:Site {url: $url})-[:USES_PGP]->(k)
                """,
                fp=fp,
                url=url,
            )

        # Usernames
        for u in usernames:
            if not u:
                continue
            tx.run(
                """
                MERGE (u:Username {name: $name})
                MERGE (s:Site {url: $url})-[:MENTIONS_USER]->(u)
                """,
                name=u,
                url=url,
            )

        # Mirrors
        for m in mirrors:
            if not m:
                continue
            tx.run(
                """
                MERGE (m:Site {url: $mirror})
                MERGE (s:Site {url: $url})-[:MIRROR_OF]->(m)
                """,
                mirror=m,
                url=url,
            )

        # Outgoing Links
        for tgt in links:
            if not tgt:
                continue
            tx.run(
                """
                MERGE (t:Site {url: $target})
                MERGE (s:Site {url: $url})-[:LINKS_TO]->(t)
                """,
                target=tgt,
                url=url,
            )

    @staticmethod
    def _add_links_mixed_tx(tx, source_url: str, targets: List[str]):
        if not source_url or not targets:
            return
        for t in targets:
            if not t:
                continue
            tx.run(
                """
                MERGE (s:Site {url: $url})
                MERGE (t:Site {url: $target})
                MERGE (s)-[:LINKS_TO]->(t)
                """,
                url=source_url,
                target=t,
            )
