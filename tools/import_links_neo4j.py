#!/usr/bin/env python3
import json
import glob
from pathlib import Path
from neo4j import GraphDatabase

NEO4J_URI = "bolt://neo4j:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "ChangeThis!Strong#2025"

DATA_DIR = Path("/docker/onion-search-starter/data_copy")

driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

def import_file(session, path: Path):
    with path.open("r", encoding="utf-8") as f:
        doc = json.load(f)

    source = doc.get("source")
    targets = doc.get("targets", [])
    context = doc.get("context", "page")
    ts = doc.get("ts")

    if not source or not targets:
        return

    for tgt in targets:
        session.run(
            """
            MERGE (s:Site {url: $source})
            MERGE (t:Site {url: $target})
            MERGE (s)-[r:LINKS_TO]->(t)
            SET r.context = $context,
                r.ts = $ts
            """,
            source=source,
            target=tgt,
            context=context,
            ts=ts,
        )

def main():
    with driver.session() as session:
        for path in DATA_DIR.glob("links_*.json"):
            print(f"Importing {path}")
            import_file(session, path)

if __name__ == "__main__":
    main()
