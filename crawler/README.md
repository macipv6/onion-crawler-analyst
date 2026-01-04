# Onion Intelligence Crawler

Dieses Verzeichnis enthält den eigentlichen Crawler für das `onion-search-starter`-Setup.

Der Crawler läuft im Docker-Container `crawler` und spricht über Tor, schreibt nach OpenSearch und optional nach Neo4j.

---

## Architektur

**Services (aus `docker-compose.yml`):**

- `tor`  
  - SOCKS5 (`9050`) + Control Port (`9051`)
- `opensearch`  
  - Single Node, ohne Security-Plugin (`DISABLE_SECURITY_PLUGIN=true`)
- `dashboards`  
  - OpenSearch Dashboards (UI)
- `renderer`  
  - Optionaler Screenshot-Service hinter Tor (für Thumbnails / Previews)
- `crawler`  
  - Dieses Python-Modul: Tor-Crawler + Parser + OS/Neo4j Integration
- `neo4j`  
  - Graphdatenbank für Link-/Wallet-/PGP-Hopping und Clusteranalysen

---

## Wichtige Komponenten im `crawler/`-Container

### `main.py`

- Entry-Point des Crawlers
- Verantwortlich für:
  - Frontier-Verwaltung (SQLite in `state/frontier.db`)
  - HTTP-Fetch über Tor (`requests` + `socks5h`)
  - robots.txt-Respekt (sofern erreichbar)
  - HTML-Parsing (BeautifulSoup)
  - Text-Extraktion, Language Detection (`langdetect`)
  - Risk-Bewertung (`plugins.risk`)
  - Klassifizierung (`plugins.classifier`)
  - Template-Fingerprint (`plugins.template_fp`)
  - Contact-Extraction (`plugins.contact_extractor`)
  - Wallet-/PGP-Erkennung & Indicator-Store (`plugins.indicator_store`)
  - Media-Link-Erkennung (`plugins.file_analyzer` / Media-Part)
  - Optionales Rendering über `renderer` (Preview/Thumbnail)
  - Indexing nach OpenSearch (`onion_pages`, `onion_media_links`, `onion_files`)
  - Neo4j-Befüllung (`neo4j_writer.Neo4jWriter`)
  - STIX-Export (`plugins.stix_export`)
  - Alerts (`plugins.alerts`)
  - Health-Monitoring (`plugins.health`)

### `neo4j_writer.py`

- Wrappt den Neo4j-Treiber
- Legt Constraints an (`init_schema`) und schreibt:

  - `(:Site {url,...})`
  - `(:Wallet {address,type})`
  - `(:PGP {fingerprint})`
  - `(:Topic {name})`
  - `(:Tech {name})`
  - `(:Username {name})`

- Kanten:

  - `(:Site)-[:USES_WALLET]->(:Wallet)`
  - `(:Site)-[:USES_PGP]->(:PGP)`
  - `(:Site)-[:HAS_TOPIC]->(:Topic)`
  - `(:Site)-[:USES_TECH]->(:Tech)`
  - `(:Site)-[:MENTIONS_USER]->(:Username)`
  - `(:Site)-[:MIRROR_OF]->(:Site)`
  - `(:Site)-[:LINKS_TO]->(:Site)`

### Wichtige Plugins (`crawler/plugins/`)

- `health.py`  
  - schreibt regelmäßig Health-Daten (Tor / OpenSearch / Neo4j) nach:
    - `DATA_DIR/health.jsonl`
    - optional OS-Index `onion_health`

- `indicator_store.py`  
  - eigene SQLite-DB `state/indicators.db`
  - speichert Wallet-Usage & PGP-Usage pro URL
  - bietet Helper für Wallet-/PGP-Reuse-Abfragen (für spätere Tools)

- `contact_extractor.py`  
  - simple Regex-Extraktion:
    - E-Mail
    - Matrix-IDs
    - Jabber/XMPP
    - Telegram-Links

- `file_analyzer.py`  
  - verarbeitet Non-HTML-Antworten
  - schreibt Hashes (SHA256/SHA1/MD5) und Metadaten nach:
    - `DATA_DIR/files_meta.jsonl`
    - optional OS-Index `onion_files`
  - optional YARA-Support (wenn `YARA_RULES_PATH` gesetzt)

- `stix_export.py`  
  - generiert STIX-2.1-Bundles für High-Risk-Sites
  - schreibt nach `DATA_DIR/stix/stix_*.json`
  - Schwelle über `STIX_RISK_THRESHOLD` konfigurierbar

- `alerts.py`  
  - generiert JSON-Alerts für Seiten mit hohem Risk-Score
  - `DATA_DIR/alerts.jsonl`
  - optional Webhook (`ALERT_WEBHOOK_URL`)

---

## Datenpfade

Standard gemäß `main.py`:

- `DATA_DIR` (ENV): Default `/app/data`
  - `links_*.json`              – persistierte Link-Batches
  - `media_links.jsonl`         – erkannte Media-Links
  - `files_meta.jsonl`          – Non-HTML-Datei-Metadaten
  - `stix/`                     – STIX-Bundles
  - `alerts.jsonl`              – High-Risk-Alerts
  - `health.jsonl`              – Health-Status

- `state/frontier.db`          – Frontier (URLs, Hosts, Links)
- `state/indicators.db`        – Indicator-Store (Wallets, PGP)

---

## OpenSearch Dashboards

### 1. Overview-Dashboard

Datei: `onion_dashboards.ndjson` (dieses README referenziert sie)

- Data View: `onion_pages` mit Time Field `extracted_at`
- Visualisierungen:
  - Topics-Verteilung (Pie)
  - High-Risk Sites (Table Host/Topics)
- Dashboard: `Onion Intelligence Overview`

### 2. Wallet / PGP / Media Dashboard

Datei: `onion_wallets_media_dashboard.ndjson`

- Data Views:
  - `onion_pages` (Pages)
  - `onion_media_links` (Media-Provider + Kategorien)
  - `onion_files` (Non-HTML-Files / Hashes)
- Visualisierungen:
  - BTC Wallet Reuse
  - PGP Fingerprint Reuse
  - Seiten mit Wallets pro Topic
  - Media-Provider-Verteilung
  - Media-Kategorien
  - Non-HTML-Files nach Content-Type

Import:

1. OpenSearch Dashboards öffnen (`http://localhost:5601`).
2. `Stack Management → Saved Objects → Import`.
3. `onion_dashboards.ndjson` importieren.
4. `onion_wallets_media_dashboard.ndjson` importieren.

---

## Neo4j – typische Abfragen

Beispiele (im Neo4j Browser):

**Wallet-Reuse:**

```cypher
MATCH (w:Wallet)<-[:USES_WALLET]-(s:Site)
WITH w, collect(s.url) AS sites, count(s) AS site_count
WHERE site_count >= 2
RETURN w.address AS wallet, w.type AS type, site_count, sites
ORDER BY site_count DESC
LIMIT 100;
