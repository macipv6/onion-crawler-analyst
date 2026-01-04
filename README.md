
<p align="center">
  <img src="https://github.com/macipv6/onion-crawler-analyst/blob/main/assets/banner.png" alt="Onion Crawler & Analyst Banner">
</p>

# Onion Crawler • Analyst UI • Neo4j Intelligence Stack

A complete Darknet Intelligence platform combining:
- **Onion Crawler** – collects & indexes onion sites via Tor
- **Analyst UI Dashboard** – investigation interface with scanning, OSINT mapping & identity extraction
- **OpenSearch Backend** – stores indexed pages & scan results
- **Neo4j Graph Database** – relationship intelligence (domains, users, wallets, infrastructure)
- **Plugin Framework** – extendable enrichment & detection modules

---

## 🚀 Features

### 🕷️ Onion Crawler
- Crawls `.onion` and clearnet targets
- Extracts:
  - emails
  - usernames / aliases
  - crypto wallets
  - PGP keys
  - linked domains
- Respects Tor routing
- Stores documents into `onion_pages` OpenSearch index

### 🧠 Analyst Dashboard (Web UI)
- Navigate all indexed Onion sites
- Keyboard navigation (← / →)
- Live host view (URL, status, tags, identities)
- Technical fingerprint info
- OSINT correlation
- Plugin activity overview

### 🔍 Active Scanning (Integrated)
For every onion host:
- Dir‑Bruteforce (FFUF-like)
- Dir‑Bruteforce (Gobuster-style)
- Port/TCP check via Tor (`nmap`)
- Retry handling + status tracking
- Stored in `onion_scans` index

### 🕸 Neo4j Intelligence Graph
Builds relationship intelligence for:
- Usernames → Platforms
- Wallets → Owners
- Onion Sites → Linked Domains
- Infrastructure associations

---

## 🧩 Architecture Overview

| Component | Purpose |
|----------|--------|
| `crawler/` | Onion crawling engine |
| `analyst/` | Dashboard UI |
| `dashboards/` | Kibana dashboards |
| `neo4j/` | Graph intelligence |
| `tools/` | helper utilities |
| `tor/` | Tor routing container |

All components are orchestrated using Docker.

---

## 🧱 Required VM Setup

Recommended deployment structure:

| VM | Purpose |
|----|--------|
| VM1 | OpenSearch + Dashboard UI |
| VM2 | Crawler Engine |
| VM3 | Neo4j Graph Database |
| Tor Container | Same network, accessible to all components |

---

## 🐳 Installation

### 1️⃣ Clone Repository
```
git clone https://github.com/macipv6/onion-crawler-analyst.git
cd onion-crawler-analyst
```

### 2️⃣ Ensure Required Directories Exist
```
chmod +x init_dirs.sh
./init_dirs.sh
```

### 3️⃣ Start Stack
```
docker compose up -d
```

Tor will automatically run on port **9050**.

---

## 🌐 Access Points

| Service | URL |
|--------|------|
| Analyst Dashboard | `http://IP:8080` |
| OpenSearch API | `http://IP:9200` |
| Kibana (optional) | `http://IP:5601` |
| Neo4j Browser | `http://IP:7474` |

---

## 🎯 Usage

### Navigate Onion Pages
- Open Dashboard
- Press ← / → to browse index
- Manual search available

### Start Scan
- Click `Scan`
- Dashboard shows scan state + progress
- Results automatically stored

---

## 🧪 Notes
- Tor latency is normal
- Some hidden services refuse requests
- Use legally, for research & security investigations only

---

## 📜 License
MIT
---

## 🤝 Contribution
Pull Requests welcome.
Feature requests welcome.
Security research encouraged.

