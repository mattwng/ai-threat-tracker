# AI Threat Tracker — Claude Context

> Real-time AI-related cyber attack and incident aggregator
> Created: March 2026

---

## Project Overview

| Attribute | Value |
|-----------|-------|
| **Purpose** | Surface AI-related cyber threats from live and static sources |
| **Tech Stack** | Python 3.11, Flask, APScheduler, BeautifulSoup, Gunicorn |
| **Port** | 5003 |
| **Domain** | threats.illuminait.io |
| **Server Path** | /opt/ai-threat-tracker |
| **GitHub** | mattwng/ai-threat-tracker |

---

## File Structure

```
ai-threat-tracker/
├── threat_tracker_app.py       # Flask app — routes, cache, scheduler
├── scripts/
│   └── threat_fetch.py         # All live-source fetching; called via subprocess
├── templates/
│   └── threats.html            # Jinja2 frontend — dark cyber aesthetic
├── static_sources.json         # Pre-loaded annual/static report entries
├── cache/                      # Runtime cache dir (Docker volume; gitignored)
│   ├── threat_cache.json       # Main cache (atomic write, 8h TTL prod/1h dev)
│   └── mitre_atlas_cache.json  # ATLAS data (7-day TTL to avoid GitHub rate limits)
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
├── .env.development
├── .env.production
├── .env                        # Active config (gitignored — copy from above)
└── CLAUDE.md
```

---

## Data Sources

### Live (fetched every 4 hours)
| Source | Method |
|--------|--------|
| CISA KEV | JSON API — filtered by AI keywords |
| AI Incident Database (AIID) | RSS feed at `/rss.xml` — GraphQL API is browser-only (403) |
| FireTail AI Breach Tracker | HTML scrape + Next.js `/_next/data/` fallback |
| MITRE ATLAS | GitHub YAML download (`dist/ATLAS.yaml`, parsed with pyyaml, 7-day local cache) |

### Static (in static_sources.json)
- ENISA Threat Landscape (annual, October)
- IBM X-Force Index (annual, February)
- Verizon DBIR (annual, April)
- Google TIG / Mandiant (ad hoc)
- MIT AI Incident Tracker (periodic)

---

## API Endpoints

| Method | Route | Description |
|--------|-------|-------------|
| GET | `/` | Serve threats.html |
| GET | `/favicon.ico` | Return 204 |
| GET | `/api/threats` | Return cached threats grouped by source |
| GET | `/api/status` | Cache age, generation status, per-source health |
| POST | `/api/refresh` | Delete cache, trigger async fetch |

---

## Key Design Decisions

### 1. Worker count
Gunicorn uses `--workers 1 --threads 4`. This prevents multiple APScheduler
instances firing simultaneously (the daily-briefings app has 4 schedulers bug
due to `--workers 4`).

### 2. Atomic cache writes
`threat_fetch.py` writes to `.tmp` then `os.replace()` to prevent partial reads
if the app is serving while the fetcher is writing.

### 3. Cache location
The cache lives in `cache/` subdirectory which is mounted as a Docker named
volume (`threat_cache`). This means data persists across container restarts,
so users don't see an empty page during deployment.

### 4. Fetcher isolation
`threat_fetch.py` is called via `subprocess.run()` from a background thread.
Per-source exceptions are caught and logged to `sources_status` — one failed
source never aborts the whole fetch.

### 5. FireTail degradation
FireTail's site is likely JS-rendered. The fetcher tries HTML scrape first,
then `/_next/data/` endpoint. If both fail, `sources_status["FireTail"]["ok"]`
is `False` and the UI shows an amber "degraded" pill.

---

## Development Commands

```bash
# Start local dev
cd ~/Development/projects/ai-threat-tracker
cp .env.development .env
docker compose up --build
# App at http://localhost:5003

# Test fetch script directly
python3 scripts/threat_fetch.py

# Force refresh via API
curl -X POST http://localhost:5003/api/refresh

# Check status
curl http://localhost:5003/api/status | python3 -m json.tool
```

---

## Deployment

```bash
# Commit and push
git add . && git commit -m "message" && git push origin main

# Deploy to server
ssh root@192.168.68.108 "cd /opt/ai-threat-tracker && git pull && cp .env.production .env && docker compose down && docker compose build --no-cache && docker compose up -d"

# Verify
curl http://192.168.68.108:5003/api/status
```

### Routing
`threats.illuminait.io` is routed via **Cloudflare Tunnel** (not NPM).
The tunnel points directly to `http://192.168.68.108:5003`. No NPM proxy host
is needed — Cloudflare handles SSL termination.

---

## Updating Static Sources

Edit `static_sources.json` directly. Each entry has an `"expires"` field — when
a static report has been superseded by a newer annual edition, update or remove
the old entries. The `"possibly outdated"` chip in the UI (future enhancement)
will check this field against today's date.

---

## Common Issues

### Cache not updating
- Force refresh: `curl -X POST http://localhost:5003/api/refresh`
- Or delete volume: `docker compose down -v && docker compose up -d`

### FireTail showing amber/degraded
- Expected — the site is JS-rendered. Data only available if Next.js endpoint
  responds or site adds a JSON API. Degrade gracefully is correct behavior.

### AIID showing no entries
- AIID GraphQL API is permanently blocked for non-browser clients (returns 403).
- Fetcher uses RSS feed at `https://incidentdatabase.ai/rss.xml` instead.
- If RSS is down, `sources_status["AI Incident Database"]["ok"]` will be False.

### MITRE ATLAS data stale
- ATLAS cache is 7 days. Delete `cache/mitre_atlas_cache.json` to force re-download.
- Or just wait — the Docker volume is persistent across restarts.
