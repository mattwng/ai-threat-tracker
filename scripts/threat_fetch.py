#!/usr/bin/env python3
"""
AI Threat Tracker — Fetcher Script
Fetches live threat data from 4 sources, writes threat_cache.json, then exits.
Called via subprocess from threat_tracker_app.py.
"""

import requests
from bs4 import BeautifulSoup
import json
import yaml
import os
import sys
import logging
import time
from datetime import datetime, timezone, timedelta

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

# ── Paths ──────────────────────────────────────────────────────────────────────
DATA_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE_DIR = os.path.join(DATA_DIR, 'cache')
THREAT_CACHE_FILE = os.path.join(CACHE_DIR, 'threat_cache.json')
MITRE_CACHE_FILE = os.path.join(CACHE_DIR, 'mitre_atlas_cache.json')

os.makedirs(CACHE_DIR, exist_ok=True)

# ── AI Keywords for CISA filtering ────────────────────────────────────────────
AI_KEYWORDS = [
    'tensorflow', 'pytorch', 'llm', 'gpt', 'huggingface', 'hugging face',
    'cuda', 'machine learning', 'ml model', 'neural network', 'deep learning',
    'openai', 'anthropic', 'gemini', 'bert', 'transformer', 'diffusion',
    'stable diffusion', 'langchain', 'llamaindex', 'ollama', 'onnx',
    'scikit', 'sklearn', 'keras', 'caffe', 'mxnet', 'paddle',
    'nvidia', 'triton', 'tritonserver', 'mlflow', 'ray', 'dask',
    'jupyter', 'notebook', 'ai ', 'artificial intelligence',
    'computer vision', 'nlp', 'natural language'
]


def is_ai_related(text):
    """Return True if text contains any AI keyword (case-insensitive)."""
    t = (text or '').lower()
    return any(kw in t for kw in AI_KEYWORDS)


# ── CISA KEV ──────────────────────────────────────────────────────────────────

def fetch_cisa_kev():
    """Fetch CISA Known Exploited Vulnerabilities and filter for AI relevance."""
    source = 'CISA KEV'
    logger.info(f"[{source}] Fetching...")
    try:
        resp = requests.get(
            'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
            timeout=30,
            headers={'User-Agent': 'AI-Threat-Tracker/1.0'}
        )
        resp.raise_for_status()
        data = resp.json()
        vulns = data.get('vulnerabilities', [])
        logger.info(f"[{source}] Total entries: {len(vulns)}")

        entries = []
        for v in vulns:
            fields = ' '.join([
                v.get('vendorProject', ''),
                v.get('product', ''),
                v.get('shortDescription', ''),
                v.get('notes', '')
            ])
            if not is_ai_related(fields):
                continue

            cve_id = v.get('cveID', '')
            date_str = v.get('dateAdded', '')
            published = date_str + 'T00:00:00Z' if date_str else datetime.now(timezone.utc).isoformat()

            severity = 'critical' if v.get('knownRansomwareCampaignUse', '') == 'Known' else 'high'

            tags = ['cve', 'exploited']
            for kw in ['tensorflow', 'pytorch', 'cuda', 'nvidia', 'llm', 'gpt', 'ml']:
                if kw in fields.lower():
                    tags.append(kw)

            entries.append({
                'id': f'cisa-{cve_id}',
                'source': source,
                'title': f"{v.get('vendorProject', 'Unknown')} {v.get('product', '')} — {cve_id}",
                'description': v.get('shortDescription', 'No description available.'),
                'vulnerability_summary': (
                    f"Affects {v.get('vendorProject', 'Unknown')} {v.get('product', '')}. "
                    f"Required action: {v.get('requiredAction', 'See advisory.')} "
                    f"Due: {v.get('dueDate', 'N/A')}."
                ),
                'published': published,
                'link': f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                'severity': severity,
                'tags': list(set(tags))
            })

        entries.sort(key=lambda x: x['published'], reverse=True)
        logger.info(f"[{source}] AI-relevant entries: {len(entries)}")
        return entries, {'ok': True, 'type': 'live', 'count': len(entries), 'error': None}
    except Exception as e:
        logger.error(f"[{source}] Error: {e}")
        return [], {'ok': False, 'type': 'live', 'count': 0, 'error': str(e)}


# ── AIID GraphQL ──────────────────────────────────────────────────────────────

def fetch_aiid():
    """
    Fetch recent incidents from the AI Incident Database via public RSS feed.
    Note: The AIID GraphQL API (incidentdatabase.ai/api/graphql) was locked to
    browser-only access. The RSS feed at /rss.xml remains publicly accessible.
    """
    source = 'AI Incident Database'
    rss_url = 'https://incidentdatabase.ai/rss.xml'
    logger.info(f"[{source}] Fetching RSS feed...")
    try:
        resp = requests.get(
            rss_url,
            headers={
                'User-Agent': (
                    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) '
                    'AppleWebKit/537.36 (KHTML, like Gecko) '
                    'Chrome/120.0.0.0 Safari/537.36'
                )
            },
            timeout=20
        )
        resp.raise_for_status()

        soup = BeautifulSoup(resp.text, 'lxml-xml')
        items = soup.find_all('item')
        logger.info(f"[{source}] RSS items: {len(items)}")

        # Deduplicate by incident cite URL — each incident has multiple reports
        seen_incidents = {}
        for item in items:
            title_el = item.find('title')
            link_el = item.find('link')
            desc_el = item.find('description')
            pub_el = item.find('pubDate')

            raw_title = title_el.get_text(strip=True) if title_el else ''
            if not raw_title or raw_title == 'No title':
                continue

            link = link_el.get_text(strip=True) if link_el else ''
            description = desc_el.get_text(strip=True) if desc_el else ''
            pub_str = pub_el.get_text(strip=True) if pub_el else ''

            # Extract incident ID from description or link (format: /cite/NNNN)
            import re
            cite_match = re.search(r'/cite/(\d+)', description + link)
            incident_key = cite_match.group(1) if cite_match else raw_title

            # Keep first occurrence per incident (most recent report)
            if incident_key in seen_incidents:
                continue
            seen_incidents[incident_key] = True

            # Normalize date
            try:
                from email.utils import parsedate_to_datetime
                published = parsedate_to_datetime(pub_str).isoformat()
            except Exception:
                published = datetime.now(timezone.utc).isoformat()

            # Build incident URL
            incident_url = (
                f"https://incidentdatabase.ai/cite/{incident_key}"
                if incident_key.isdigit()
                else link or 'https://incidentdatabase.ai'
            )

            # Truncate description — remove trailing "(report_number: NNNN)" artifacts
            clean_desc = re.sub(r'\s*\(report_number:\s*\d+\)\s*$', '', description).strip()
            clean_desc = re.sub(r'\s*\(https://incidentdatabase\.ai/\S+\)\s*$', '', clean_desc).strip()

            seen_incidents[incident_key] = {
                'id': f'aiid-{incident_key}',
                'source': source,
                'title': raw_title,
                'description': clean_desc[:500] or 'AI system incident.',
                'vulnerability_summary': 'Real-world AI system harm incident documented in the AI Incident Database.',
                'published': published,
                'link': incident_url,
                'severity': 'medium',
                'tags': ['ai-incident', 'aiid']
            }

        entries = [v for v in seen_incidents.values() if isinstance(v, dict)]
        entries = entries[:50]  # Cap at 50
        logger.info(f"[{source}] Deduplicated entries: {len(entries)}")
        return entries, {'ok': True, 'type': 'live', 'count': len(entries), 'error': None}
    except Exception as e:
        logger.error(f"[{source}] Error: {e}")
        return [], {'ok': False, 'type': 'live', 'count': 0, 'error': str(e)}


# ── FireTail AI Breach Tracker ────────────────────────────────────────────────

def fetch_firetail():
    """
    Fetch AI breach data from FireTail.
    Attempts plain HTML scrape first; falls back to Next.js data endpoint.
    Degrades gracefully if JS-rendered with < 3 parseable entries.
    """
    source = 'FireTail AI Breaches'
    base_url = 'https://firetail.io'
    target_url = f'{base_url}/ai-breach-tracker'
    logger.info(f"[{source}] Fetching...")

    headers = {
        'User-Agent': (
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) '
            'AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/120.0.0.0 Safari/537.36'
        )
    }

    entries = []

    try:
        resp = requests.get(target_url, headers=headers, timeout=20)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, 'lxml')

        # Look for breach cards / table rows
        cards = (
            soup.find_all('article') or
            soup.find_all('tr', class_=lambda c: c and 'breach' in c.lower()) or
            soup.find_all('div', class_=lambda c: c and any(k in (c or '').lower() for k in ['breach', 'incident', 'card', 'row']))
        )

        if len(cards) >= 3:
            for i, card in enumerate(cards[:50]):
                title_el = card.find(['h2', 'h3', 'h4', 'strong', 'td'])
                link_el = card.find('a', href=True)
                desc_el = card.find('p')

                title = title_el.get_text(strip=True) if title_el else f'AI Breach #{i + 1}'
                link = link_el['href'] if link_el else target_url
                if link.startswith('/'):
                    link = base_url + link
                description = desc_el.get_text(strip=True) if desc_el else 'AI security breach incident.'

                entries.append({
                    'id': f'firetail-{i}',
                    'source': source,
                    'title': title,
                    'description': description[:400],
                    'vulnerability_summary': 'AI system breach tracked by FireTail.',
                    'published': datetime.now(timezone.utc).isoformat(),
                    'link': link,
                    'severity': 'high',
                    'tags': ['ai-breach', 'firetail']
                })
            logger.info(f"[{source}] Scraped {len(entries)} entries via HTML.")
            return entries, {'ok': True, 'type': 'live', 'count': len(entries), 'error': None}

        # < 3 entries from plain scrape — likely JS-rendered, try Next.js data endpoint
        logger.warning(f"[{source}] Plain scrape found < 3 entries, trying Next.js data endpoint...")
        next_resp = requests.get(
            f'{base_url}/_next/data/index/ai-breach-tracker.json',
            headers=headers,
            timeout=15
        )
        if next_resp.status_code == 200:
            ndata = next_resp.json()
            breaches = (
                ndata.get('pageProps', {}).get('breaches') or
                ndata.get('pageProps', {}).get('incidents') or
                ndata.get('pageProps', {}).get('data') or
                []
            )
            for i, b in enumerate(breaches[:50]):
                title = b.get('title') or b.get('name') or b.get('company') or f'Breach #{i+1}'
                desc = b.get('description') or b.get('summary') or 'AI breach incident.'
                link = b.get('url') or b.get('link') or target_url
                pub = b.get('date') or b.get('published') or b.get('discovered') or ''
                try:
                    dt = datetime.fromisoformat(pub.replace('Z', '+00:00'))
                    published = dt.isoformat()
                except Exception:
                    published = datetime.now(timezone.utc).isoformat()

                entries.append({
                    'id': f'firetail-{i}',
                    'source': source,
                    'title': title,
                    'description': str(desc)[:400],
                    'vulnerability_summary': 'AI system breach tracked by FireTail.',
                    'published': published,
                    'link': link,
                    'severity': 'high',
                    'tags': ['ai-breach', 'firetail']
                })
            if entries:
                logger.info(f"[{source}] Next.js endpoint returned {len(entries)} entries.")
                return entries, {'ok': True, 'type': 'live', 'count': len(entries), 'error': None}

        logger.warning(f"[{source}] Could not extract data (JS-rendered, no fallback available).")
        return [], {
            'ok': False,
            'type': 'live',
            'count': 0,
            'error': 'Site appears JS-rendered; data unavailable without a headless browser.'
        }

    except Exception as e:
        logger.error(f"[{source}] Error: {e}")
        return [], {'ok': False, 'type': 'live', 'count': 0, 'error': str(e)}


# ── MITRE ATLAS ───────────────────────────────────────────────────────────────

ATLAS_URL = 'https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml'
ATLAS_CACHE_TTL_DAYS = 7


def fetch_mitre_atlas():
    """
    Download MITRE ATLAS techniques (AI-specific ATT&CK framework).
    Uses a 7-day file cache to avoid hammering GitHub.
    The repo distributes ATLAS.yaml (not JSON) — parsed with PyYAML.
    """
    source = 'MITRE ATLAS'
    logger.info(f"[{source}] Checking cache...")

    # Check local cache freshness
    if os.path.exists(MITRE_CACHE_FILE):
        mtime = os.path.getmtime(MITRE_CACHE_FILE)
        age_days = (time.time() - mtime) / 86400
        if age_days < ATLAS_CACHE_TTL_DAYS:
            logger.info(f"[{source}] Using cached ATLAS data ({age_days:.1f} days old).")
            try:
                with open(MITRE_CACHE_FILE, 'r') as f:
                    atlas_data = yaml.safe_load(f)
                return _parse_atlas(atlas_data)
            except Exception as e:
                logger.warning(f"[{source}] Cache read failed, re-downloading: {e}")

    logger.info(f"[{source}] Downloading ATLAS.yaml...")
    try:
        resp = requests.get(ATLAS_URL, timeout=30, headers={'User-Agent': 'AI-Threat-Tracker/1.0'})
        resp.raise_for_status()
        atlas_data = yaml.safe_load(resp.text)

        # Write to local cache (atomic)
        tmp = MITRE_CACHE_FILE + '.tmp'
        with open(tmp, 'w') as f:
            yaml.dump(atlas_data, f)
        os.replace(tmp, MITRE_CACHE_FILE)
        logger.info(f"[{source}] ATLAS data cached to {MITRE_CACHE_FILE}")

        return _parse_atlas(atlas_data)
    except Exception as e:
        logger.error(f"[{source}] Error: {e}")
        return [], {'ok': False, 'type': 'live', 'count': 0, 'error': str(e)}


def _parse_atlas(atlas_data):
    """
    Parse ATLAS YAML into threat entries.
    Structure: atlas_data.matrices[0].techniques (flat list of technique dicts).
    """
    source = 'MITRE ATLAS'
    entries = []

    matrices = atlas_data.get('matrices', []) if isinstance(atlas_data, dict) else []

    for matrix in matrices:
        techniques = matrix.get('techniques', [])
        for tech in techniques:
            obj_id = tech.get('id', '')
            name = tech.get('name', 'Unknown Technique')
            description = tech.get('description', 'No description available.')

            # tactics is a list of tactic IDs in ATLAS YAML
            tactic_ids = tech.get('tactics', [])

            tags = ['mitre', 'atlas', 'ai-attack']
            tags.extend([str(t).lower().replace('.', '-') for t in tactic_ids[:2]])

            entries.append({
                'id': f'atlas-{obj_id}',
                'source': source,
                'title': f"[{obj_id}] {name}",
                'description': description[:500],
                'vulnerability_summary': (
                    f"Adversarial AI/ML attack technique from MITRE ATLAS v{atlas_data.get('version', '')}. "
                    f"Tactics: {', '.join(str(t) for t in tactic_ids[:3]) or 'N/A'}."
                ),
                'published': str(tech.get('created_date', datetime.now(timezone.utc).date())) + 'T00:00:00Z',
                'link': f"https://atlas.mitre.org/techniques/{obj_id}",
                'severity': 'high',
                'tags': list(set(tags))
            })

    logger.info(f"[{source}] Parsed {len(entries)} techniques.")
    return entries, {'ok': True, 'type': 'live', 'count': len(entries), 'error': None}


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    logger.info("=== AI Threat Fetch Starting ===")
    start = time.time()

    grouped = {}
    sources_status = {}

    fetch_jobs = [
        ('CISA KEV', fetch_cisa_kev),
        ('AI Incident Database', fetch_aiid),
        ('FireTail AI Breaches', fetch_firetail),
        ('MITRE ATLAS', fetch_mitre_atlas),
    ]

    for source_name, fn in fetch_jobs:
        try:
            entries, status = fn()
            grouped[source_name] = entries
            sources_status[source_name] = status
        except Exception as e:
            logger.error(f"[main] Uncaught exception in {source_name}: {e}")
            grouped[source_name] = []
            sources_status[source_name] = {'ok': False, 'type': 'live', 'count': 0, 'error': str(e)}

    cache_data = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'grouped': grouped,
        'sources_status': sources_status,
        'fetch_duration_seconds': round(time.time() - start, 1)
    }

    # Atomic write
    tmp = THREAT_CACHE_FILE + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(cache_data, f, indent=2)
    os.replace(tmp, THREAT_CACHE_FILE)

    total = sum(len(v) for v in grouped.values())
    logger.info(f"=== Fetch complete: {total} entries in {cache_data['fetch_duration_seconds']}s ===")
    logger.info(f"Cache written to: {THREAT_CACHE_FILE}")


if __name__ == '__main__':
    main()
