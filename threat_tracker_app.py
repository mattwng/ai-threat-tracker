#!/usr/bin/env python3
"""
AI Threat Tracker — Flask app
Surfaces real-time AI-related cyber attacks and incidents from multiple sources.
"""

from flask import Flask, jsonify, render_template, request, make_response
from flask_compress import Compress
from datetime import datetime, timezone
import json
import os
import threading
import subprocess
from apscheduler.schedulers.background import BackgroundScheduler
import atexit
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

app.config['COMPRESS_MIMETYPES'] = ['text/html', 'text/css', 'application/json', 'application/javascript']
app.config['COMPRESS_LEVEL'] = 6
app.config['COMPRESS_MIN_SIZE'] = 500
Compress(app)

# ── Paths ──────────────────────────────────────────────────────────────────────
DATA_DIR = os.path.dirname(os.path.abspath(__file__))
CACHE_DIR = os.path.join(DATA_DIR, 'cache')
THREAT_CACHE_FILE = os.path.join(CACHE_DIR, 'threat_cache.json')
STATIC_SOURCES_FILE = os.path.join(DATA_DIR, 'static_sources.json')

# ── Cache config ───────────────────────────────────────────────────────────────
FLASK_ENV = os.getenv('FLASK_ENV', 'production')
CACHE_TTL = 3600 if FLASK_ENV == 'development' else 28800  # 1h dev, 8h prod

# ── Generation state ───────────────────────────────────────────────────────────
_fetch_in_progress = False
_fetch_lock = threading.Lock()


def load_cache():
    """Load threat cache from file if still valid."""
    if not os.path.exists(THREAT_CACHE_FILE):
        return None
    try:
        with open(THREAT_CACHE_FILE, 'r') as f:
            data = json.load(f)
        ts = data.get('timestamp', '2000-01-01T00:00:00Z')
        cache_time = datetime.fromisoformat(ts)
        if cache_time.tzinfo is None:
            cache_time = cache_time.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - cache_time).total_seconds()
        if age < CACHE_TTL:
            return data
    except Exception as e:
        print(f"[cache] Error loading: {e}")
    return None


def trigger_fetch_async():
    """Spawn the fetcher script in a background thread. No-op if already running."""
    global _fetch_in_progress

    with _fetch_lock:
        if _fetch_in_progress:
            print("[fetch] Already in progress, skipping.")
            return False
        _fetch_in_progress = True

    def run():
        global _fetch_in_progress
        try:
            script = os.path.join(DATA_DIR, 'scripts', 'threat_fetch.py')
            print(f"[fetch] Starting: {script}")
            result = subprocess.run(
                ['python3', script],
                cwd=DATA_DIR,
                capture_output=True,
                text=True,
                timeout=300
            )
            if result.returncode == 0:
                print("[fetch] Completed successfully.")
            else:
                print(f"[fetch] Failed (rc={result.returncode}):\n{result.stderr[:500]}")
        except subprocess.TimeoutExpired:
            print("[fetch] Timed out after 300s.")
        except Exception as e:
            print(f"[fetch] Exception: {e}")
        finally:
            with _fetch_lock:
                _fetch_in_progress = False

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return True


def init_scheduler():
    """Start APScheduler with a 4-hour interval trigger."""
    scheduler = BackgroundScheduler(timezone='America/Los_Angeles')
    scheduler.add_job(
        func=trigger_fetch_async,
        trigger='interval',
        hours=4,
        id='threat_refresh',
        name='Threat data refresh'
    )
    scheduler.start()
    print("[scheduler] Threat refresh every 4 hours.")
    atexit.register(lambda: scheduler.shutdown(wait=False))
    return scheduler


def init_on_startup():
    """Trigger fetch on startup if no valid cache exists."""
    os.makedirs(CACHE_DIR, exist_ok=True)
    if not load_cache():
        print("[startup] No valid cache — triggering initial fetch.")
        trigger_fetch_async()


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('threats.html')


@app.route('/favicon.ico')
def favicon():
    return '', 204


@app.route('/api/threats')
def api_threats():
    """Return cached threats grouped by source, merged with static sources."""
    cache = load_cache()

    if cache:
        # Merge static sources into grouped data
        grouped = cache.get('grouped', {})
        sources_status = cache.get('sources_status', {})

        # Load and merge static sources
        static_grouped, static_status = load_static_sources()
        for source, entries in static_grouped.items():
            grouped[source] = entries
        sources_status.update(static_status)

        ts = cache.get('timestamp', datetime.now(timezone.utc).isoformat())
        cache_time = datetime.fromisoformat(ts)
        if cache_time.tzinfo is None:
            cache_time = cache_time.replace(tzinfo=timezone.utc)
        age_seconds = (datetime.now(timezone.utc) - cache_time).total_seconds()

        response = make_response(jsonify({
            'success': True,
            'grouped': grouped,
            'sources_status': sources_status,
            'timestamp': ts,
            'cache_age_seconds': int(age_seconds),
            'generating': _fetch_in_progress
        }))
        remaining = max(60, int(CACHE_TTL - age_seconds))
        response.headers['Cache-Control'] = f'public, max-age={remaining}'
        return response
    else:
        started = trigger_fetch_async()
        static_grouped, static_status = load_static_sources()
        return make_response(jsonify({
            'success': True,
            'grouped': static_grouped,
            'sources_status': static_status,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'cache_age_seconds': 0,
            'generating': started,
            'message': 'Live sources are being fetched. Refresh in ~60 seconds.'
        })), 202


@app.route('/api/status')
def api_status():
    """Return cache age, generation status, and per-source health."""
    cache = load_cache()
    cache_age = None
    has_cache = cache is not None

    if has_cache:
        ts = cache.get('timestamp', '')
        try:
            cache_time = datetime.fromisoformat(ts)
            if cache_time.tzinfo is None:
                cache_time = cache_time.replace(tzinfo=timezone.utc)
            cache_age = int((datetime.now(timezone.utc) - cache_time).total_seconds())
        except Exception:
            pass

    return jsonify({
        'generating': _fetch_in_progress,
        'has_cache': has_cache,
        'cache_age_seconds': cache_age,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'sources_status': cache.get('sources_status', {}) if cache else {}
    })


@app.route('/api/refresh', methods=['POST'])
def api_refresh():
    """Delete cache and trigger a fresh fetch."""
    try:
        if os.path.exists(THREAT_CACHE_FILE):
            try:
                os.remove(THREAT_CACHE_FILE)
            except OSError as e:
                print(f"[refresh] Could not remove cache (will be overwritten): {e}")
        started = trigger_fetch_async()
        return jsonify({
            'success': True,
            'generating': started,
            'message': 'Fetch started.' if started else 'Already in progress.'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ── Static sources helper ──────────────────────────────────────────────────────

def load_static_sources():
    """Load static_sources.json and return (grouped_dict, status_dict)."""
    grouped = {}
    status = {}
    if not os.path.exists(STATIC_SOURCES_FILE):
        return grouped, status
    try:
        with open(STATIC_SOURCES_FILE, 'r') as f:
            entries = json.load(f)
        for entry in entries:
            source = entry.get('source', 'Unknown')
            grouped.setdefault(source, []).append(entry)
            status[source] = {'ok': True, 'type': 'static', 'count': 0}
        for source in grouped:
            status[source]['count'] = len(grouped[source])
    except Exception as e:
        print(f"[static] Error loading static sources: {e}")
    return grouped, status


# ── Bootstrap ──────────────────────────────────────────────────────────────────

with app.app_context():
    init_on_startup()
    init_scheduler()


if __name__ == '__main__':
    port = int(os.getenv('PORT', 5003))
    app.run(debug=(FLASK_ENV == 'development'), host='0.0.0.0', port=port)
