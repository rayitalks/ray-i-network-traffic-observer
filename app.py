"""Ray-i: a loopback-only network traffic observer."""
from __future__ import annotations

import argparse
import csv
from contextlib import contextmanager
import io
import html
import hashlib
import json
import math
import os
from pathlib import Path
import secrets
import socket
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit
from urllib.request import build_opener, ProxyHandler
import webbrowser

import psutil
from telemetry import Telemetry
from system_insights import SystemInsights
from insight_recorder import InsightRecorder

ROOT = Path(__file__).resolve().parent
RETENTION = 30 * 86400
FIELDS = ('id', 'profile_name', 'remote_ip', 'remote_port', 'local_ip', 'local_port', 'tcp_status')


def counter_delta(old, new, elapsed):
    """Reset/replaced interfaces and missing intervals are not measured traffic."""
    if elapsed <= 0 or elapsed > 30 or new[0] < old[0] or new[1] < old[1]:
        return None
    return (new[0] - old[0], new[1] - old[1])


def csv_safe(value):
    text = '' if value is None else str(value)
    return "'" + text if text.lstrip().startswith(('=', '+', '-', '@', '\t', '\r')) else text


class Store:
    def __init__(self, path):
        self.path = path
        with self.connect() as db:
            db.executescript('''
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS samples (
                    ts REAL, adapter TEXT, rx INTEGER, tx INTEGER, seconds REAL,
                    PRIMARY KEY(ts, adapter));
                CREATE INDEX IF NOT EXISTS samples_time ON samples(ts);
                CREATE TABLE IF NOT EXISTS connections (
                    id TEXT PRIMARY KEY, seen REAL, app TEXT, domain TEXT,
                    ip TEXT, country TEXT, allowed INTEGER, tunneled INTEGER, payload TEXT);
                CREATE INDEX IF NOT EXISTS connections_seen ON connections(seen);
            ''')

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def ingest(self, rows, now):
        with self.connect() as db:
            for row in rows:
                if not row.get('id'):
                    continue
                db.execute('''INSERT INTO connections VALUES (?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(id) DO UPDATE SET seen=excluded.seen, app=excluded.app,
                    domain=excluded.domain, ip=excluded.ip, country=excluded.country,
                    allowed=excluded.allowed, tunneled=excluded.tunneled, payload=excluded.payload''',
                    (str(row['id']), now, row.get('profile_name') or row.get('profile') or 'Unknown app',
                     row.get('domain') or '', row.get('remote_ip') or '', row.get('country') or '',
                     row.get('allowed'), bool(row.get('tunneled')), json.dumps(row)))

    def cleanup(self, now):
        with self.connect() as db:
            db.execute('DELETE FROM samples WHERE ts < ?', (now - RETENTION,))
            db.execute('DELETE FROM connections WHERE seen < ?', (now - RETENTION,))

    def records(self, hours=24, search='', verdict='all', offset=0, limit=100):
        where, args = self.filters(hours, search, verdict)
        with self.connect() as db:
            total = db.execute('SELECT COUNT(*) FROM connections WHERE ' + where, args).fetchone()[0]
            rows = db.execute('SELECT payload, seen FROM connections WHERE ' + where +
                              ' ORDER BY seen DESC, id LIMIT ? OFFSET ?', args + [limit, offset]).fetchall()
        return total, [dict(json.loads(r['payload']), last_observed=r['seen']) for r in rows]

    @staticmethod
    def filters(hours, search, verdict):
        where = 'seen >= ?'
        args = [time.time() - hours * 3600]
        if search:
            where += ' AND (app LIKE ? ESCAPE "\\" OR domain LIKE ? ESCAPE "\\" OR ip LIKE ? ESCAPE "\\")'
            needle = '%' + search.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '%'
            args.extend([needle] * 3)
        if verdict == 'blocked':
            where += ' AND allowed=0'
        elif verdict == 'allowed':
            where += ' AND allowed=1'
        return where, args


class RayiNetworkTrafficObserver:
    def __init__(self, data_dir):
        data_dir.mkdir(parents=True, exist_ok=True)
        self.store = Store(data_dir / 'ray-i-network-traffic-observer.sqlite3')
        self.os_store = Store(data_dir / 'windows-connections.sqlite3')
        self.csrf = secrets.token_urlsafe(32)
        self.adapters = []
        self.counter_error = None
        self.os_error = None
        self.os_sync = None
        self.stop = threading.Event()
        self.opener = build_opener(ProxyHandler({}))
        self.telemetry = Telemetry(self, data_dir)
        self.insights = SystemInsights()
        self.recorder = InsightRecorder(self.insights)
        self.insight_job = threading.Lock()

    def maintain(self):
        while not self.stop.is_set():
            try:
                self.store.cleanup(time.time())
                self.os_store.cleanup(time.time())
                self.telemetry.cleanup(time.time())
            except sqlite3.Error:
                pass  # Retry independently of either collector.
            self.stop.wait(60)

    def connection_store(self, source):
        return self.os_store

    def collect_os_connections(self):
        while not self.stop.is_set():
            try:
                now = time.time()
                rows, processes = [], {}
                for conn in psutil.net_connections(kind='tcp'):
                    if not conn.raddr:
                        continue
                    if conn.pid not in processes:
                        try:
                            proc = psutil.Process(conn.pid) if conn.pid else None
                            processes[conn.pid] = (proc.name(), proc.create_time()) if proc else ('Unknown process', 0)
                        except (psutil.Error, OSError):
                            processes[conn.pid] = ('PID ' + str(conn.pid or 'unknown'), 0)
                    name, created = processes[conn.pid]
                    identity = json.dumps([conn.pid, created, tuple(conn.laddr), tuple(conn.raddr)])
                    rows.append({'id': 'os_' + hashlib.sha256(identity.encode()).hexdigest(),
                                 'profile_name': name, 'profile': str(conn.pid), 'domain': '',
                                 'remote_ip': conn.raddr.ip, 'remote_port': conn.raddr.port,
                                 'local_ip': conn.laddr.ip, 'local_port': conn.laddr.port,
                                 'country': '', 'type': 'ip', 'ip_protocol': 6,
                                 'allowed': None, 'tunneled': None, 'started': None, 'ended': None,
                                 'source': 'Windows TCP', 'tcp_status': conn.status,
                                 'bytes_received': None, 'bytes_sent': None})
                self.os_store.ingest(rows, now)
                self.telemetry.observe('windows', rows, now)
                self.os_sync, self.os_error = now, None
            except Exception:
                self.os_error = 'Windows TCP connection collection is unavailable; retrying.'
            self.stop.wait(5)

    def collect_counters(self):
        previous = {}
        previous_time = time.monotonic()
        while not self.stop.is_set():
            try:
                now, tick = time.time(), time.monotonic()
                counts = psutil.net_io_counters(pernic=True, nowrap=False)
                stats = psutil.net_if_stats()
                current = {name: (v.bytes_recv, v.bytes_sent) for name, v in counts.items()
                           if name in stats and stats[name].isup and 'loopback' not in name.lower()}
                self.adapters = sorted(current)
                with self.store.connect() as db:
                    for name, values in current.items():
                        if name in previous:
                            delta = counter_delta(previous[name], values, tick - previous_time)
                            if delta is not None:
                                db.execute('INSERT OR REPLACE INTO samples VALUES (?,?,?,?,?)',
                                           (now, name, *delta, tick - previous_time))
                previous, previous_time = current, tick
                # Read back this cycle's committed deltas; alert writes use their own transaction.
                with self.store.connect() as db:
                    cycle = db.execute('SELECT adapter,rx,tx,seconds FROM samples WHERE ts=?', (now,)).fetchall()
                for sample in cycle:
                    self.telemetry.bandwidth(*sample, now)
                self.counter_error = None
            except Exception:
                self.counter_error = 'Windows adapter counters are unavailable; retrying.'
            self.stop.wait(5)

    def summary(self, hours, adapter, source='windows'):
        cutoff = time.time() - hours * 3600
        with self.store.connect() as db:
            names = [r[0] for r in db.execute('SELECT DISTINCT adapter FROM samples WHERE ts >= ?', (cutoff,))]
            if not adapter or adapter not in names:
                row = db.execute('SELECT adapter FROM samples WHERE ts >= ? GROUP BY adapter ORDER BY SUM(rx+tx) DESC LIMIT 1', (cutoff,)).fetchone()
                adapter = row[0] if row else (self.adapters[0] if self.adapters else '')
            first = db.execute('SELECT MIN(ts) FROM samples WHERE ts >= ? AND adapter=?', (cutoff, adapter)).fetchone()[0]
            bucket = max(5, math.ceil((time.time() - first) / 120)) if first else 5
            chart = [dict(r) for r in db.execute('''SELECT CAST(ts / ? AS INTEGER)*? AS ts,
                SUM(rx)/SUM(seconds) AS rx, SUM(tx)/SUM(seconds) AS tx FROM samples
                WHERE ts >= ? AND adapter=? GROUP BY CAST(ts / ? AS INTEGER) ORDER BY ts''',
                (bucket, bucket, cutoff, adapter, bucket))]
            totals = dict(db.execute('SELECT COALESCE(SUM(rx),0) AS rx, COALESCE(SUM(tx),0) AS tx, MIN(ts) AS since FROM samples WHERE ts >= ? AND adapter=?', (cutoff, adapter)).fetchone())
            latest = db.execute('SELECT rx/seconds AS rx, tx/seconds AS tx, ts FROM samples WHERE adapter=? ORDER BY ts DESC LIMIT 1', (adapter,)).fetchone()
            current = dict(latest) if latest and latest['ts'] > time.time() - 20 else None
        with self.connection_store(source).connect() as db:
            connections = dict(db.execute('''SELECT COUNT(*) AS total,
                COUNT(DISTINCT app) AS apps FROM connections WHERE seen >= ?''', (cutoff,)).fetchone())
            apps = [dict(r) for r in db.execute('''SELECT app, COUNT(*) AS total,
                COALESCE(SUM(allowed=0),0) AS blocked FROM connections WHERE seen >= ?
                GROUP BY app ORDER BY total DESC LIMIT 8''', (cutoff,))]
        return {                'counter_error': self.counter_error, 'adapter': adapter,
                'source': source, 'os_sync': self.os_sync, 'os_error': self.os_error,
                'adapters': sorted(set(names + self.adapters)), 'current': current, 'chart': chart,
                'totals': totals, 'connections': connections, 'apps': apps, 'bucket': bucket,
                'retention_days': 30, 'csrf': self.csrf}


def handler_for(app, port):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass  # Do not log private search terms or connection destinations.

        def send(self, status, body, content_type='application/json', extra=None):
            payload = json.dumps(body).encode() if content_type == 'application/json' else body
            self.send_response(status)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(payload)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
            for key, value in (extra or {}).items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(payload)

        def safe_request(self, write=False):
            hosts = {f'127.0.0.1:{port}', f'localhost:{port}'}
            if self.headers.get('Host') not in hosts:
                self.send(403, {'error': 'Invalid host'})
                return False
            origin = self.headers.get('Origin')
            if origin and origin not in {'http://' + host for host in hosts}:
                self.send(403, {'error': 'Cross-origin access denied'})
                return False
            if self.headers.get('Sec-Fetch-Site') == 'cross-site':
                self.send(403, {'error': 'Cross-site access denied'})
                return False
            if write and not secrets.compare_digest(self.headers.get('X-Ray-i-Token', ''), app.csrf):
                self.send(403, {'error': 'Reload Ray-i before connecting'})
                return False
            return True

        def params(self):
            query = parse_qs(urlsplit(self.path).query)
            def get(name, default=''):
                return query.get(name, [default])[0]
            hours = float(get('hours', '24'))
            offset = int(get('offset', '0'))
            if not math.isfinite(hours) or not 0 < hours <= 720 or offset < 0:
                raise ValueError('Invalid range')
            source = get('source', 'windows')
            if source != 'windows':
                raise ValueError('Invalid source')
            return hours, get('search')[:200], get('verdict', 'all'), offset, get('adapter'), source

        def do_GET(self):
            if not self.safe_request():
                return
            path = urlsplit(self.path).path
            try:
                if path.startswith('/api/'):
                    insight_reads = {
                        '/api/insights/snapshot': app.recorder.snapshot,
                        '/api/insights/recording': app.recorder.recording,
                        '/api/insights/connections': app.insights.connections,
                        '/api/insights/apps': app.insights.installed_apps,
                    }
                    if path in insight_reads:
                        return self.send(200, insight_reads[path]())
                    if path == '/api/health':
                        return self.send(200, {'application': 'Ray-i Network Traffic Observer', 'version': '1.0.0'})
                    hours, search, verdict, offset, adapter, source = self.params()
                    if path in ('/api/dashboard', '/api/dashboard.csv'):
                        dashboard = app.telemetry.snapshot(hours, source, search, adapter)
                        if path == '/api/dashboard':
                            return self.send(200, dashboard)
                        view = parse_qs(urlsplit(self.path).query).get('view', ['live'])[0]
                        collections = {'live': 'live_apps', 'timeline': 'events', 'health': 'probes',
                                       'spikes': 'spikes', 'destinations': 'alerts', 'adapters': 'adapters',
                                       'dns': 'dns'}
                        if view not in collections:
                            raise ValueError('Invalid dashboard')
                        rows = dashboard[collections[view]]
                        fields = list(dict.fromkeys(key for row in rows for key in row))
                        stream = io.StringIO(newline='')
                        writer = csv.writer(stream)
                        writer.writerow(['generated_unix', 'lookback_hours', 'dashboard', *fields])
                        for row in rows:
                            writer.writerow([dashboard['generated'], hours, view, *[csv_safe(json.dumps(row.get(f)) if isinstance(row.get(f), (dict,list)) else row.get(f)) for f in fields]])
                        return self.send(200, stream.getvalue().encode('utf-8-sig'), 'text/csv; charset=utf-8',
                                         {'Content-Disposition': f'attachment; filename="ray-i-{view}.csv"'})
                    if path == '/api/summary':
                        return self.send(200, app.summary(hours, adapter, source))
                    if path == '/api/connections':
                        total, rows = app.connection_store(source).records(hours, search, verdict, offset)
                        return self.send(200, {'total': total, 'rows': rows, 'offset': offset})
                    if path == '/api/export':
                        # Export all matching rows consistently in a single database read.
                        total, rows = app.connection_store(source).records(hours, search, verdict, 0, -1)
                        stream = io.StringIO(newline='')
                        writer = csv.writer(stream)
                        writer.writerow((*FIELDS, 'last_observed'))
                        for row in rows:
                            writer.writerow([csv_safe(row.get(f)) for f in (*FIELDS, 'last_observed')])
                        return self.send(200, stream.getvalue().encode('utf-8-sig'), 'text/csv; charset=utf-8',
                                         {'Content-Disposition': 'attachment; filename="ray-i-network-traffic-observer-connections.csv"'})
                    if path == '/api/bandwidth.csv':
                        summary = app.summary(hours, adapter, source)
                        stream = io.StringIO(newline='')
                        writer = csv.writer(stream)
                        writer.writerow(('timestamp_unix', 'adapter', 'bytes_received', 'bytes_sent', 'sample_seconds'))
                        with app.store.connect() as db:
                            for row in db.execute('SELECT ts,adapter,rx,tx,seconds FROM samples WHERE ts>=? AND adapter=? ORDER BY ts',
                                                  (time.time()-hours*3600, summary['adapter'])):
                                writer.writerow([csv_safe(value) for value in row])
                        return self.send(200, stream.getvalue().encode('utf-8-sig'), 'text/csv; charset=utf-8',
                                         {'Content-Disposition': 'attachment; filename="ray-i-network-traffic-observer-bandwidth.csv"'})
                    if path == '/api/report':
                        summary = app.summary(hours, adapter, source)
                        esc = lambda value: html.escape(str(value))
                        counts = summary['connections']
                        lines = ['<!doctype html><html lang="en"><meta charset="utf-8"><title>Ray-i Network Traffic Observer report</title>',
                                 '<body><h1>Ray-i Network Traffic Observer report</h1>',
                                 '<p>Generated: '+esc(time.strftime('%Y-%m-%d %H:%M:%S %Z'))+'</p>',
                                 '<p>Time range: last '+esc(hours)+' hours. Adapter: '+esc(summary['adapter'])+'</p>',
                                 '<p>Connection source: '+esc(source)+'. Sampled TCP observations.</p>',
                                 '<h2>Observed adapter bandwidth</h2><ul>',
                                 '<li>Received: '+esc(summary['totals']['rx'])+' bytes</li>',
                                 '<li>Sent: '+esc(summary['totals']['tx'])+' bytes</li></ul>',
                                 '<h2>Connection observations</h2><ul>']
                        for key, label in [('total','Connections'),('apps','Apps')]:
                            value = counts[key]
                            lines.append('<li>'+label+': '+esc(value)+'</li>')
                        lines.append('</ul><h2>Top apps by observed connections</h2><table><tr><th>Application</th><th>Connections</th></tr>')
                        for row in summary['apps']:
                            lines.append('<tr><td>'+esc(row['app'])+'</td><td>'+esc(row['total'])+'</td></tr>')
                        lines.append('</table><h2>Coverage</h2><p>This summary includes all retained observations in the time range; history search and decision filters do not apply. History is sampled while Ray-i runs and filters by last observation. Collection gaps and short-lived connections can be missing. Adapter traffic is not per-app bandwidth. No observations does not mean no traffic.</p></body></html>')
                        return self.send(200, ''.join(lines).encode(), 'text/html; charset=utf-8',
                                         {'Content-Disposition': 'attachment; filename="ray-i-network-traffic-observer-report.html"'})
                    return self.send(404, {'error': 'Not found'})
                files = {'/': ('index.html', 'text/html; charset=utf-8'),
                         '/insights.js': ('insights.js', 'text/javascript; charset=utf-8'),
                         '/insights.css': ('insights.css', 'text/css; charset=utf-8'),
                         '/app.js': ('app.js', 'text/javascript; charset=utf-8'),
                         '/dashboards.js': ('dashboards.js', 'text/javascript; charset=utf-8'),
                         '/style.css': ('style.css', 'text/css; charset=utf-8')}
                if path not in files:
                    return self.send(404, {'error': 'Not found'})
                name, mime = files[path]
                self.send(200, (ROOT / 'static' / name).read_bytes(), mime)
            except (ValueError, TypeError):
                self.send(400, {'error': 'Invalid query parameters'})
            except Exception:
                self.send(500, {'error': 'Local data could not be read'})

        def do_POST(self):
            if not self.safe_request(write=True):
                return
            path = urlsplit(self.path).path
            if path in ('/api/insights/record-start', '/api/insights/record-stop',
                        '/api/insights/disk', '/api/insights/benchmark'):
                try:
                    length = int(self.headers.get('Content-Length', '0'))
                    if not 0 < length <= 4096:
                        raise ValueError('Invalid request size')
                    body = json.loads(self.rfile.read(length))
                    if not isinstance(body, dict):
                        raise ValueError('Expected an object')
                    if path.endswith('/record-start'):
                        return self.send(200, app.recorder.start())
                    if path.endswith('/record-stop'):
                        return self.send(200, app.recorder.stop())
                    if not app.insight_job.acquire(blocking=False):
                        return self.send(409, {'error': 'A diagnostic job is already running'})
                    try:
                        result = (app.insights.disk_space(body.get('path')) if path.endswith('/disk')
                                  else app.insights.benchmark())
                    finally:
                        app.insight_job.release()
                    return self.send(200, result)
                except (ValueError, TypeError, AttributeError):
                    return self.send(400, {'error': 'Invalid diagnostic request or folder path'})
                except OSError:
                    return self.send(400, {'error': 'The selected folder could not be read'})
            if urlsplit(self.path).path in ('/api/monitoring', '/api/acknowledge'):
                try:
                    length = int(self.headers.get('Content-Length', '0'))
                    if not 0 < length <= 4096:
                        raise ValueError('Invalid request size')
                    body = json.loads(self.rfile.read(length))
                    if urlsplit(self.path).path == '/api/monitoring':
                        result = app.telemetry.configure(body)
                    else:
                        event_id = body.get('id')
                        if type(event_id) is not int or event_id < 1:
                            raise ValueError('Invalid event ID')
                        result = {'updated': app.telemetry.acknowledge(event_id)}
                    return self.send(200, result)
                except (ValueError, TypeError, AttributeError):
                    return self.send(400, {'error': 'Invalid monitoring settings or event ID'})
            if urlsplit(self.path).path == '/api/stop':
                self.send(200, {'message': 'Collector stopped. Your history is saved locally.'})
                app.stop.set()
                threading.Thread(target=self.server.shutdown, daemon=True).start()
                return
            return self.send(404, {'error': 'Not found'})
    return Handler


class LocalServer(ThreadingHTTPServer):
    # Windows SO_REUSEADDR otherwise permits another process to bind the same port.
    allow_reuse_address = os.name != 'nt'

    def server_bind(self):
        if os.name == 'nt':
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8787)
    parser.add_argument('--no-browser', action='store_true')
    default_dir = Path(os.environ.get('LOCALAPPDATA', Path.home() / '.local' / 'share')) / 'RayiNetworkTrafficObserver'
    parser.add_argument('--data-dir', type=Path, default=default_dir)
    args = parser.parse_args()
    app = RayiNetworkTrafficObserver(args.data_dir)
    try:
        server = LocalServer(('127.0.0.1', args.port), handler_for(app, args.port))
    except OSError:
        try:
            with app.opener.open(f'http://127.0.0.1:{args.port}/api/health', timeout=3) as response:
                existing = json.load(response)
            if existing.get('application') != 'Ray-i Network Traffic Observer':
                raise ValueError('Different application')
        except Exception:
            raise SystemExit(f'Port {args.port} is unavailable. Choose another with --port.')
        print(f'Ray-i is already running at http://127.0.0.1:{args.port}')
        if not args.no_browser:
            webbrowser.open(f'http://127.0.0.1:{args.port}')
        return
    for target in (app.maintain, app.collect_counters, app.collect_os_connections,
                   app.telemetry.collect_dns, app.telemetry.collect_probes,
                   lambda: app.recorder.collect(app.stop)):
        threading.Thread(target=target, daemon=True).start()
    print(f'Ray-i is running at http://127.0.0.1:{args.port} (Ctrl+C to stop)', flush=True)
    print(f'Local data: {args.data_dir}', flush=True)
    if not args.no_browser:
        webbrowser.open(f'http://127.0.0.1:{args.port}')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        app.stop.set()
        server.server_close()


if __name__ == '__main__':
    main()
