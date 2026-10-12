"""Derived observations, local DNS cache snapshots, and opt-in ICMP measurements."""
from collections import Counter, defaultdict, deque
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import statistics
import subprocess
import threading
import time


def valid_target(value):
    if not isinstance(value, str):
        raise ValueError('Enter one IPv4 or IPv6 address')
    address = ipaddress.ip_address(value.strip())
    if address.is_multicast or address.is_unspecified or str(address) == '255.255.255.255':
        raise ValueError('Use a unicast destination address')
    return str(address)


def windows_json(script, target=None):
    if os.name != 'nt':
        raise RuntimeError('This collector requires Windows')
    executable = Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
    env = dict(os.environ)
    if target is not None:
        env['RAYI_PROBE_TARGET'] = valid_target(target)
    result = subprocess.run([str(executable), '-NoProfile', '-NonInteractive', '-Command',
        "[Console]::OutputEncoding=[Text.UTF8Encoding]::new(); $ErrorActionPreference='Stop'; " + script],
        capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=12,
        creationflags=subprocess.CREATE_NO_WINDOW, env=env)
    if result.returncode:
        raise RuntimeError('Windows collector failed')
    return json.loads(result.stdout.lstrip('\ufeff').strip() or '[]')


def ping_once(target):
    return windows_json("$p=[Net.NetworkInformation.Ping]::new(); try { $r=$p.Send($env:RAYI_PROBE_TARGET,1200); "
        "@{status=$r.Status.ToString();ms=$(if($r.Status -eq 'Success'){$r.RoundtripTime}else{$null})} "
        "| ConvertTo-Json -Compress } finally {$p.Dispose()}", target)


class Telemetry:
    def __init__(self, app, data_dir):
        self.app, self.store = app, app.store
        self.config_path = data_dir / 'monitoring.json'
        self.lock = threading.RLock()
        self.current, self.last, self.previous = {}, {}, {}
        self.recent_rates = defaultdict(lambda: deque(maxlen=60))
        self.last_spike = {}
        self.dns_last, self.dns_error = None, None
        self.config = {'probe_enabled': False, 'probe_target': '1.1.1.1', 'spike_factor': 3.0,
                       'spike_min_bps': 1048576}
        if self.config_path.exists():
            try:
                self.config = self.validate_config(json.loads(self.config_path.read_text()), self.config)
            except (ValueError, OSError, TypeError):
                pass
        with self.store.connect() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS monitor_events (
                    id INTEGER PRIMARY KEY, ts REAL, source TEXT, kind TEXT, app TEXT,
                    destination TEXT, detail TEXT, acknowledged INTEGER DEFAULT 0);
                CREATE INDEX IF NOT EXISTS monitor_events_time ON monitor_events(ts,source,kind);
                CREATE TABLE IF NOT EXISTS known_destinations (
                    source TEXT, identity TEXT, destination TEXT, first_seen REAL, last_seen REAL,
                    PRIMARY KEY(source,identity,destination));
                CREATE TABLE IF NOT EXISTS app_rates (
                    ts REAL, app TEXT, rx REAL, tx REAL, measured INTEGER,
                    PRIMARY KEY(ts,app));
                CREATE TABLE IF NOT EXISTS probes (
                    ts REAL, target TEXT, status TEXT, ms REAL);
                CREATE INDEX IF NOT EXISTS probes_time ON probes(ts,target);
                CREATE TABLE IF NOT EXISTS dns_cache (
                    id TEXT PRIMARY KEY, name TEXT, type TEXT, data TEXT, status INTEGER,
                    ttl INTEGER, first_seen REAL, last_seen REAL);
            ''')

    @staticmethod
    def validate_config(values, current):
        if not isinstance(values, dict) or set(values) - set(current):
            raise ValueError('Unknown monitoring setting')
        config = dict(current, **values)
        if not isinstance(config['probe_enabled'], bool):
            raise ValueError('Probe enabled must be true or false')
        config['probe_target'] = valid_target(config['probe_target'])
        for field, lo, hi in [('spike_factor', 2, 20), ('spike_min_bps', 65536, 1073741824)]:
            v = config[field]
            if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) or not lo <= v <= hi:
                raise ValueError('Invalid spike threshold')
        return config

    def configure(self, values):
        with self.lock:
            config = self.validate_config(values, self.config)
            temporary = self.config_path.with_suffix('.tmp')
            temporary.write_text(json.dumps(config), encoding='utf-8')
            temporary.replace(self.config_path)
            self.config = config
            return dict(config)

    @staticmethod
    def event(db, now, source, kind, app='', destination='', detail=None):
        db.execute('INSERT INTO monitor_events(ts,source,kind,app,destination,detail) VALUES (?,?,?,?,?,?)',
                   (now, source, kind, app, destination, json.dumps(detail or {})))

    def observe(self, source, rows, now, complete=True):
        """Successful snapshots only. Gaps never imply a disconnection."""
        rows = {str(r['id']): dict(r) for r in rows if r.get('id')}
        with self.lock, self.store.connect() as db:
            prior = self.current.get(source, {})
            last = self.last.get(source)
            continuous = last is not None and 0 < now-last <= 20
            baseline = last is None or not continuous
            if last is not None and not continuous:
                self.event(db, now, source, 'collection_gap', detail={'seconds': now-last})
            rates = defaultdict(lambda: [0, 0, 0])
            for key, row in rows.items():
                app = row.get('profile_name') or row.get('profile') or 'Unknown app'
                identity = app
                dest = row.get('domain') or row.get('remote_ip') or ''
                active = row.get('tcp_status') not in ('TIME_WAIT', 'CLOSE', 'CLOSED', 'LISTEN')
                row['_active'] = bool(active)
                if key not in prior:
                    self.event(db, now, source, 'baseline' if baseline else 'appeared', app, dest,
                               {'port': row.get('remote_port'), 'status': row.get('tcp_status'), 'connection': key})
                elif continuous and prior[key].get('tcp_status') != row.get('tcp_status'):
                    self.event(db, now, source, 'state_changed', app, dest, {'status': row.get('tcp_status')})
                if dest and app != 'Unknown process':
                    new = db.execute('INSERT OR IGNORE INTO known_destinations VALUES (?,?,?,?,?)',
                                     (source, identity, dest, now, now)).rowcount
                    if new and not baseline:
                        self.event(db, now, source, 'new_destination', app, dest, {'identity': identity})
                    db.execute('UPDATE known_destinations SET last_seen=? WHERE source=? AND identity=? AND destination=?',
                               (now, source, identity, dest))
            if continuous and complete:
                for key in prior.keys()-rows.keys():
                    row = prior[key]
                    self.event(db, now, source, 'no_longer_observed', row.get('profile_name', 'Unknown app'),
                               row.get('domain') or row.get('remote_ip', ''), {'connection': key})
            self.current[source], self.last[source] = rows, now

    def bandwidth(self, adapter, rx, tx, seconds, now):
        rate = (rx+tx)/seconds
        with self.lock:
            history = self.recent_rates[adapter]
            if history and now-history[-1][0] > 20:
                history.clear()
            baseline = statistics.median(v for _, v in history) if history else None
            config = dict(self.config)
            if len(history) >= 12 and rate >= max(config['spike_min_bps'], baseline*config['spike_factor']) and now-self.last_spike.get(adapter, 0) >= 60:
                recent = self.current.get('windows', {}) if now-self.last.get('windows', 0) < 20 else {}
                apps = sorted({r.get('profile_name', 'Unknown') for r in recent.values() if r.get('_active')})
                with self.store.connect() as db:
                    self.event(db, now, 'windows', 'traffic_spike', destination=adapter,
                               detail={'rate': rate, 'baseline': baseline, 'factor': config['spike_factor'],
                                       'active_apps': apps[:20], 'active_app_count': len(apps)})
                self.last_spike[adapter] = now
            history.append((now, rate))

    def collect_dns(self):
        while not self.app.stop.is_set():
            try:
                rows = windows_json('Get-DnsClientCache | Select-Object Entry,Name,Type,Status,TimeToLive,Data | ConvertTo-Json -Compress')
                self.ingest_dns(rows if isinstance(rows, list) else [rows], time.time())
                self.dns_error = None
            except Exception:
                self.dns_error = 'Windows DNS cache is unavailable; retrying.'
            self.app.stop.wait(30)

    def ingest_dns(self, rows, now):
        with self.store.connect() as db:
            for row in rows:
                name = row.get('Entry') or row.get('Name')
                if not name:
                    continue
                values = (name, str(row.get('Type', '')), str(row.get('Data') or ''), row.get('Status'))
                key = hashlib.sha256(json.dumps(values).encode()).hexdigest()
                db.execute('''INSERT INTO dns_cache VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(id)
                    DO UPDATE SET ttl=excluded.ttl,last_seen=excluded.last_seen''',
                    (key, *values, row.get('TimeToLive'), now, now))
        self.dns_last = now

    def collect_probes(self):
        while not self.app.stop.is_set():
            with self.lock:
                config = dict(self.config)
            if config['probe_enabled']:
                try:
                    result = ping_once(config['probe_target'])
                    status = result['status']
                    ms = result.get('ms') if status == 'Success' else None
                except Exception:
                    status, ms = 'CollectorError', None
                with self.store.connect() as db:
                    db.execute('INSERT INTO probes VALUES (?,?,?,?)', (time.time(), config['probe_target'], status, ms))
            self.app.stop.wait(10)

    def cleanup(self, now):
        with self.store.connect() as db:
            for table, column in [('monitor_events', 'ts'), ('known_destinations', 'last_seen'),
                                  ('app_rates', 'ts'), ('probes', 'ts'), ('dns_cache', 'last_seen')]:
                db.execute(f'DELETE FROM {table} WHERE {column} < ?', (now-30*86400,))

    def acknowledge(self, event_id):
        with self.store.connect() as db:
            return db.execute("UPDATE monitor_events SET acknowledged=1 WHERE id=? AND kind IN ('new_destination','traffic_spike')", (event_id,)).rowcount

    def snapshot(self, hours, source, search='', adapter=''):
        now, cutoff = time.time(), time.time()-hours*3600
        with self.lock:
            current = list(self.current.get(source, {}).values())
            last = self.last.get(source)
            config = dict(self.config)
        live = [r for r in current if r.get('_active') and (not search or search.lower() in json.dumps(r).lower())]
        fresh = last is not None and now-last < 20
        grouped = {}
        for row in live:
            name = row.get('profile_name') or 'Unknown app'
            group = grouped.setdefault(name, {'app': name, 'connections': 0, 'destinations': set(), 'states': Counter()})
            group['connections'] += 1
            group['destinations'].add(row.get('domain') or row.get('remote_ip'))
            group['states'][row.get('tcp_status') or 'active'] += 1
        live_apps = [{**v, 'destinations': len(v['destinations']), 'states': dict(v['states'])} for v in grouped.values()]
        live_apps.sort(key=lambda r: r['connections'], reverse=True)
        with self.store.connect() as db:
            # Search is literal data. Source selects timeline and destination observations only.
            events = [dict(r) for r in db.execute('''SELECT * FROM monitor_events WHERE ts>=? AND source=?
                AND (?='' OR instr(lower(app || ' ' || destination),lower(?))>0) ORDER BY ts DESC,id DESC LIMIT 501''',
                (cutoff, source, search, search))]
            for row in events:
                row['detail'] = json.loads(row['detail'])
            alerts = [dict(r) for r in db.execute('''SELECT * FROM monitor_events WHERE ts>=? AND source=? AND kind='new_destination'
                AND (?='' OR instr(lower(app || ' ' || destination),lower(?))>0) ORDER BY ts DESC LIMIT 501''', (cutoff, source, search, search))]
            spikes = [dict(r) for r in db.execute("SELECT * FROM monitor_events WHERE ts>=? AND kind='traffic_spike' AND (?='' OR destination=?) ORDER BY ts DESC LIMIT 501", (cutoff, adapter, adapter))]
            for row in spikes:
                row['detail'] = json.loads(row['detail'])
            adapter_rows = [dict(r) for r in db.execute('''SELECT adapter,SUM(rx) AS rx,SUM(tx) AS tx,MAX(ts) AS last,
                SUM(seconds) AS seconds FROM samples WHERE ts>=? GROUP BY adapter ORDER BY rx+tx DESC''', (cutoff,))]
            for row in adapter_rows:
                latest = db.execute('SELECT rx/seconds AS rx_rate,tx/seconds AS tx_rate FROM samples WHERE adapter=? ORDER BY ts DESC LIMIT 1', (row['adapter'],)).fetchone()
                row.update(dict(latest) if latest and now-row['last'] < 20 else {'rx_rate': None, 'tx_rate': None})
            rates_at = db.execute('SELECT MAX(ts) FROM app_rates').fetchone()[0]
            rates = [dict(r) for r in db.execute('SELECT * FROM app_rates WHERE ts=? AND (?=\'\' OR instr(lower(app),lower(?))>0) ORDER BY rx+tx DESC', (rates_at, search, search))] if rates_at and rates_at >= cutoff else []
            probe_stats = dict(db.execute('''SELECT COUNT(*) AS attempts,SUM(status='Success') AS received,
                SUM(status='CollectorError') AS errors,AVG(ms) AS mean_ms,MIN(ms) AS min_ms,MAX(ms) AS max_ms
                FROM probes WHERE ts>=? AND target=?''', (cutoff, config['probe_target'])).fetchone())
            probes = [dict(r) for r in db.execute('SELECT * FROM probes WHERE ts>=? AND target=? ORDER BY ts DESC LIMIT 300', (cutoff, config['probe_target']))]
            dns = [dict(r) for r in db.execute('''SELECT * FROM dns_cache WHERE last_seen>=?
                AND (?='' OR instr(lower(name || ' ' || data),lower(?))>0) ORDER BY last_seen DESC,name LIMIT 501''', (cutoff, search, search))]
            known = db.execute('SELECT COUNT(*) FROM known_destinations WHERE source=? AND last_seen>=?', (source, cutoff)).fetchone()[0]
        attempts = (probe_stats['attempts'] or 0)-(probe_stats['errors'] or 0)
        probe_stats['loss_percent'] = 100*(attempts-(probe_stats['received'] or 0))/attempts if attempts else None
        return {'generated': now, 'source': source, 'last_sample': last, 'fresh': fresh,
                'live_apps': live_apps, 'live_connections': len(live), 'events': events[:500], 'events_truncated': len(events)>500,
                'alerts': alerts[:500], 'alerts_truncated': len(alerts)>500, 'known_destinations': known,
                'spikes': spikes[:500], 'spikes_truncated': len(spikes)>500, 'adapters': adapter_rows,
                'rates': rates, 'rates_at': rates_at, 'rates_fresh': bool(rates_at and now-rates_at<20),
                'config': config, 'probes': list(reversed(probes)), 'probe_stats': probe_stats,
                'dns': dns[:500], 'dns_truncated': len(dns)>500, 'dns_last': self.dns_last, 'dns_error': self.dns_error,
                }
