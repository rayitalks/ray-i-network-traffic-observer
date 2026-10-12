"""Synthetic-data regression tests. No adapter collection runs."""
import csv
import gc
import http.client
from http.server import BaseHTTPRequestHandler
import io
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock
from urllib.parse import urlencode

from app import RayiNetworkTrafficObserver, Store, RETENTION, ThreadingHTTPServer, counter_delta, csv_safe, handler_for


def record(identifier, app='Browser', domain='example.test', allowed=True, tunneled=False):
    return {'id': identifier, 'profile_name': app, 'domain': domain,
            'remote_ip': '192.0.2.1', 'allowed': allowed, 'tunneled': tunneled}


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.directory.name) / 'test.sqlite3')

    def tearDown(self):
        gc.collect()
        self.directory.cleanup()

    def test_upsert_preserves_uniqueness_and_updates_unknown_verdict(self):
        now = time.time()
        self.store.ingest([record('one', allowed=True)], now - 10)
        self.store.ingest([record('one', app='Updated', allowed=None)], now)
        total, rows = self.store.records()
        self.assertEqual(total, 1)
        self.assertEqual(rows[0]['profile_name'], 'Updated')
        self.assertIsNone(rows[0]['allowed'])
        self.assertEqual(rows[0]['last_observed'], now)
        self.assertEqual(self.store.records(verdict='allowed')[0], 0)
        self.assertEqual(self.store.records(verdict='blocked')[0], 0)

    def test_search_wildcards_are_literal_and_sql_text_is_data(self):
        self.store.ingest([record('literal', app='100%_safe\\tool'),
                           record('ordinary', app='100 percentXsafe')], time.time())
        for search in ('%', '_', '\\'):
            with self.subTest(search=search):
                total, rows = self.store.records(search=search)
                self.assertEqual(total, 1)
                self.assertEqual(rows[0]['id'], 'literal')
        self.assertEqual(self.store.records(search="' OR 1=1 --")[0], 0)
        self.assertEqual(self.store.records()[0], 2)

    def test_time_verdict_and_route_filters(self):
        now = time.time()
        self.store.ingest([record('allowed'), record('blocked', allowed=False),
                           record('routed', tunneled=True)], now)
        self.store.ingest([record('old', allowed=False)], now - 48 * 3600)
        self.assertEqual(self.store.records(hours=24)[0], 3)
        self.assertEqual(self.store.records(verdict='blocked')[1][0]['id'], 'blocked')

    def test_cleanup_purges_old_samples_and_connections_without_collectors(self):
        now = time.time()
        self.store.ingest([record('expired')], now - RETENTION - 1)
        self.store.ingest([record('current')], now)
        with self.store.connect() as db:
            db.executemany('INSERT INTO samples VALUES (?,?,?,?,?)',
                           [(now - RETENTION - 1, 'Ethernet', 10, 20, 5),
                            (now, 'Ethernet', 30, 40, 5)])
        self.store.cleanup(now)
        with self.store.connect() as db:
            self.assertEqual([row[0] for row in db.execute('SELECT id FROM connections')], ['current'])
            self.assertEqual(db.execute('SELECT COUNT(*), SUM(rx) FROM samples').fetchone()[:], (1, 30))


class MeasurementTests(unittest.TestCase):
    def test_counter_delta_and_reset_or_suspend(self):
        self.assertEqual(counter_delta((100, 200), (150, 300), 5), (50, 100))
        for new, elapsed in (((90, 300), 5), ((150, 190), 5),
                             ((150, 300), 0), ((150, 300), -1), ((150, 300), 31)):
            with self.subTest(new=new, elapsed=elapsed):
                self.assertIsNone(counter_delta((100, 200), new, elapsed))

    def test_csv_guard_preserves_plain_data_and_neutralizes_formulas(self):
        for value in ('=1+1', '+SUM(A1)', '-1+2', '@SUM(A1)', '  =1+1', '\t=1+1', '\r=1+1'):
            with self.subTest(value=value):
                self.assertEqual(csv_safe(value), "'" + value)
        self.assertEqual(csv_safe('example.test'), 'example.test')
        self.assertEqual(csv_safe(None), '')
        self.assertEqual(csv_safe(123), '123')


class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.app = RayiNetworkTrafficObserver(Path(self.directory.name))
        self.app.authorize = Mock(side_effect=AssertionError('Must never authorize during tests'))
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), BaseHTTPRequestHandler)
        self.port = self.server.server_address[1]
        self.server.RequestHandlerClass = handler_for(self.app, self.port)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        gc.collect()
        self.directory.cleanup()

    def request(self, path, method='GET', headers=None, body=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=3)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def test_host_origin_and_cross_site_rejected(self):
        for headers in ({'Host': 'attacker.test'}, {'Origin': 'https://attacker.test'},
                        {'Sec-Fetch-Site': 'cross-site'}):
            with self.subTest(headers=headers):
                self.assertEqual(self.request('/api/connections', headers=headers)[0], 403)

    def test_monitoring_requires_csrf_and_validates_body(self):
        body = json.dumps({'probe_enabled': True, 'probe_target': '1.1.1.1'})
        self.assertEqual(self.request('/api/monitoring', 'POST', body=body)[0], 403)
        headers = {'X-Ray-i-Token': self.app.csrf, 'Content-Type': 'application/json'}
        self.assertEqual(self.request('/api/monitoring', 'POST', headers, body)[0], 200)
        self.assertEqual(self.request('/api/monitoring', 'POST', headers, '{invalid')[0], 400)
        self.assertEqual(self.request('/api/monitoring', 'POST', headers, '{"probe_target":"host;cmd"}')[0], 400)

    def test_dashboard_export_matches_filtered_rows(self):
        self.app.telemetry.observe('windows', [record('one', app='=unsafe'), record('two', app='Other')], time.time())
        query = urlencode({'source': 'windows', 'search': '=unsafe', 'view': 'timeline'})
        status, _, payload = self.request('/api/dashboard?' + query)
        self.assertEqual(status, 200)
        rows = json.loads(payload)['events']
        status, _, payload = self.request('/api/dashboard.csv?' + query)
        self.assertEqual(status, 200)
        exported = list(csv.DictReader(io.StringIO(payload.decode('utf-8-sig'))))
        self.assertEqual([int(r['id']) for r in exported], [r['id'] for r in rows])
        self.assertEqual(exported[0]['app'], "'=unsafe")
        self.assertEqual(self.request('/api/dashboard.csv?view=invalid')[0], 400)

    def test_csrf_missing_or_wrong_rejected_without_auth_side_effect(self):
        for headers in ({}, {'X-Ray-i-Token': 'wrong'}):
            with self.subTest(headers=headers):
                self.assertEqual(self.request('/api/connect', 'POST', headers)[0], 403)

    def test_nonfinite_negative_and_zero_ranges_rejected(self):
        for hours in ('nan', 'inf', '-1', '0', '721'):
            with self.subTest(hours=hours):
                self.assertEqual(self.request('/api/connections?hours=' + hours)[0], 400)

    def test_valid_read_and_csv_export_share_filters(self):
        now = time.time()
        self.app.os_store.ingest([record('match', app='=unsafe', domain='target.test', allowed=False),
                               record('allowed', domain='target.test'),
                               record('different', domain='other.test', allowed=False)], now)
        self.app.os_store.ingest([record('old', domain='target.test', allowed=False)], now - 48 * 3600)
        query = urlencode({'hours': 24, 'search': 'target', 'verdict': 'blocked'})
        status, headers, payload = self.request('/api/connections?' + query)
        self.assertEqual(status, 200)
        rows = json.loads(payload)['rows']
        self.assertEqual([r['id'] for r in rows], ['match'])
        self.assertEqual(headers['Cache-Control'], 'no-store')
        self.assertNotIn('Access-Control-Allow-Origin', headers)
        status, headers, payload = self.request('/api/export?' + query)
        self.assertEqual(status, 200)
        exported = list(csv.DictReader(io.StringIO(payload.decode('utf-8-sig'))))
        self.assertEqual([r['id'] for r in exported], ['match'])
        self.assertEqual(exported[0]['profile_name'], "'=unsafe")
        self.assertIn('attachment', headers['Content-Disposition'])

    def test_only_windows_source_is_supported(self):
        self.app.os_store.ingest([record('one')], time.time())
        status, _, payload = self.request('/api/connections')
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(payload)['rows'][0]['id'], 'one')
        self.assertEqual(self.request('/api/connections?source=unexpected')[0], 400)

    def test_report_escapes_app_and_adapter_names_and_ignores_history_filters(self):
        now = time.time()
        name = '<script>alert("x")</script>'
        adapter = '<img src=x onerror=alert(1)>'
        self.app.os_store.ingest([record('windows', app=name, allowed=None)], now)
        with self.app.store.connect() as db:
            db.execute('INSERT INTO samples VALUES (?,?,?,?,?)', (now, adapter, 10, 20, 5))
        query = urlencode({'source': 'windows', 'adapter': adapter, 'search': 'no-match', 'verdict': 'blocked'})
        status, headers, payload = self.request('/api/report?' + query)
        self.assertEqual(status, 200)
        text = payload.decode()
        self.assertIn('&lt;script&gt;', text)
        self.assertIn('&lt;img', text)
        self.assertNotIn('<script>', text)
        self.assertNotIn('<img', text)
        self.assertIn('Connections: 1', text)
        self.assertIn('attachment', headers['Content-Disposition'])

    def test_bandwidth_csv_respects_adapter_and_time_scope(self):
        now = time.time()
        with self.app.store.connect() as db:
            db.executemany('INSERT INTO samples VALUES (?,?,?,?,?)',
                           [(now, 'Ethernet', 10, 20, 5), (now, 'VPN', 90, 80, 5),
                            (now - 48 * 3600, 'Ethernet', 100, 200, 5)])
        status, _, payload = self.request('/api/bandwidth.csv?hours=24&adapter=Ethernet&source=windows')
        self.assertEqual(status, 200)
        rows = list(csv.DictReader(io.StringIO(payload.decode('utf-8-sig'))))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['adapter'], 'Ethernet')
        self.assertEqual(rows[0]['bytes_received'], '10')


if __name__ == '__main__':
    unittest.main()
