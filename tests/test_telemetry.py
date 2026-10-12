"""Validate measurement semantics with synthetic snapshots; no external probes."""
import tempfile
import time
import unittest
from pathlib import Path

from app import RayiNetworkTrafficObserver


class TelemetryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.app = RayiNetworkTrafficObserver(Path(self.directory.name))
        self.t = self.app.telemetry
        self.now = time.time()

    def tearDown(self):
        self.directory.cleanup()

    def row(self, identifier='one', destination='192.0.2.1', rx=100, tx=50):
        return dict(id=identifier, profile_name='Browser', remote_ip=destination,
                    tcp_status='ESTABLISHED', active=True, bytes_received=rx, bytes_sent=tx)

    def test_baseline_new_destination_and_gap_semantics(self):
        self.t.observe('windows', [self.row()], self.now-15)
        self.t.observe('windows', [self.row(), self.row('two', '192.0.2.2')], self.now-10)
        self.t.observe('windows', [], self.now-5, complete=False)
        d = self.t.snapshot(24, 'windows')
        self.assertEqual(len(d['alerts']), 1)
        self.assertEqual(d['alerts'][0]['destination'], '192.0.2.2')
        self.assertNotIn('no_longer_observed', [e['kind'] for e in d['events']])
        self.t.observe('windows', [self.row('three', '192.0.2.3')], self.now+30)
        d = self.t.snapshot(24, 'windows')
        self.assertEqual(len(d['alerts']), 1)
        self.assertIn('collection_gap', [e['kind'] for e in d['events']])
        self.assertEqual(self.t.acknowledge(d['alerts'][0]['id']), 1)

    def test_spike_warmup_cooldown_and_gap(self):
        for i in range(12):
            self.t.bandwidth('Ethernet', 1000, 0, 5, self.now-60+i*5)
        self.t.bandwidth('Ethernet', 10_000_000, 0, 5, self.now)
        self.t.bandwidth('Ethernet', 10_000_000, 0, 5, self.now+5)
        self.t.bandwidth('Ethernet', 10_000_000, 0, 5, self.now+90)
        self.assertEqual(len(self.t.snapshot(24, 'windows')['spikes']), 1)

    def test_probe_errors_excluded_and_dns_upsert(self):
        with self.t.store.connect() as db:
            db.executemany('INSERT INTO probes VALUES (?,?,?,?)', [
                (self.now, '1.1.1.1', 'Success', 8),
                (self.now, '1.1.1.1', 'TimedOut', None),
                (self.now, '1.1.1.1', 'CollectorError', None)])
        cache = dict(Entry='example.test', Type=1, Data='192.0.2.1', Status=0, TimeToLive=30)
        self.t.ingest_dns([cache], self.now-10)
        self.t.ingest_dns([{**cache, 'TimeToLive': 20}], self.now)
        d = self.t.snapshot(24, 'windows')
        self.assertEqual(d['probe_stats']['loss_percent'], 50)
        self.assertEqual(d['probe_stats']['mean_ms'], 8)
        self.assertEqual(len(d['dns']), 1)
        self.assertEqual(d['dns'][0]['first_seen'], self.now-10)
        self.assertEqual(d['dns'][0]['ttl'], 20)

    def test_config_validation_and_persistence(self):
        for config in ({'probe_target': '1.1.1.1; whoami'}, {'probe_enabled': 1},
                       {'spike_factor': float('nan')}, {'spike_min_bps': -1}, {'unexpected': 2}):
            with self.subTest(config=config), self.assertRaises(ValueError):
                self.t.configure(config)
        self.t.configure({'probe_enabled': True, 'probe_target': '1.1.1.1'})
        restored = RayiNetworkTrafficObserver(Path(self.directory.name))
        self.assertTrue(restored.telemetry.config['probe_enabled'])


if __name__ == '__main__':
    unittest.main()
