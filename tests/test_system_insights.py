"""Diagnostics retain unknown values and bound explicitly requested work."""
import socket
import stat
import tempfile
from pathlib import Path
from types import SimpleNamespace as NS
import unittest
from unittest.mock import MagicMock, patch

from system_insights import SystemInsights


class SystemInsightsTests(unittest.TestCase):
    def setUp(self):
        self.insights = SystemInsights()

    def test_missing_battery_and_frequency_are_unknown(self):
        with patch('system_insights.psutil.cpu_percent', return_value=[20, 40]), \
             patch('system_insights.psutil.cpu_count', return_value=2), \
             patch('system_insights.psutil.cpu_freq', return_value=None), \
             patch('system_insights.psutil.virtual_memory', return_value=NS(total=100, available=70, used=30, percent=30)), \
             patch('system_insights.psutil.sensors_battery', return_value=None):
            result = self.insights.snapshot()
        self.assertEqual(result['cpu_percent'], 30)
        self.assertFalse(result['battery']['available'])
        self.assertIsNone(result['battery']['percent'])
        self.assertIsNone(result['frequency_mhz'])

    def test_listeners_udp_and_owner_identity_survive(self):
        sockets = [NS(pid=5, type=socket.SOCK_STREAM, laddr=('0.0.0.0', 80), raddr=(), status='LISTEN'),
                   NS(pid=5, type=socket.SOCK_DGRAM, laddr=('127.0.0.1', 53), raddr=(), status='NONE')]
        process = MagicMock()
        process.name.return_value = 'example'
        process.create_time.return_value = 123.5
        with patch('system_insights.psutil.net_connections', return_value=sockets), \
             patch('system_insights.psutil.Process', return_value=process):
            result = self.insights.connections()
        self.assertEqual([row['protocol'] for row in result['connections']], ['TCP', 'UDP'])
        self.assertEqual(result['connections'][0]['scope'], 'all interfaces')
        self.assertEqual(result['connections'][1]['scope'], 'loopback')
        self.assertEqual(result['connections'][0]['create_time'], 123.5)
        self.assertIn('Firewall', result['exposure_caveat'])

    def test_registry_sizes_sorted_deduplicated_and_unknown_preserved(self):
        registry = MagicMock()
        registry.KEY_READ, registry.KEY_WOW64_64KEY, registry.KEY_WOW64_32KEY = 1, 2, 4
        registry.QueryInfoKey.return_value = (3, 0, 0)
        registry.EnumKey.side_effect = lambda key, index: str(index)
        registry.OpenKey.side_effect = lambda key, name, *args: _Key(name)
        values = [{'DisplayName': 'Small', 'EstimatedSize': 2},
                  {'DisplayName': 'Large', 'EstimatedSize': 10}, {'DisplayName': 'Unknown'}]
        def query(key, name):
            if name not in values[int(key)]:
                raise FileNotFoundError()
            return values[int(key)][name], 1
        registry.QueryValueEx.side_effect = query
        with patch('system_insights.winreg', registry):
            result = self.insights.installed_apps()
        self.assertEqual([r['name'] for r in result['apps']], ['Large', 'Small', 'Unknown'])
        self.assertEqual(result['apps'][0]['estimated_size_bytes'], 10240)
        self.assertIsNone(result['apps'][2]['estimated_size_bytes'])

    def test_disk_scan_counts_sizes_and_rejects_implicit_path(self):
        with self.assertRaises(ValueError):
            self.insights.disk_space('')
        with self.assertRaises(ValueError):
            self.insights.disk_space('.')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'a').write_bytes(b'abc')
            (root / 'nested').mkdir()
            (root / 'nested' / 'b').write_bytes(b'12345')
            result = self.insights.disk_space(directory)
        self.assertEqual(result['total_bytes'], 8)
        self.assertEqual(result['files'], 2)
        self.assertEqual(result['directories'], 1)
        self.assertFalse(result['truncated'])

    def test_disk_scan_skips_reparse_and_has_time_budget(self):
        child = NS(path='junction', stat=lambda **kwargs: NS(st_mode=stat.S_IFDIR, st_file_attributes=0x400))
        children = MagicMock()
        children.__enter__.return_value = [child]
        with tempfile.TemporaryDirectory() as directory, \
             patch('system_insights.os.scandir', return_value=children):
            result = self.insights.disk_space(directory)
            self.assertEqual(result['skipped_links'], 1)
            self.assertEqual(result['directories'], 0)
            with patch('system_insights.time.monotonic', side_effect=[0, 4]):
                result = self.insights.disk_space(directory)
            self.assertTrue(result['truncated'])

    def test_benchmark_is_bounded_and_rejects_overlap(self):
        with patch('system_insights.time.perf_counter', side_effect=[0, .1, .5, 1.1, 1.2]), \
             patch('system_insights.hashlib.sha256') as digest:
            result = self.insights.benchmark()
        self.assertEqual(digest.call_count, 2)
        self.assertEqual(result['bytes_processed'], 2 * 1024 * 1024)
        self.assertAlmostEqual(result['mib_per_second'], 2 / 1.2)
        self.insights._benchmark_lock.acquire()
        try:
            with self.assertRaises(ValueError):
                self.insights.benchmark()
        finally:
            self.insights._benchmark_lock.release()


class _Key:
    def __init__(self, name):
        self.name = name

    def __enter__(self):
        return self.name

    def __exit__(self, *args):
        pass
