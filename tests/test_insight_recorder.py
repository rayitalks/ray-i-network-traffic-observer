import unittest
from unittest.mock import Mock
from insight_recorder import InsightRecorder


class RecorderTests(unittest.TestCase):
    def test_cap_stops_without_overwriting_beginning_and_restart_clears(self):
        provider = Mock()
        provider.snapshot.return_value = {'cpu_percent': 12}
        recorder = InsightRecorder(provider, max_samples=2)
        recorder.start()
        recorder.sample()
        recorder.start()  # duplicate request must not erase active session
        recorder.sample()
        recorder.sample()
        self.assertFalse(recorder.recording()['recording'])
        self.assertEqual(len(recorder.recording()['samples']), 2)
        recorder.start()
        self.assertEqual(recorder.recording()['samples'], [])

    def test_gaps_are_explicit_and_export_is_detached(self):
        provider = Mock()
        provider.snapshot.side_effect = [OSError('no sensor'), {'cpu_percent': 7}]
        recorder = InsightRecorder(provider)
        recorder.start()
        recorder.sample()
        recorder.sample()
        exported = recorder.stop()
        self.assertNotIn('cpu_percent', exported['samples'][0])
        self.assertTrue(exported['samples'][0]['errors'])
        exported['samples'][1]['cpu_percent'] = 99
        self.assertEqual(recorder.recording()['samples'][1]['cpu_percent'], 7)
