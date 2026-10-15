"""Bounded local system recording; independent NTO trace format."""
import copy
import threading
import time


class InsightRecorder:
    def __init__(self, provider, max_samples=3600):
        self.provider = provider
        self.max_samples = max_samples
        self.lock = threading.RLock()
        self.active = False
        self.samples = []
        self.latest = {'ts': None, 'errors': ['Waiting for first system sample']}

    def sample(self):
        with self.lock:
            try:
                current = dict(self.provider.snapshot(), ts=time.time())
            except Exception:
                current = {'ts': time.time(), 'errors': ['System sample unavailable']}
            self.latest = current
            if self.active:
                self.samples.append(current)
                if len(self.samples) >= self.max_samples:
                    self.active = False
            return copy.deepcopy(current)

    def collect(self, stop):
        while not stop.is_set():
            self.sample()
            stop.wait(2)

    def snapshot(self):
        with self.lock:
            return copy.deepcopy(self.latest)

    def recording(self):
        with self.lock:
            return {'recording': self.active, 'samples': copy.deepcopy(self.samples),
                    'max_samples': self.max_samples}

    def start(self):
        with self.lock:
            if not self.active:
                self.samples = []
                self.active = True
            return self.recording()

    def stop(self):
        with self.lock:
            self.active = False
            return self.recording()
