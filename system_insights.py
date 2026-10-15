"""Read-only host diagnostics and explicitly requested, bounded local workloads."""
import hashlib
import heapq
import ipaddress
import os
from pathlib import Path
import socket
import stat
import threading
import time

import psutil

try:
    import winreg
except ImportError:
    winreg = None


class SystemInsights:
    def __init__(self):
        self._benchmark_lock = threading.Lock()

    def snapshot(self):
        result = {'errors': []}
        try:
            # A real short sampling interval avoids psutil's first-call zero baseline.
            cores = psutil.cpu_percent(interval=0.1, percpu=True)
            result.update(cpu_percent=sum(cores) / len(cores) if cores else None,
                          per_core_percent=cores, logical_cpus=psutil.cpu_count())
        except (OSError, psutil.Error) as exc:
            result.update(cpu_percent=None, per_core_percent=[], logical_cpus=None)
            result['errors'].append(str(exc))
        try:
            memory = psutil.virtual_memory()
            result['memory'] = {k: getattr(memory, k) for k in ('total', 'available', 'used', 'percent')}
        except (OSError, psutil.Error) as exc:
            result['memory'] = None
            result['errors'].append(str(exc))
        try:
            frequency = psutil.cpu_freq()
            result['frequency_mhz'] = frequency.current if frequency else None
        except (OSError, psutil.Error, NotImplementedError):
            result['frequency_mhz'] = None
        result['battery'] = {'available': False, 'percent': None, 'power_plugged': None, 'seconds_left': None}
        try:
            battery = psutil.sensors_battery()
            if battery:
                result['battery'].update(available=True, percent=battery.percent,
                    power_plugged=battery.power_plugged,
                    seconds_left=battery.secsleft if battery.secsleft >= 0 else None)
        except (OSError, psutil.Error, NotImplementedError, AttributeError):
            pass
        return result

    def connections(self):
        result = {'connections': [], 'errors': [], 'exposure_caveat':
                  'Local bindings do not establish Internet reachability. Firewall, NAT and routing affect exposure; permissions may hide sockets or owners.'}
        try:
            sockets = psutil.net_connections(kind='inet')
        except (OSError, psutil.Error) as exc:
            result['errors'].append(str(exc))
            return result
        owners = {}
        for connection in sockets:
            if connection.pid not in owners:
                owner = {'pid': connection.pid, 'name': None, 'create_time': None}
                if connection.pid is not None:
                    try:
                        process = psutil.Process(connection.pid)
                        with process.oneshot():
                            owner.update(name=process.name(), create_time=process.create_time())
                    except (OSError, psutil.Error):
                        pass
                owners[connection.pid] = owner
            local = connection.laddr
            remote = connection.raddr
            address = local[0] if local else ''
            try:
                ip = ipaddress.ip_address(address.split('%')[0])
                scope = 'all interfaces' if ip.is_unspecified else 'loopback' if ip.is_loopback else 'specific interface'
            except ValueError:
                scope = 'unknown'
            result['connections'].append(dict(owners[connection.pid],
                protocol='UDP' if connection.type == socket.SOCK_DGRAM else 'TCP',
                local_address=address, local_port=local[1] if local else None,
                remote_address=remote[0] if remote else '', remote_port=remote[1] if remote else None,
                status=connection.status, scope=scope))
        result['connections'].sort(key=lambda row: (row['protocol'], row['local_port'] or 0, row['pid'] or -1))
        return result

    def installed_apps(self):
        result = {'available': winreg is not None, 'apps': [], 'errors': [],
                  'size_caveat': 'Registry EstimatedSize values are publisher estimates; missing sizes are unknown. This inventory may omit portable or Store apps.'}
        if winreg is None:
            return result
        seen = set()
        subkey = r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
        for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
            for view in (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
                try:
                    with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ | view) as root:
                        for index in range(winreg.QueryInfoKey(root)[0]):
                            try:
                                with winreg.OpenKey(root, winreg.EnumKey(root, index)) as key:
                                    def value(name):
                                        try:
                                            return winreg.QueryValueEx(key, name)[0]
                                        except OSError:
                                            return None
                                    name = value('DisplayName')
                                    if not name:
                                        continue
                                    version, publisher = value('DisplayVersion'), value('Publisher')
                                    location, size = value('InstallLocation'), value('EstimatedSize')
                                    identity = (name, version, publisher, location)
                                    if identity in seen:
                                        continue
                                    seen.add(identity)
                                    result['apps'].append(dict(name=name, version=version, publisher=publisher,
                                        install_location=location, estimated_size_bytes=size * 1024
                                        if isinstance(size, int) and size >= 0 else None))
                            except OSError as exc:
                                result['errors'].append(str(exc))
                except FileNotFoundError:
                    pass
                except OSError as exc:
                    result['errors'].append(str(exc))
        result['apps'].sort(key=lambda row: (-(row['estimated_size_bytes'] or 0), row['name'].casefold()))
        return result

    def disk_space(self, path):
        if not isinstance(path, str) or not path.strip():
            raise ValueError('Supply an explicit absolute directory path')
        root = Path(path)
        if not root.is_absolute():
            raise ValueError('Supply an explicit absolute directory path')
        # Reject symlinks/junctions in the entire supplied path, not only its final component.
        for component in (*reversed(root.parents), root):
            metadata = component.lstat()
            if stat.S_ISLNK(metadata.st_mode) or getattr(metadata, 'st_file_attributes', 0) & 0x400:
                raise ValueError('Symbolic links and reparse points are not scanned')
        if not root.is_dir():
            raise ValueError('Path must be a directory')
        result = dict(path=str(root), total_bytes=0, files=0, directories=0, largest_files=[],
                      truncated=False, skipped_links=0, errors=[],
                      size_caveat='Logical file sizes; hard links may be counted more than once. Scan stops at 10,000 entries or three seconds.')
        pending, largest, entries = [root], [], 0
        deadline = time.monotonic() + 3
        while pending:
            if entries >= 10000 or time.monotonic() >= deadline:
                result['truncated'] = True
                break
            directory = pending.pop()
            try:
                with os.scandir(directory) as children:
                    for child in children:
                        if entries >= 10000 or time.monotonic() >= deadline:
                            result['truncated'] = True
                            break
                        entries += 1
                        try:
                            metadata = child.stat(follow_symlinks=False)
                            if stat.S_ISLNK(metadata.st_mode) or getattr(metadata, 'st_file_attributes', 0) & 0x400:
                                result['skipped_links'] += 1
                            elif stat.S_ISDIR(metadata.st_mode):
                                result['directories'] += 1
                                pending.append(Path(child.path))
                            elif stat.S_ISREG(metadata.st_mode):
                                result['files'] += 1
                                result['total_bytes'] += metadata.st_size
                                heapq.heappush(largest, (metadata.st_size, child.path))
                                if len(largest) > 20:
                                    heapq.heappop(largest)
                        except OSError as exc:
                            if len(result['errors']) < 20:
                                result['errors'].append(str(exc))
            except OSError as exc:
                if len(result['errors']) < 20:
                    result['errors'].append(str(exc))
            if result['truncated']:
                break
        result['largest_files'] = [{'path': p, 'size_bytes': size} for size, p in sorted(largest, reverse=True)]
        return result

    def benchmark(self):
        if not self._benchmark_lock.acquire(blocking=False):
            raise ValueError('A benchmark is already running')
        try:
            payload, iterations = b'\x5a' * (1024 * 1024), 0
            started = time.perf_counter()
            while time.perf_counter() - started < 1:
                hashlib.sha256(payload).digest()
                iterations += 1
            seconds = time.perf_counter() - started
            return dict(algorithm='SHA-256, 1 MiB blocks, single worker', seconds=seconds,
                iterations=iterations, bytes_processed=iterations * len(payload),
                mib_per_second=iterations / seconds if seconds else 0,
                caveat='A local hashing throughput sample, not an overall PC score. Hardware acceleration, power settings and background load affect results.')
        finally:
            self._benchmark_lock.release()
