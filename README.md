# Ray-i Network Traffic Observer

**Your network, in focus.**

Turn network activity into a clear, searchable picture with **Ray-i Network Traffic Observer**: nine Windows dashboards for live application connections, adapter bandwidth, TCP history, connection timelines, traffic spikes, new destinations, adapter comparison, DNS cache insights, and optional network-health checks.

See which applications have active connections, spot changes as they happen between samples, investigate first-seen destinations, and compare traffic across your adapters. Keep 30 days of observations on your computer and turn them into CSV exports and shareable HTML reports. No account, cloud service, or observation uploads required.

## Platform support

**Windows is the supported platform for this release.** DNS cache collection and optional ICMP health probes use Windows PowerShell; the included setup launcher is Windows-specific. The Python core uses psutil for TCP snapshots and adapter counters, but full Linux and macOS operation has not been validated and those Windows-dependent features are not portable as implemented. This release does not claim full Linux or macOS support.

## Quick start

Install Python 3.11 or newer on Windows, download this repository, and double-click **Start Ray-i Network Traffic Observer.cmd**. The launcher creates an isolated Python environment, installs the pinned dependency, and opens the dashboard on this computer.

Manual setup:

```powershell
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe app.py
```

The interface runs at `http://127.0.0.1:8787`. Optional arguments: `--port 8787`, `--no-browser`, and `--data-dir <directory>`. The server binds only to loopback; this is a desktop tool, not an internet-hosted monitoring service.

## Dashboards

- **Overview:** adapter receive/send totals and rates, observed connections, and top applications.
- **Network history:** searchable, paginated TCP connection observations with CSV and HTML reports.
- **Live app activity:** currently sampled active sockets grouped by application.
- **Connection timeline:** initial baseline, appeared, changed, missing, and collection-gap events.
- **Network health:** opt-in ICMP probes to an IP address; latency, unanswered probes, and collector errors.
- **Traffic spikes:** per-interface rates compared with a rolling median, with adjustable thresholds.
- **New destinations:** reviewable first-seen application/destination pairs after the learning baseline.
- **Adapter comparison:** independent totals and current rates for each interface.
- **DNS activity:** read-only Windows DNS cache observations.

The interface refreshes approximately every five seconds. DNS cache collection runs every 30 seconds. Network-health probes start disabled on new installations and can be started/stopped in the app. The suggested target is the public Cloudflare address `1.1.1.1`.

## Measurement limits

TCP history is sampled while the app runs. Short-lived sockets between samples may be missed, process attribution may be unknown, and reused socket endpoints may merge observations. TCP snapshots do not supply per-app byte counts, firewall decisions, tunnel health, or domain attribution. Adapter counters measure bytes independently; virtual and physical interfaces can count overlapping traffic.

New-destination alerts mean unseen in the retained baseline, not malicious. Spike alerts need 12 preceding samples and default to 3 times the median of up to 60 samples with a 1 MiB/s floor and one-minute cooldown per adapter. Nearby app activity is correlation, not byte attribution. Baselines reset across long collection gaps.

DNS cache entries are not a query log: they cannot establish request counts or requesting applications and may originate from the hosts file. Health probes use one ICMP echo per approximately 10 seconds with a 1.2-second timeout. Failed replies do not prove a whole-network outage; collector errors are excluded from the unanswered-probe percentage.

## Privacy and exports

Runtime databases and settings are stored outside the source directory, under the operating system's application-data folder. No analytics, account tokens, connection records, screenshots, personal paths, or exports are bundled in this release. The app does not upload observations. Starting probes sends ICMP traffic only to the chosen target. Initial dependency installation contacts the Python package registry.

Observations are retained for 30 days. Closing the browser does not stop collection; use **Stop collector** or stop the server. Exports contain the user's own network details and should be reviewed before sharing. Do not publish runtime databases or expose the collector through a public reverse proxy.

Dashboard CSVs export the displayed record collection with generation time and lookback metadata. Timeline, alerts, and DNS views show up to 500 rows; the health plot/table shows the latest 300 probes while summary metrics cover the whole selected range. History CSV exports all matching observations. Live activity always describes the latest snapshot; adapter comparison shows all interfaces. HTML reports summarize the time range and selected adapter independently of history search.

## System insights

Open **System insights** for CPU utilization by logical processor, memory, reported CPU frequency, and battery state. CPU utilization samples a short 0.1-second interval approximately every two seconds; it is not a full-interval average. Missing readings remain unavailable. Windows frequency may be a nominal rather than instantaneous clock.

**Start recording** stores up to 3,600 system snapshots in memory, stopping automatically at the limit. Stop, scrub, and play snapshots; download an NTO JSON trace to retain it across server restarts. Starting a new recording replaces the previous in-memory session. Imported traces remain in the browser. Replay advances one sample per second, independent of capture timing; timestamps preserve gaps. The NTO trace format is independent and does not import TMOG traces.

The same screen provides on-demand TCP/UDP socket ownership and local binding scope, installed desktop-app inventory sorted by publisher-estimated size, explicit folder scans, and a one-second SHA-256 throughput benchmark. Folder scans stop at 10,000 entries or three seconds, skip links/reparse points, and show partial totals when truncated. Registry inventories can omit portable and Store apps. Local bindings do not prove Internet reachability. The benchmark is a hashing measurement, not a general system score.

This is an independent implementation informed by TMOG's publicly documented feature categories. It is not feature parity: GPU telemetry, watts, thermal sensors, device health, TMOG trace compatibility, and full multi-subsystem benchmarks are not implemented. Recordings contain system metrics only, not process histories or connection snapshots.

## Development checks

```powershell
.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Tests use temporary databases and synthetic records. See [RESEARCH.md](RESEARCH.md) for measurement sources. Released under the [MIT License](LICENSE).
