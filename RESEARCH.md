# Measurement sources

Ray-i uses Python psutil for operating-system adapter counters and TCP socket snapshots, SQLite for device-local retention, Windows DNS cache snapshots for observed cache entries, and .NET Ping for opt-in ICMP measurements.

- psutil network APIs: https://psutil.readthedocs.io/en/latest/#network
- Windows DNS cache: https://learn.microsoft.com/powershell/module/dnsclient/get-dnsclientcache
- Ping round-trip time: https://learn.microsoft.com/en-us/dotnet/api/system.net.networkinformation.pingreply.roundtriptime
- Ping status: https://learn.microsoft.com/en-us/dotnet/api/system.net.networkinformation.pingreply.status

Round-trip time is accepted only for a successful reply. Unknown or unavailable values remain unknown. Adapter reset/gap intervals are excluded. Snapshot differences indicate observations rather than proof of connection initiation or termination.

Regression tests cover retention, literal search, escaped HTML and CSV exports, origin/host/CSRF protection, measurement baselines, gaps, spike warmup/cooldown, DNS upserts, probe-error exclusion, and configuration validation.
