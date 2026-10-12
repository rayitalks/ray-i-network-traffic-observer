"use strict";
const dashboards = {
  live: [
    "Live app activity",
    "Current sampled connections, grouped by application.",
  ],
  timeline: [
    "Connection timeline",
    "What appeared, changed, or stopped being observed.",
  ],
  health: [
    "Network health",
    "Round-trip measurements to your chosen destination.",
  ],
  spikes: [
    "Traffic spikes",
    "Adapter traffic compared with its recent baseline.",
  ],
  destinations: [
    "New destination alerts",
    "First-seen destinations after a local learning baseline.",
  ],
  adapters: [
    "Adapter comparison",
    "Compare interfaces without double-counting their traffic.",
  ],
  dns: [
    "DNS activity",
    "Inspect DNS cache observations collected on this device.",
  ],
};
let dashboardKey = "live",
  dashboardQuery = "",
  dashboardRequest = 0,
  dashboardData = null;
const osViews = new Set(["health", "spikes", "adapters"]);
const when = (ts) =>
  ts ? new Date(ts * 1000).toLocaleString() : "Not observed";
const fmtMs = (n) => (n == null ? "—" : Number(n).toFixed(1) + " ms");
const eventName = (name) =>
  ({
    baseline: "Baseline observation",
    appeared: "Appeared",
    no_longer_observed: "No longer observed",
    state_changed: "TCP state changed",
    collection_gap: "Collection gap",
    new_destination: "New destination",
    firewall_decision: "Decision observed",
    traffic_spike: "Traffic spike",
  })[name] || name;

function openDashboard(key) {
  dashboardKey = key;
  dashboardRequest++;
  dashboardQuery = "";
  $("dashboard-search").value = "";
  state.view = "dash-" + key;
  state.revision++;
  document
    .querySelectorAll(".view")
    .forEach((e) => e.classList.toggle("hidden", e.id !== "dashboard"));
  document
    .querySelectorAll(".nav")
    .forEach((e) =>
      e.classList.toggle("active", e.dataset.view === state.view),
    );
  $("page-title").textContent = dashboards[key][0];
  $("page-subtitle").textContent = dashboards[key][1];
  $("notice").classList.add("hidden");
  $("export-type").classList.add("hidden");
  $("export").textContent = "↓ Export view CSV";
  $("dashboard-search").classList.toggle("hidden", osViews.has(key));
  $("dashboard-settings").replaceChildren();
  $("dashboard-settings").classList.add("hidden");
  $("dashboard-metrics").replaceChildren();
  $("dashboard-visual").replaceChildren();
  $("dashboard-records").replaceChildren();
  $("dashboard-status").textContent = "Loading observations…";
  loadDashboard();
}
function dashboardParameters() {
  const p = parameters();
  p.set("search", dashboardQuery);
  p.set("view", dashboardKey);
  if (osViews.has(dashboardKey)) p.set("source", "windows");
  return p;
}
function exportDashboard() {
  location.href = "/api/dashboard.csv?" + dashboardParameters();
}
function cards(items) {
  $("dashboard-metrics").replaceChildren(
    ...items.map(([label, value, note]) => {
      const e = node("article", undefined, "metric");
      e.append(
        node("div", label.toUpperCase(), "metric-label"),
        node("div", String(value), "metric-value"),
        node("div", note || "", "metric-note"),
      );
      return e;
    }),
  );
}
function heading(parent, title, subtitle) {
  const head = node("div", undefined, "panel-heading");
  const copy = node("div");
  copy.append(node("h2", title));
  if (subtitle) copy.append(node("p", subtitle));
  head.append(copy);
  parent.append(head);
}
function table(
  title,
  columns,
  rows,
  empty = "No matching observations in this range.",
) {
  const panel = $("dashboard-records");
  panel.replaceChildren();
  heading(
    panel,
    title,
    `${number(rows.length)} rows shown · use search to narrow records`,
  );
  if (!rows.length) {
    panel.append(node("div", empty, "empty"));
    return;
  }
  const wrap = node("div", undefined, "table-wrap"),
    t = node("table"),
    head = node("thead"),
    hr = node("tr");
  columns.forEach((c) => hr.append(node("th", c[0])));
  head.append(hr);
  t.append(head);
  const body = node("tbody");
  rows.forEach((row) => {
    const tr = node("tr");
    columns.forEach((c) => {
      const td = node("td");
      const value = c[1](row);
      if (value instanceof Node) td.append(value);
      else td.textContent = value == null ? "—" : String(value);
      tr.append(td);
    });
    body.append(tr);
  });
  t.append(body);
  wrap.append(t);
  panel.append(wrap);
}
function acknowledge(row) {
  const b = node(
    "button",
    row.acknowledged ? "Reviewed" : "Mark reviewed",
    "button small",
  );
  b.disabled = Boolean(row.acknowledged);
  b.addEventListener("click", async () => {
    b.disabled = true;
    try {
      await api("/api/acknowledge", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Ray-i-Token": state.csrf,
        },
        body: JSON.stringify({ id: row.id }),
      });
      loadDashboard();
    } catch (e) {
      b.disabled = false;
      $("dashboard-status").textContent = e.message;
    }
  });
  return b;
}
function historyLink(name) {
  const b = node("button", name, "inline-link");
  b.addEventListener("click", () => {
    state.search = name;
    state.offset = 0;
    $("search").value = name;
    changeView("history");
  });
  return b;
}
function bars(title, rows, valueLabel = "connections") {
  const panel = $("dashboard-visual");
  panel.replaceChildren();
  heading(
    panel,
    title,
    `Largest ${Math.min(12, rows.length)} groups · ${valueLabel}`,
  );
  if (!rows.length) {
    panel.append(node("div", "No measured values to plot.", "empty"));
    return;
  }
  const max = Math.max(1, ...rows.map((r) => r.value));
  const list = node("div", undefined, "dashboard-bars");
  rows.slice(0, 12).forEach((r) => {
    const row = node("div", undefined, "dashboard-bar-row");
    const label = node("span", r.label, "dashboard-bar-label");
    label.title = r.label;
    const track = node("div", undefined, "dashboard-bar-track"),
      fill = node("div", undefined, "dashboard-bar-fill");
    fill.style.width = (100 * r.value) / max + "%";
    track.append(fill);
    row.append(
      label,
      track,
      node("span", r.text || number(r.value), "dashboard-bar-value"),
    );
    list.append(row);
  });
  panel.append(list);
}
function plot(title, points, format, description) {
  const panel = $("dashboard-visual");
  panel.replaceChildren();
  heading(panel, title, description);
  if (!points.length) {
    panel.append(node("div", "Waiting for measured samples.", "empty"));
    return;
  }
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", "0 0 900 220");
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", title);
  svg.classList.add("dashboard-chart");
  function shape(tag, attributes, text) {
    const e = document.createElementNS(ns, tag);
    Object.entries(attributes).forEach(([k, v]) => e.setAttribute(k, v));
    if (text) e.textContent = text;
    svg.append(e);
    return e;
  }
  const min = points[0].ts,
    max = points[points.length - 1].ts;
  const peak =
    Math.max(1, ...points.filter((p) => p.value != null).map((p) => p.value)) *
    1.1;
  const x = (t) => 70 + (810 * (t - min)) / (max - min || 1),
    y = (v) => 180 - (150 * v) / peak;
  for (let i = 0; i < 4; i++) {
    const v = (peak * i) / 3;
    shape("line", { x1: 70, y1: y(v), x2: 880, y2: y(v), stroke: "#273943" });
    shape(
      "text",
      { x: 4, y: y(v) + 4, fill: "#91a7b1", "font-size": 11 },
      format(v),
    );
  }
  let previous = null;
  points.forEach((p) => {
    if (p.value == null) {
      shape("circle", { cx: x(p.ts), cy: 187, r: 3, fill: "#e7ac72" });
      previous = null;
      return;
    }
    if (previous && p.ts - previous.ts <= 30)
      shape("line", {
        x1: x(previous.ts),
        y1: y(previous.value),
        x2: x(p.ts),
        y2: y(p.value),
        stroke: "#76dfc5",
        "stroke-width": 2,
      });
    shape("circle", { cx: x(p.ts), cy: y(p.value), r: 2, fill: "#76dfc5" });
    previous = p;
  });
  shape(
    "text",
    { x: 70, y: 210, fill: "#91a7b1", "font-size": 11 },
    new Date(min * 1000).toLocaleTimeString(),
  );
  shape(
    "text",
    { x: 880, y: 210, fill: "#91a7b1", "font-size": 11, "text-anchor": "end" },
    new Date(max * 1000).toLocaleTimeString(),
  );
  panel.append(svg);
}
function collectionNote(d) {
  return d.fresh
    ? `Latest TCP snapshot: ${when(d.last_sample)}.`
    : `No fresh snapshot. Last sample: ${when(d.last_sample)}.`;
}
function controls(d) {
  const panel = $("dashboard-settings");
  if (!["health", "spikes"].includes(dashboardKey)) return;
  if (panel.childElementCount) {
    if (dashboardKey === "health") {
      panel.querySelector("[type=submit]").textContent = d.config.probe_enabled
        ? "Apply target"
        : "Start probes";
    }
    return;
  }
  panel.classList.remove("hidden");
  const form = node("form", undefined, "monitor-form");
  function input(label, value, type = "text") {
    const l = node("label", label);
    const i = node("input");
    i.type = type;
    i.value = value;
    l.append(i);
    form.append(l);
    return i;
  }
  if (dashboardKey === "health") {
    const target = input(
      "Probe destination (IP address)",
      d.config.probe_target,
    );
    const enable = node(
      "button",
      d.config.probe_enabled ? "Apply target" : "Start probes",
      "button primary",
    );
    enable.type = "submit";
    const stop = node("button", "Stop probes", "button");
    stop.type = "button";
    stop.addEventListener("click", () => save({ probe_enabled: false }));
    form.append(enable, stop);
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      save({ probe_target: target.value.trim(), probe_enabled: true });
    });
  } else {
    const adapterLabel = node("label", "Adapter");
    const adapterSelect = $("adapter").cloneNode(true);
    adapterSelect.id = "spike-adapter";
    adapterSelect.value = state.adapter || $("adapter").value;
    adapterSelect.addEventListener("change", () => {
      state.adapter = adapterSelect.value;
      $("adapter").value = state.adapter;
      state.revision++;
      loadDashboard();
    });
    adapterLabel.append(adapterSelect);
    form.append(adapterLabel);
    const factor = input("Times baseline", d.config.spike_factor, "number");
    factor.min = 2;
    factor.max = 20;
    factor.step = 0.5;
    const floor = input(
      "Minimum traffic (MiB/s)",
      d.config.spike_min_bps / 1048576,
      "number",
    );
    floor.min = 0.0625;
    floor.max = 1024;
    floor.step = 0.0625;
    const apply = node("button", "Apply thresholds", "button primary");
    apply.type = "submit";
    form.append(apply);
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      save({
        spike_factor: Number(factor.value),
        spike_min_bps: Number(floor.value) * 1048576,
      });
    });
  }
  const feedback = node("span", "", "control-feedback");
  feedback.setAttribute("role", "status");
  form.append(feedback);
  panel.append(form);
  async function save(body) {
    try {
      await api("/api/monitoring", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Ray-i-Token": state.csrf,
        },
        body: JSON.stringify(body),
      });
      feedback.textContent = "Saved locally.";
      await loadDashboard();
    } catch (e) {
      feedback.textContent = e.message;
    }
  }
}
async function loadDashboard() {
  const request = ++dashboardRequest,
    key = dashboardKey,
    revision = state.revision;
  try {
    const d = await api("/api/dashboard?" + dashboardParameters());
    if (
      request !== dashboardRequest ||
      revision !== state.revision ||
      state.view !== "dash-" + key
    )
      return;
    dashboardData = d;
    controls(d);
    $("dashboard-scope").textContent =
      `Last ${state.hours} hours · Windows observations`;
    const status = $("dashboard-status");
    status.classList.remove("warning");
    status.textContent = collectionNote(d);
    const method = $("dashboard-method");
    if (key === "live") {
      cards([
        [
          "Active sampled sockets",
          d.fresh ? number(d.live_connections) : "—",
          "Latest snapshot, not a lifetime total",
        ],
        [
          "Apps",
          d.fresh ? number(d.live_apps.length) : "—",
          "Grouped by reported application name",
        ],
        [
          "Sample age",
          d.last_sample ? Math.round(d.generated - d.last_sample) + "s" : "—",
          "Collection every ~5 seconds",
        ],
      ]);
      bars(
        "Apps with active connections",
        d.live_apps.map((r) => ({ label: r.app, value: r.connections })),
      );
      table(
        "Inspect applications",
        [
          ["Application", (r) => historyLink(r.app)],
          ["Sampled connections", (r) => r.connections],
          ["Distinct destinations", (r) => r.destinations],
          [
            "Observed states",
            (r) =>
              Object.entries(r.states)
                .map(([s, n]) => `${s}: ${n}`)
                .join(" · "),
          ],
        ],
        d.live_apps,
      );
      method.textContent =
        "TCP TIME_WAIT/closed sockets are excluded from active counts. Process attribution may be unknown. App names can group multiple processes. Stale snapshots are explicitly marked.";
    } else if (key === "timeline") {
      const kinds = {};
      d.events.forEach((r) => (kinds[r.kind] = (kinds[r.kind] || 0) + 1));
      cards([
        [
          "Events shown",
          number(d.events.length),
          d.events_truncated
            ? "Latest 500; narrow time or search"
            : "Within selected range",
        ],
        ["Appeared", number(kinds.appeared), "Between successful snapshots"],
        [
          "No longer observed",
          number(kinds.no_longer_observed),
          "Not a confirmed disconnect",
        ],
        [
          "Collection gaps",
          number(kinds.collection_gap),
          "Gaps are kept separate",
        ],
      ]);
      bars(
        "Observed event types",
        Object.entries(kinds)
          .map(([label, value]) => ({ label: eventName(label), value }))
          .sort((a, b) => b.value - a.value),
        "events in displayed records",
      );
      table(
        "Connection events",
        [
          ["Observed", (r) => when(r.ts)],
          ["Event", (r) => eventName(r.kind)],
          ["Application", (r) => r.app || "—"],
          ["Destination", (r) => r.destination || "—"],
          [
            "Detail",
            (r) =>
              r.detail.status ||
              (r.detail.seconds &&
                Math.round(r.detail.seconds) + " second gap") ||
              "Snapshot transition",
          ],
        ],
        d.events,
      );
      method.textContent =
        "Events begin with this version. First samples establish a baseline. Restart, long gaps, or partial scans never establish disconnections; transitions are only inferred between successful snapshots.";
    } else if (key === "health") {
      const s = d.probe_stats,
        last = d.probes.at(-1);
      status.textContent = `Probes ${d.config.probe_enabled ? "enabled" : "stopped"} · ${d.config.probe_target} · approximately every 10 seconds · last sample ${when(last?.ts)}.`;
      cards([
        [
          "Latest RTT",
          fmtMs(last?.status === "Success" ? last.ms : null),
          last?.status || "No samples",
        ],
        [
          "Unanswered probes",
          s.loss_percent == null ? "—" : s.loss_percent.toFixed(1) + "%",
          `${number((s.attempts || 0) - (s.errors || 0))} valid attempts in range`,
        ],
        ["Mean RTT", fmtMs(s.mean_ms), "Successful probes only"],
        [
          "Collector errors",
          number(s.errors),
          "Excluded from loss calculation",
        ],
      ]);
      plot(
        "Probe round-trip time",
        d.probes.map((r) => ({ ts: r.ts, value: r.ms })),
        (v) => Math.round(v) + " ms",
        "Latest 300 probes · orange dots denote failed or unavailable samples",
      );
      table(
        "Probe results",
        [
          ["Time", (r) => when(r.ts)],
          ["Destination", (r) => r.target],
          ["Result", (r) => r.status],
          ["Round-trip", (r) => fmtMs(r.ms)],
        ],
        [...d.probes].reverse(),
        "Start probes to measure a destination.",
      );
      method.textContent =
        "One ICMP echo attempt per cycle, 1.2 second timeout. Non-success replies count as unanswered probes; collector errors do not. ICMP may be filtered or deprioritized. Failure does not establish a whole-network outage. No measurements are invented for gaps.";
    } else if (key === "spikes") {
      status.textContent = `A spike requires at least 12 prior samples and traffic ≥ ${d.config.spike_factor}× the preceding median, with a ${formatBytes(d.config.spike_min_bps)}/s floor. One alert per adapter per minute.`;
      cards([
        [
          "Spikes shown",
          number(d.spikes.length),
          d.spikes_truncated ? "Latest 500" : "Selected adapter and range",
        ],
        [
          "Threshold",
          d.config.spike_factor + "×",
          "Up to 60 preceding samples",
        ],
        [
          "Minimum rate",
          formatBytes(d.config.spike_min_bps) + "/s",
          "Receive + send on one interface",
        ],
      ]);
      bars(
        "Largest traffic spikes",
        d.spikes
          .map((r) => ({
            label:
              r.destination +
              " · " +
              new Date(r.ts * 1000).toLocaleTimeString(),
            value: r.detail.rate,
            text: formatBytes(r.detail.rate) + "/s",
          }))
          .sort((a, b) => b.value - a.value),
        "bytes per second",
      );
      table(
        "Spike observations",
        [
          ["Time", (r) => when(r.ts)],
          ["Adapter", (r) => r.destination],
          [
            "Rate / baseline",
            (r) =>
              formatBytes(r.detail.rate) +
              "/s / " +
              formatBytes(r.detail.baseline) +
              "/s",
          ],
          [
            "Apps active nearby",
            (r) => (r.detail.active_apps || []).join(", ") || "Unavailable",
          ],
          ["Review", acknowledge],
        ],
        d.spikes,
        "No spikes detected under the current rule. A baseline takes about one minute.",
      );
      method.textContent =
        "These are threshold-based alerts. Nearby app activity is correlation, not per-app byte attribution. Baselines reset across collection gaps; adapters may measure overlapping traffic.";
    } else if (key === "destinations") {
      cards([
        [
          "New destinations shown",
          number(d.alerts.length),
          d.alerts_truncated
            ? "Latest 500 alerts"
            : "After the initial baseline",
        ],
        [
          "Awaiting review",
          number(d.alerts.filter((r) => !r.acknowledged).length),
          "Within displayed alerts",
        ],
        [
          "Known app/destination pairs",
          number(d.known_destinations),
          "Baseline retained for 30 days",
        ],
      ]);
      const counts = {};
      d.alerts.forEach((r) => (counts[r.app] = (counts[r.app] || 0) + 1));
      bars(
        "Apps contacting new destinations",
        Object.entries(counts)
          .map(([label, value]) => ({ label, value }))
          .sort((a, b) => b.value - a.value),
        "first-seen alerts shown",
      );
      table(
        "Destination review",
        [
          ["First detected", (r) => when(r.ts)],
          ["Application", (r) => historyLink(r.app)],
          ["Destination", (r) => r.destination],
          ["Review", acknowledge],
        ],
        d.alerts,
        "The first successful snapshot is a learning baseline. Later new destinations appear here.",
      );
      method.textContent =
        "New means unseen for this application in the retained local baseline, not unsafe. Unknown Windows processes are excluded. Destinations are identified by IP address. Restarts or long collection gaps establish a fresh comparison snapshot without raising a first-scan alert storm.";
    } else if (key === "adapters") {
      status.textContent =
        "Each interface is measured independently. Do not add physical and virtual adapters together: the same traffic may cross both.";
      cards([
        ["Adapters", number(d.adapters.length), "Observed in this range"],
        [
          "Fresh interfaces",
          number(d.adapters.filter((r) => r.rx_rate != null).length),
          "Most recent sample under 20 seconds",
        ],
      ]);
      bars(
        "Observed volume by interface",
        d.adapters
          .map((r) => ({
            label: r.adapter,
            value: r.rx + r.tx,
            text: formatBytes(r.rx + r.tx),
          }))
          .sort((a, b) => b.value - a.value),
        "receive + send bytes",
      );
      table(
        "Interface measurements",
        [
          ["Adapter", (r) => r.adapter],
          ["Downloaded", (r) => formatBytes(r.rx)],
          ["Uploaded", (r) => formatBytes(r.tx)],
          [
            "Down now",
            (r) =>
              r.rx_rate == null ? "Stale" : formatBytes(r.rx_rate) + "/s",
          ],
          [
            "Up now",
            (r) =>
              r.tx_rate == null ? "Stale" : formatBytes(r.tx_rate) + "/s",
          ],
          ["Last sample", (r) => when(r.last)],
        ],
        d.adapters,
      );
      method.textContent =
        "Totals are sums of measured deltas while the collector runs. Counter resets, missing intervals, and sleep gaps are excluded. Loopback interfaces are excluded by the adapter collector.";
    } else if (key === "dns") {
      status.textContent =
        d.dns_error ||
        `DNS cache last sampled ${when(d.dns_last)}. Cache observations are not a query log.`;
      cards([
        [
          "Records shown",
          number(d.dns.length),
          d.dns_truncated
            ? "Newest 500 matching cache records"
            : "Selected range",
        ],
        ["Source", "Windows cache", "No requesting-app attribution"],
      ]);
      const types = {};
      d.dns.forEach((r) => {
        const t = dnsType(r.type);
        types[t] = (types[t] || 0) + 1;
      });
      bars(
        "DNS record types",
        Object.entries(types)
          .map(([label, value]) => ({ label, value }))
          .sort((a, b) => b.value - a.value),
        "displayed records",
      );
      table(
        "DNS cache observations",
        [
          ["Name", (r) => r.name],
          ["Type", (r) => dnsType(r.type)],
          ["Answer", (r) => r.data || "—"],
          [
            "Cache status",
            (r) => (r.status === 0 ? "Success" : String(r.status)),
          ],
          ["TTL at sample", (r) => r.ttl + " s"],
          [
            "First / last seen",
            (r) => when(r.first_seen) + " / " + when(r.last_seen),
          ],
        ],
        d.dns,
      );
      method.textContent =
        "Read-only DNS cache snapshots every 30 seconds. Entries may outlive requests or originate from the hosts file. TTL is captured at sample time. Request counts, requesting apps, and resolution failure rates cannot be inferred from the cache.";
    }
  } catch (error) {
    if (request === dashboardRequest) {
      $("dashboard-status").textContent =
        "Dashboard unavailable: " + error.message;
      $("dashboard-status").classList.add("warning");
    }
  }
}
function dnsType(value) {
  return (
    {
      1: "A",
      2: "NS",
      5: "CNAME",
      6: "SOA",
      12: "PTR",
      15: "MX",
      16: "TXT",
      28: "AAAA",
      33: "SRV",
    }[value] || String(value)
  );
}
let dashboardDebounce;
$("dashboard-search").addEventListener("input", () => {
  clearTimeout(dashboardDebounce);
  dashboardDebounce = setTimeout(() => {
    dashboardQuery = $("dashboard-search").value;
    loadDashboard();
  }, 250);
});
