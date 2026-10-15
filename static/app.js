"use strict";
const $ = (id) => document.getElementById(id);
const state = {
  view: "overview",
  source: "windows",
  hours: 24,
  adapter: "",
  search: "",
  verdict: "all",
  offset: 0,
  csrf: "",
  chart: [],
  busy: false,
  total: 0,
  request: 0,
  revision: 0,
  queued: false,
  bucket: 5,
};
const number = (value) => Number(value || 0).toLocaleString();
function bytes(value) {
  if (value == null) return ["—", ""];
  const units = ["B", "KB", "MB", "GB", "TB"];
  let n = Math.max(0, Number(value)),
    i = 0;
  while (n >= 1024 && i < 4) {
    n /= 1024;
    i++;
  }
  return [
    n.toLocaleString(undefined, { maximumFractionDigits: i ? 1 : 0 }),
    units[i],
  ];
}
function formatBytes(value) {
  return bytes(value).join(" ");
}
function metric(id, value) {
  const [n, u] = bytes(value);
  $(id).replaceChildren(document.createTextNode(n));
  const small = document.createElement("small");
  small.textContent = u;
  $(id).append(small);
}
function node(tag, text, className) {
  const e = document.createElement(tag);
  if (text !== undefined) e.textContent = text;
  if (className) e.className = className;
  return e;
}
function parameters() {
  return new URLSearchParams({
    source: state.source,
    hours: state.hours,
    adapter: state.adapter,
    search: state.search,
    verdict: state.verdict,
    offset: state.offset,
  });
}
async function api(path, options) {
  const response = await fetch(path, options);
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "Request failed");
  return data;
}
function changeView(view) {
  if (view === "insights") { openInsights(); return; }
  document.querySelector(".page-heading .toolbar").classList.remove("hidden");
  if (view.startsWith("dash-")) {
    openDashboard(view.slice(5));
    return;
  }
  $("notice").classList.remove("hidden");
  $("export-type").classList.remove("hidden");
  $("export").textContent = "↓ Export";
  state.view = view;
  document
    .querySelectorAll(".view")
    .forEach((e) => e.classList.toggle("hidden", e.id !== view));
  document
    .querySelectorAll(".nav")
    .forEach((e) => e.classList.toggle("active", e.dataset.view === view));
  const titles = {
    overview: [
      "A clearer view of your network.",
      "Understand the traffic. Keep the context. Stay in control.",
    ],
    history: [
      "Every connection has a story.",
      "A searchable record, stored on your computer.",
    ],
  };
  $("page-title").textContent = titles[view][0];
  $("page-subtitle").textContent = titles[view][1];
  if (view === "history") loadHistory();
  if (view === "overview") drawChart();
}
document
  .querySelectorAll("[data-view]")
  .forEach((e) =>
    e.addEventListener("click", () => changeView(e.dataset.view)),
  );
function ranks(id, items, key) {
  const container = $(id);
  container.replaceChildren();
  if (!items.length) {
    container.append(
      node("div", "No observations in this time range.", "empty"),
    );
    return;
  }
  const max = items[0].total;
  items.forEach((item) => {
    const row = node("div", undefined, "rank");
    row.append(
      node("div", String(item[key]).slice(0, 2).toUpperCase(), "app-icon"),
    );
    const content = node("div", undefined, "rank-content");
    content.append(node("div", item[key], "rank-name"));
    const bar = node("div", undefined, "bar");
    const fill = node("div", undefined, "bar-fill");
    fill.style.width = (100 * item.total) / max + "%";
    bar.append(fill);
    content.append(bar);
    row.append(content);
    const count = node("div", number(item.total), "rank-number");
    if (item.blocked)
      count.append(node("small", number(item.blocked) + " blocked"));
    row.append(count);
    container.append(row);
  });
}
async function refresh() {
  if (state.busy) {
    state.queued = true;
    return;
  }
  state.busy = true;
  const revision = state.revision;
  try {
    const result = await api("/api/summary?" + parameters());
    if (revision !== state.revision) {
      state.queued = true;
      return;
    }
    state.csrf = result.csrf;
    state.chart = result.chart;
    state.bucket = result.bucket;
    metric("download", result.totals.since ? result.totals.rx : null);
    metric("upload", result.totals.since ? result.totals.tx : null);
    $("connections").textContent = number(result.connections.total);
    $("adapter-count").textContent = number(result.adapters.length);
    $("app-count").textContent =
      number(result.connections.apps) + " apps observed";
    $("rx-rate").textContent = result.current
      ? formatBytes(result.current.rx) + "/s"
      : "—";
    $("tx-rate").textContent = result.current
      ? formatBytes(result.current.tx) + "/s"
      : "—";
    $("health").textContent = result.current
      ? "Adapter collector active"
      : "Waiting for adapter samples";
    const options = result.adapters;
    const names = Array.from($("adapter").options).map((e) => e.value);
    if (JSON.stringify(options) !== JSON.stringify(names)) {
      $("adapter").replaceChildren(
        ...options.map((name) => {
          const o = node("option", name);
          o.value = name;
          return o;
        }),
      );
    }
    state.adapter = result.adapter;
    $("adapter").value = result.adapter;
    $("notice").textContent =
      result.os_error ||
      result.counter_error ||
      "Recording sampled TCP activity on this computer. Records stay on your device for 30 days.";
    $("notice").classList.toggle(
      "warning",
      Boolean(result.os_error || result.counter_error),
    );
    $("updated").textContent = result.os_sync
      ? "Windows sampled " +
        new Date(result.os_sync * 1000).toLocaleTimeString()
      : "Waiting for first sample";
    ranks("apps", result.apps, "app");
    drawChart();
    if (state.view === "history") await loadHistory();
    if (state.view.startsWith("dash-")) await loadDashboard();
  } catch (error) {
    $("notice").textContent =
      "Ray-i is unreachable. Check that its local server is running. " +
      error.message;
    $("notice").classList.add("warning");
    $("health").textContent = "Collector unavailable";
  } finally {
    state.busy = false;
    if (state.queued) {
      state.queued = false;
      refresh();
    }
  }
}
async function loadHistory() {
  const request = ++state.request;
  const revision = state.revision;
  try {
    const result = await api("/api/connections?" + parameters());
    if (request !== state.request || revision !== state.revision) return;
    state.total = result.total;
    $("result-count").textContent = number(result.total) + " observations";
    $("rows").replaceChildren();
    result.rows.forEach((row) => {
      const tr = node("tr");
      const identity = node("td");
      identity.append(
        node("strong", row.profile_name || row.profile || "Unknown app"),
        node("small", row.domain || row.remote_ip || "Unknown destination"),
      );
      tr.append(
        identity,
        node("td", row.remote_port),
        node("td", row.tcp_status || "Unknown"),
        node("td", new Date(row.last_observed * 1000).toLocaleString()),
      );
      $("rows").append(tr);
    });
    if (!result.rows.length) {
      const tr = node("tr");
      const td = node(
        "td",
        state.search
          ? "No observations match these filters."
          : "Waiting for TCP snapshots.",
        "empty",
      );
      td.colSpan = 4;
      tr.append(td);
      $("rows").append(tr);
    }
    $("page-info").textContent = result.total
      ? `${number(state.offset + 1)}–${number(Math.min(state.offset + 100, result.total))} of ${number(result.total)}`
      : "No observations yet";
    $("previous").disabled = state.offset === 0;
    $("next").disabled = state.offset + 100 >= result.total;
  } catch (error) {
    $("page-info").textContent = error.message;
  }
}
function drawChart() {
  if (state.view !== "overview") return;
  const canvas = $("chart"),
    r = canvas.getBoundingClientRect();
  if (!r.width) return;
  const scale = window.devicePixelRatio || 1;
  canvas.width = r.width * scale;
  canvas.height = r.height * scale;
  const ctx = canvas.getContext("2d");
  ctx.scale(scale, scale);
  const w = r.width,
    h = r.height,
    left = 60,
    bottom = h - 15,
    top = 15;
  const data = state.chart;
  $("chart-empty").classList.toggle("hidden", data.length > 1);
  const max = Math.max(1024, ...data.map((x) => Math.max(x.rx, x.tx))) * 1.15;
  ctx.font = "9px Segoe UI";
  for (let i = 0; i < 4; i++) {
    const y = top + ((bottom - top) * i) / 3;
    ctx.strokeStyle = "#24343d";
    ctx.setLineDash([3, 5]);
    ctx.beginPath();
    ctx.moveTo(left, y);
    ctx.lineTo(w, y);
    ctx.stroke();
    ctx.fillStyle = "#67818d";
    ctx.fillText(formatBytes(max * (1 - i / 3)) + "/s", 0, y + 3);
  }
  ctx.setLineDash([]);
  if (data.length < 2) return;
  const start = data[0].ts,
    end = data[data.length - 1].ts;
  const x = (v) => left + ((w - left - 4) * (v - start)) / (end - start || 1);
  const y = (v) => bottom - ((bottom - top) * v) / max;
  const segments = [];
  let segment = [];
  for (const point of data) {
    if (
      segment.length &&
      point.ts - segment[segment.length - 1].ts > state.bucket * 2
    ) {
      segments.push(segment);
      segment = [];
    }
    segment.push(point);
  }
  if (segment.length) segments.push(segment);
  for (const [key, color] of [
    ["rx", "#76dfc5"],
    ["tx", "#7dafff"],
  ]) {
    for (const group of segments) {
      if (group.length < 2) continue;
      ctx.beginPath();
      ctx.moveTo(x(group[0].ts), bottom);
      for (const point of group) ctx.lineTo(x(point.ts), y(point[key]));
      ctx.lineTo(x(group[group.length - 1].ts), bottom);
      ctx.closePath();
      const gradient = ctx.createLinearGradient(0, top, 0, bottom);
      gradient.addColorStop(0, color + "35");
      gradient.addColorStop(1, color + "00");
      ctx.fillStyle = gradient;
      ctx.fill();
      ctx.beginPath();
      group.forEach((point, i) => {
        if (i === 0) ctx.moveTo(x(point.ts), y(point[key]));
        else ctx.lineTo(x(point.ts), y(point[key]));
      });
      ctx.strokeStyle = color;
      ctx.lineWidth = 1.8;
      ctx.stroke();
    }
  }
  $("chart-start").textContent = new Date(start * 1000).toLocaleString();
  $("chart-end").textContent = new Date(end * 1000).toLocaleTimeString();
}
$("range").addEventListener("change", () => {
  state.hours = Number($("range").value);
  state.revision++;
  state.offset = 0;
  refresh();
});
$("adapter").addEventListener("change", () => {
  state.adapter = $("adapter").value;
  state.revision++;
  refresh();
});
let debounce;
$("search").addEventListener("input", () => {
  clearTimeout(debounce);
  debounce = setTimeout(() => {
    state.search = $("search").value;
    state.offset = 0;
    loadHistory();
  }, 250);
});
$("previous").addEventListener("click", () => {
  state.offset = Math.max(0, state.offset - 100);
  loadHistory();
});
$("next").addEventListener("click", () => {
  state.offset += 100;
  loadHistory();
});
$("export").addEventListener("click", () => {
  if (state.view.startsWith("dash-")) {
    exportDashboard();
    return;
  }
  const route = {
    connections: "/api/export",
    bandwidth: "/api/bandwidth.csv",
    report: "/api/report",
  }[$("export-type").value];
  location.href = route + "?" + parameters();
});
window.addEventListener("resize", drawChart);
refresh();
const pollTimer = setInterval(refresh, 5000);
$("stop").addEventListener("click", async () => {
  try {
    const result = await api("/api/stop", {
      method: "POST",
      headers: { "X-Ray-i-Token": state.csrf },
    });
    clearInterval(pollTimer);
    $("notice").textContent =
      result.message +
      " Run Start Ray-i Network Traffic Observer.cmd to resume.";
    $("health").textContent = "Collector stopped";
    $("stop").disabled = true;
  } catch (error) {
    $("notice").textContent = error.message;
  }
});
