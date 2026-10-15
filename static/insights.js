"use strict";
const insightState = {samples: [], replay: false, index: 0, timer: null, busy: false, imported: false};
const insightLabel = (key) => key.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase());
function insightValue(value, key = "") {
  if (value != null && typeof value === "number") {
    if (key.endsWith("_bytes") || ["total", "available", "used"].includes(key)) return formatBytes(value);
    if (key.includes("percent")) return value.toFixed(1) + " %";
    if (key === "frequency_mhz") return value.toFixed(0) + " MHz";
    if (key === "ts") return new Date(value * 1000).toLocaleString();
  }
  if (value == null) return "Unavailable";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}
function insightRender(target, data) {
  target.replaceChildren();
  if (Array.isArray(data)) {
    if (!data.length) { target.append(node("p", "No observations.", "insights-note")); return; }
    const rows = data.slice(0, 500);
    if (rows.some(row => !row || typeof row !== "object" || Array.isArray(row))) { target.append(node("p", insightValue(rows))); return; }
    const keys = [...new Set(rows.flatMap(row => Object.keys(row)))].slice(0, 30);
    const wrap = node("div", undefined, "insights-table-wrap"), table = node("table"), head = node("thead"), tr = node("tr");
    keys.forEach(key => tr.append(node("th", insightLabel(key)))); head.append(tr); table.append(head);
    const body = node("tbody"); rows.forEach(row => { const line = node("tr"); keys.forEach(key => line.append(node("td", insightValue(row[key], key)))); body.append(line); }); table.append(body); wrap.append(table); target.append(wrap);
    if (data.length > 500) target.append(node("p", `Showing 500 of ${data.length} rows.`, "insights-note"));
  } else if (data && typeof data === "object") {
    const fields = node("div", undefined, "insights-fields");
    for (const [key, value] of Object.entries(data)) {
      if (Array.isArray(value) || (value && typeof value === "object")) continue;
      const field = node("div", undefined, "insights-field"); field.append(node("small", insightLabel(key)), node("span", insightValue(value, key))); fields.append(field);
    }
    target.append(fields);
    for (const [key,value] of Object.entries(data)) {
      if (!value || typeof value !== "object") continue;
      const section = node("section", undefined, "insights-panel"); section.append(node("h3", insightLabel(key))); const content = node("div"); if (key === "per_core_percent") insightRender(content,value.map((percent, index) => ({core:index+1,percent}))); else insightRender(content,value); section.append(content); target.append(section);
    }
  } else target.append(node("p", insightValue(data)));
}
async function insightApi(route, body) {
  return api("/api/insights/" + route, body === undefined ? undefined : {method:"POST",headers:{"Content-Type":"application/json","X-Ray-i-Token":state.csrf},body:JSON.stringify(body)});
}
function insightPause() { clearInterval(insightState.timer); insightState.timer = null; $("insights-play").textContent = "Play replay"; }
function insightSample(index) {
  if (!insightState.samples.length) return;
  insightState.replay = true; insightState.index = Math.max(0,Math.min(insightState.samples.length-1,index));
  const sample = insightState.samples[insightState.index]; $("insights-scrub").value = insightState.index;
  $("insights-time").textContent = `Replay ${insightState.index+1}/${insightState.samples.length} · ${sample.ts ? new Date(sample.ts*1000).toLocaleString() : "Unknown time"}`;
  insightRender($("insights-snapshot"), sample);
}
async function insightRefresh() {
  if (state.view !== "insights" || insightState.busy) return;
  insightState.busy = true;
  try {
    const rec = await insightApi("recording");
    $("insights-recorder-state").textContent = `${rec.recording ? "Recording" : "Stopped"} · ${rec.samples.length} / ${rec.max_samples} samples${insightState.imported ? " · Imported trace loaded for replay" : ""}`;
    $("insights-record").disabled = rec.recording; $("insights-stop-record").disabled = !rec.recording;
    if (!insightState.imported && !insightState.replay) insightState.samples = rec.samples;
    $("insights-scrub").max = Math.max(0,insightState.samples.length-1);
    if (!insightState.replay) { const snapshot = await insightApi("snapshot"); if (!insightState.replay) { insightRender($("insights-snapshot"),snapshot); $("insights-time").textContent = "Live"; } }
    $("insights-status").textContent = insightState.replay ? "Replay shows the selected recorded snapshot. Other panels are current on-demand observations." : "Live system observations · refreshes every five seconds";
  } catch(error) { $("insights-status").textContent = error.message; }
  finally { insightState.busy = false; }
}
function openInsights() {
  state.view = "insights"; state.revision++;
  document.querySelectorAll(".view").forEach(e=>e.classList.toggle("hidden",e.id!=="insights"));
  document.querySelectorAll(".nav").forEach(e=>e.classList.toggle("active",e.dataset.view==="insights"));
  $("page-title").textContent = "System insights"; $("page-subtitle").textContent = "Understand performance, record observations, and replay changes.";
  $("notice").classList.add("hidden"); document.querySelector(".page-heading .toolbar").classList.add("hidden"); insightRefresh();
}
async function insightAction(button, route, target, body) {
  button.disabled = true;
  try { const data = await insightApi(route,body); if (target) insightRender($(target),data); else { if (route === "record-start" || route === "record-stop") { insightPause(); insightState.replay=false; insightState.imported=false; } await insightRefresh(); } }
  catch(error) { $("insights-status").textContent = error.message; }
  finally { button.disabled = false; }
}
$("insights-live").onclick = () => { insightPause(); insightState.replay=false; insightState.imported=false; insightRefresh(); };
$("insights-record").onclick = function() { insightAction(this,"record-start",null,{}); };
$("insights-stop-record").onclick = function() { insightAction(this,"record-stop",null,{}); };
$("insights-connections").onclick = function() { insightAction(this,"connections","insights-connections-result"); };
$("insights-apps").onclick = function() { insightAction(this,"apps","insights-apps-result"); };
$("insights-disk").onclick = function() { const path = $("insights-path").value.trim(); if (!path) { $("insights-status").textContent="Enter a folder path to scan."; return; } insightAction(this,"disk","insights-disk-result",{path}); };
$("insights-benchmark").onclick = function() { insightAction(this,"benchmark","insights-benchmark-result",{}); };
$("insights-scrub").oninput = function() { insightPause(); insightSample(Number(this.value)); };
$("insights-play").onclick = () => {
  if (insightState.timer) { insightPause(); return; }
  if (!insightState.samples.length) { $("insights-status").textContent="Record or import samples before replaying."; return; }
  insightSample(insightState.index >= insightState.samples.length-1 ? 0 : insightState.index); $("insights-play").textContent="Pause replay";
  insightState.timer=setInterval(()=>{ if (state.view!=="insights" || insightState.index>=insightState.samples.length-1) { insightPause(); return; } insightSample(insightState.index+1); },1000);
};
$("insights-download").onclick = async () => {
  try {
    const samples=insightState.imported ? insightState.samples : (await insightApi("recording")).samples;
    if (!samples.length) throw new Error("No recorded samples to download.");
    const url=URL.createObjectURL(new Blob([JSON.stringify({format:"nto-trace",version:1,samples})],{type:"application/json"})); const a=node("a"); a.href=url; a.download="nto-trace.json"; a.click(); setTimeout(()=>URL.revokeObjectURL(url),1000);
  } catch(error) { $("insights-status").textContent=error.message; }
};
function validateInsightTrace(trace) {
  if (!trace || trace.format!=="nto-trace" || trace.version!==1 || !Array.isArray(trace.samples) || !trace.samples.length || trace.samples.length>3600) throw new Error("Expected an NTO version 1 trace containing 1–3600 samples.");
  let entries=0;
  function check(value,depth) {
    if (++entries>500000 || depth>8) throw new Error("Trace structure exceeds supported limits.");
    if (typeof value==="string" && value.length>8192) throw new Error("Trace contains an oversized field.");
    if (value && typeof value==="object") { if (Object.keys(value).length>10000) throw new Error("Trace collection is too large."); for (const [key,item] of Object.entries(value)) { if (["__proto__","constructor","prototype"].includes(key)) throw new Error("Invalid trace field."); check(item,depth+1); } }
  }
  for (const sample of trace.samples) { if (!sample || Array.isArray(sample) || typeof sample!=="object" || !Number.isFinite(sample.ts) || sample.ts<0 || sample.ts>8640000000000) throw new Error("Each sample must contain a valid timestamp."); check(sample,0); }
  return trace.samples;
}
$("insights-import").onchange = async function() {
  const file=this.files[0]; if (!file) return;
  try { if (file.size>20*1024*1024) throw new Error("Trace must be 20 MB or smaller."); const samples=validateInsightTrace(JSON.parse(await file.text())); insightPause(); insightState.samples=samples; insightState.imported=true; $("insights-scrub").max=samples.length-1; insightSample(0); $("insights-status").textContent=`Imported ${samples.length} samples locally.`; }
  catch(error) { $("insights-status").textContent=error.message; }
  finally { this.value=""; }
};
setInterval(insightRefresh,5000);
