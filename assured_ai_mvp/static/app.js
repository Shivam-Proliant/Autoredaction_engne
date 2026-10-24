const $ = (selector) => document.querySelector(selector);
const state = { scan: null, terms: [], detectors: [], tier: "algorithmic", toastTimer: null };
const examples = {
  incident: "Hi, I was double-charged on my electricity bill. My account is under the name Marcus Albright. Email: marcus.albright@example.com. Mobile: +44 7700 900123. API key: sk-proj-89fH2kL9pQ3mN7vX1zR4. Server IP: 192.168.1.200.",
  credit: "Review the mortgage application for Priya Patel (single mother, age 32), living at BS16 1QY. Her national insurance number is QQ 12 34 56 C and her phone is +44 7700 900123.",
  resume: "Resume for Alexnder Cockbrn: graduated from OxfordUniversity and worked at BristolBusinessPark. Please share the report with Synoptx and protect the project LookoutEdg."
};

async function api(path, options = {}) {
  const response = await fetch(path, { headers: { "Content-Type": "application/json" }, ...options });
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error || `Request failed (${response.status})`);
  return payload;
}

function showToast(message) {
  const toast = $("#toast"); toast.textContent = message; toast.classList.add("show");
  clearTimeout(state.toastTimer); state.toastTimer = setTimeout(() => toast.classList.remove("show"), 2300);
}

function escapeText(value) { return String(value).replace(/[&<>"']/g, char => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]); }

function renderHighlight(scan, original) {
  const container = $("#highlighted-text"); container.replaceChildren();
  const highlights = [...(scan.highlights || [])].sort((a, b) => a.start - b.start);
  let cursor = 0;
  for (const match of highlights) {
    if (match.start < cursor) continue;
    container.append(document.createTextNode(original.slice(cursor, match.start)));
    const mark = document.createElement("mark");
    mark.className = `highlight${match.review_required ? " review" : ""}`;
    mark.title = `${match.entity_type} → ${match.placeholder}${match.review_required ? " · Review suggested" : ""}`;
    mark.textContent = original.slice(match.start, match.end);
    container.append(mark); cursor = match.end;
  }
  container.append(document.createTextNode(original.slice(cursor)));
}

function renderScan(scan, originalText, historical = false) {
  state.scan = scan;
  $("#results-section").hidden = false;
  if (historical) {
    $("#highlighted-text").textContent = "Original input is not retained. The saved redacted output is shown on the right.";
  } else {
    renderHighlight(scan, originalText);
  }
  $("#redacted-output").textContent = scan.redacted_text;
  const tierLabel = scan.tier === "local_llm" ? "Tier 2 · Local Qwen" : scan.tier === "hybrid" ? "Tier 3 · Hybrid" : "Tier 1 · Algorithmic";
  const modelStat = scan.model_name ? `<span class="stat-pill">${escapeText(scan.model_name)} · CPU</span>` : "";
  $("#scan-stats").innerHTML = `<span class="stat-pill">${tierLabel}</span><span class="stat-pill"><strong>${scan.match_count}</strong> redactions</span><span class="stat-pill"><strong>${scan.review_count}</strong> review flags</span><span class="stat-pill"><strong>${Number(scan.processing_ms).toFixed(2)} ms</strong></span>${modelStat}`;
  $("#review-alert").hidden = !scan.review_count;
  $("#scan-time").textContent = new Date(`${scan.created_at.replace(" ", "T")}Z`).toLocaleString();
  $("#reveal-values").checked = false;
  renderMappings(scan.mappings || []);
  $("#results-section").scrollIntoView({ behavior: "smooth", block: "start" });
}

function renderMappings(mappings) {
  const body = $("#mapping-rows"); body.replaceChildren();
  $("#table-empty").hidden = mappings.length !== 0;
  for (const item of mappings) {
    const row = document.createElement("tr");
    const sensitivity = item.sensitivity.toLowerCase();
    const cells = [
      `<span class="placeholder">${escapeText(item.placeholder)}</span>`,
      `<span class="${item.raw_value === "[REDACTED]" ? "value-masked" : ""}">${escapeText(item.raw_value)}</span>`,
      `<span class="type-label">${escapeText(item.entity_type)}</span>${item.review_required ? '<span class="review-tag">Review</span>' : ""}`,
      `<span class="method-label">${escapeText(item.match_method)}</span>`,
      `<span class="sensitivity ${escapeText(sensitivity)}">${escapeText(item.sensitivity.replaceAll("_", " "))}</span>`
    ];
    for (const html of cells) { const cell = document.createElement("td"); cell.innerHTML = html; row.append(cell); }
    body.append(row);
  }
}

function renderDetectors() {
  const grid = $("#detector-grid"); grid.replaceChildren();
  for (const detector of state.detectors) {
    const label = document.createElement("label"); label.className = "detector-switch";
    const copy = document.createElement("span"); copy.className = "detector-copy";
    const title = document.createElement("b"); title.textContent = detector.label;
    const key = document.createElement("small"); key.textContent = detector.key.replaceAll("_", " ");
    copy.append(title, key);
    const input = document.createElement("input"); input.type = "checkbox"; input.checked = detector.enabled; input.setAttribute("aria-label", `${detector.label} detector`);
    const track = document.createElement("span"); track.className = "switch-track"; const knob = document.createElement("i"); track.append(knob);
    input.addEventListener("change", async () => {
      input.disabled = true;
      try {
        await api("/api/detectors", { method: "PUT", body: JSON.stringify({ detectors: { [detector.key]: input.checked } }) });
        detector.enabled = input.checked; updateToggleAllLabel(); showToast(`${detector.label} ${input.checked ? "enabled" : "disabled"}`);
      } catch (error) { input.checked = !input.checked; showToast(error.message); }
      finally { input.disabled = false; }
    });
    label.append(copy, input, track); grid.append(label);
  }
  updateToggleAllLabel();
}

function updateToggleAllLabel() {
  const allEnabled = state.detectors.every(item => item.enabled);
  $("#toggle-all").textContent = allEnabled ? "Turn all off" : "Turn all on";
}

async function loadDetectors() {
  const { detectors } = await api("/api/detectors"); state.detectors = detectors; renderDetectors();
}

function selectTier(tier) {
  state.tier = tier;
  document.querySelectorAll("[data-tier]").forEach(button => {
    const selected = button.dataset.tier === tier;
    button.classList.toggle("tier-active", selected);
    button.setAttribute("aria-pressed", String(selected));
  });
}

async function loadRuntime() {
  try {
    const runtime = await api("/api/runtime");
    const llmButton = $("#tier-local-llm"), hybridButton = $("#tier-hybrid");
    const available = Boolean(runtime.desktop_app && runtime.local_model.available);
    llmButton.disabled = !available; hybridButton.disabled = !available;
    if (available) {
      llmButton.querySelector(".tier-label").textContent = "TIER 2 · LOCAL QWEN READY";
      llmButton.querySelector("small").textContent = "Qwen 0.5B · up to 12k chars · CPU · offline";
      hybridButton.querySelector(".tier-label").textContent = "TIER 3 · LOCAL HYBRID READY";
      hybridButton.querySelector("small").textContent = "Detectors plus Qwen · CPU · offline";
      $("#tier-description").textContent = "Qwen2.5-0.5B-Instruct was found on this laptop. Local tiers run offline in this desktop app; model detections are marked for review.";
      $("#processing-mode").textContent = "Local Qwen available · CPU · offline · desktop only";
    } else {
      const message = runtime.desktop_app ? runtime.local_model.message : "Available only in the standalone desktop app.";
      llmButton.querySelector("small").textContent = message;
      hybridButton.querySelector("small").textContent = message;
    }
  } catch { /* Older browser-only servers keep the model tiers unavailable. */ }
}

async function loadTerms() {
  const { terms } = await api("/api/terms"); state.terms = terms;
  $("#term-count").textContent = `${terms.length} term${terms.length === 1 ? "" : "s"}`;
  const list = $("#terms-list"); list.replaceChildren();
  for (const term of terms) {
    const chip = document.createElement("span"); chip.className = "term-chip";
    const label = document.createElement("strong"); label.textContent = term.value;
    const type = document.createElement("small"); type.textContent = term.entity_type;
    const remove = document.createElement("button"); remove.type = "button"; remove.textContent = "×"; remove.title = `Remove ${term.value}`; remove.setAttribute("aria-label", `Remove ${term.value}`);
    remove.addEventListener("click", async () => { await api(`/api/terms/${term.id}`, { method: "DELETE" }); await loadTerms(); showToast("Protected term removed"); });
    chip.append(label, type, remove); list.append(chip);
  }
}

document.querySelectorAll("[data-tier]").forEach(button => button.addEventListener("click", () => selectTier(button.dataset.tier)));
$("#source-text").addEventListener("input", event => { $("#char-count").textContent = `${event.target.value.length.toLocaleString()} / 100,000 characters`; });
$("#new-scan").addEventListener("click", () => { $("#source-text").value = ""; $("#source-text").dispatchEvent(new Event("input")); $("#source-text").focus(); $("#results-section").hidden = true; });
document.querySelectorAll("[data-example]").forEach(button => button.addEventListener("click", () => { $("#source-text").value = examples[button.dataset.example]; $("#source-text").dispatchEvent(new Event("input")); $("#source-text").focus(); }));

$("#run-scan").addEventListener("click", async () => {
  const text = $("#source-text").value;
  $("#scan-error").hidden = true;
  if (!text.trim()) { $("#scan-error").textContent = "Enter text before running a scan."; $("#scan-error").hidden = false; $("#source-text").focus(); return; }
  const button = $("#run-scan"); button.disabled = true; button.innerHTML = "Scanning…";
  try {
    const { scan } = await api("/api/scan", { method: "POST", body: JSON.stringify({ text, tier: state.tier }) });
    renderScan(scan, text); showToast(`${scan.match_count} redaction${scan.match_count === 1 ? "" : "s"} found`);
  } catch (error) { $("#scan-error").textContent = error.message; $("#scan-error").hidden = false; }
  finally { button.disabled = false; button.innerHTML = "<span>⌕</span> Run scan"; }
});

$("#reveal-values").addEventListener("change", async event => {
  if (!state.scan) return;
  try {
    const suffix = event.target.checked ? "/reveal" : "";
    const { scan } = await api(`/api/scans/${encodeURIComponent(state.scan.id)}${suffix}`);
    renderMappings(scan.mappings || []);
    // renderScan resets the toggle, so preserve the user's explicit choice here.
    $("#reveal-values").checked = event.target.checked;
  } catch (error) { event.target.checked = false; showToast(error.message); }
});

$("#copy-output").addEventListener("click", async () => {
  try { await navigator.clipboard.writeText($("#redacted-output").textContent); showToast("Redacted output copied"); }
  catch { showToast("Clipboard access is unavailable in this browser"); }
});

$("#export-report").addEventListener("click", async event => {
  const button = event.currentTarget; button.disabled = true;
  try {
    const { report } = await api("/api/compliance-report");
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const link = document.createElement("a");
    const date = report.generated_at_utc.slice(0, 10);
    link.href = URL.createObjectURL(blob);
    link.download = `assured-ai-compliance-report-${date}.json`;
    document.body.append(link); link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(link.href), 1000);
    showToast(`Compliance report downloaded · ${report.summary.scan_count} saved scans`);
  } catch (error) { showToast(error.message); }
  finally { button.disabled = false; }
});

$("#toggle-all").addEventListener("click", async () => {
  const turnOn = state.detectors.some(item => !item.enabled);
  const updates = Object.fromEntries(state.detectors.map(item => [item.key, turnOn]));
  const button = $("#toggle-all"); button.disabled = true;
  try {
    await api("/api/detectors", { method: "PUT", body: JSON.stringify({ detectors: updates }) });
    state.detectors.forEach(item => { item.enabled = turnOn; }); renderDetectors(); showToast(`All detectors turned ${turnOn ? "on" : "off"}`);
  } catch (error) { showToast(error.message); }
  finally { button.disabled = false; }
});

$("#term-form").addEventListener("submit", async event => {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.currentTarget));
  try {
    await api("/api/terms", { method: "POST", body: JSON.stringify(data) });
    event.currentTarget.reset(); $("#term-type").value = "PERSON_NAME"; $("#term-sensitivity").value = "CONFIDENTIAL";
    await loadTerms(); showToast("Protected term saved");
  } catch (error) { showToast(error.message); }
});

Promise.all([loadTerms(), loadDetectors(), loadRuntime()]).catch(error => showToast(error.message));
