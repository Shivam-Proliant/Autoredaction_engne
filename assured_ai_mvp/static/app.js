const $ = (selector) => document.querySelector(selector);
const state = { scan: null, terms: [], toastTimer: null };
const examples = {
  incident: "Urgent: investigate the deadlock for Callum Cockburn at Synoptix. Contact him at callum.cockburn@example.com. The service key is sk-proj-89fH2kL9pQ3mN7vX1zR4 and the host is 192.168.1.200.",
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
  $("#scan-stats").innerHTML = `<span class="stat-pill"><strong>${scan.match_count}</strong> redactions</span><span class="stat-pill"><strong>${scan.review_count}</strong> review flags</span><span class="stat-pill"><strong>${Number(scan.processing_ms).toFixed(2)} ms</strong></span>`;
  $("#review-alert").hidden = !scan.review_count;
  $("#scan-time").textContent = new Date(`${scan.created_at.replace(" ", "T")}Z`).toLocaleString();
  $("#reveal-values").checked = false;
  renderMappings(scan.mappings || []);
  loadHistory();
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

async function loadHistory() {
  try {
    const { scans } = await api("/api/scans");
    const list = $("#history-list"); list.replaceChildren();
    if (!scans.length) { list.innerHTML = '<div class="history-empty">Your scans will appear here</div>'; return; }
    for (const scan of scans) {
      const button = document.createElement("button"); button.className = "history-button";
      button.textContent = `${scan.match_count} redactions · ${new Date(`${scan.created_at.replace(" ", "T")}Z`).toLocaleDateString()}`;
      button.title = `${scan.id} · ${scan.redacted_text.slice(0, 90)}`;
      button.addEventListener("click", async () => {
        const result = await api(`/api/scans/${encodeURIComponent(scan.id)}`);
        renderScan(result.scan, null, true); // Original text is intentionally not persisted.
        showToast("Loaded saved scan. Original text is not stored.");
      });
      list.append(button);
    }
  } catch (error) { showToast(error.message); }
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

$("#source-text").addEventListener("input", event => { $("#char-count").textContent = `${event.target.value.length.toLocaleString()} / 100,000 characters`; });
$("#new-scan").addEventListener("click", () => { $("#source-text").value = ""; $("#source-text").dispatchEvent(new Event("input")); $("#source-text").focus(); $("#results-section").hidden = true; });
document.querySelectorAll("[data-example]").forEach(button => button.addEventListener("click", () => { $("#source-text").value = examples[button.dataset.example]; $("#source-text").dispatchEvent(new Event("input")); $("#source-text").focus(); }));

$("#run-scan").addEventListener("click", async () => {
  const text = $("#source-text").value;
  $("#scan-error").hidden = true;
  if (!text.trim()) { $("#scan-error").textContent = "Enter text before running a scan."; $("#scan-error").hidden = false; $("#source-text").focus(); return; }
  const button = $("#run-scan"); button.disabled = true; button.innerHTML = "Scanning…";
  try {
    const { scan } = await api("/api/scan", { method: "POST", body: JSON.stringify({ text }) });
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

$("#term-form").addEventListener("submit", async event => {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.currentTarget));
  try {
    await api("/api/terms", { method: "POST", body: JSON.stringify(data) });
    event.currentTarget.reset(); $("#term-type").value = "CUSTOM_TERM"; $("#term-sensitivity").value = "CONFIDENTIAL";
    await loadTerms(); showToast("Protected term saved");
  } catch (error) { showToast(error.message); }
});

Promise.all([loadTerms(), loadHistory()]).catch(error => showToast(error.message));
