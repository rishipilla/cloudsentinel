const configuredBase = document.querySelector('meta[name="cloudsentinel-api-base-url"]')?.content ?? "";
const API_BASE = configuredBase.replace(/\/$/, "");
const $ = (id) => document.getElementById(id);

const elements = {
  apiDot: $("api-dot"), apiStatus: $("api-status"), dbDot: $("db-dot"), dbStatus: $("db-status"),
  total: $("metric-total"), success: $("metric-success"), failed: $("metric-failed"), latency: $("metric-latency"),
  rows: $("history-rows"), table: $("table-wrap"), empty: $("empty-state"), footer: $("table-footer"), count: $("row-count"),
  error: $("history-error"), errorText: $("history-error-text"), form: $("check-form"), url: $("endpoint-url"), timeout: $("timeout"),
  result: $("result-banner"), submit: $("submit-check"),
};

function setConnection(dot, label, state, text) {
  dot.className = `status-dot ${state}`;
  label.textContent = text;
}

async function getJson(path, options = {}) {
  let response;
  try {
    response = await fetch(`${API_BASE}${path}`, options);
  } catch {
    throw new Error("Could not reach the API. Confirm the backend is running and the API base URL is correct.");
  }
  let data;
  try { data = await response.json(); } catch { data = {}; }
  if (!response.ok) {
    const detail = Array.isArray(data.detail) ? data.detail.map((issue) => issue.msg).join(" ") : data.detail;
    const error = new Error(detail || `The server returned HTTP ${response.status}.`);
    error.status = response.status;
    throw error;
  }
  return data;
}

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date);
}

function safeUrlLabel(value) {
  try {
    const parsed = new URL(value);
    return `${parsed.host}${parsed.pathname}${parsed.search}`;
  } catch { return value; }
}

function renderRows(checks) {
  elements.rows.replaceChildren();
  for (const check of checks) {
    const row = document.createElement("tr");
    const urlCell = document.createElement("td"); urlCell.className = "url-cell";
    const url = document.createElement("span"); url.className = "url-text"; url.textContent = safeUrlLabel(check.url); url.title = check.url; urlCell.append(url);
    const statusCell = document.createElement("td");
    const badge = document.createElement("span");
    const status = check.status === "healthy" ? "healthy" : check.status === "degraded" ? "degraded" : check.status === "down" ? "down" : "unknown";
    badge.className = `status-badge ${status}`; badge.textContent = status[0].toUpperCase() + status.slice(1); statusCell.append(badge);
    const codeCell = document.createElement("td"); codeCell.className = check.status_code == null ? "muted-cell status-code" : "status-code"; codeCell.textContent = check.status_code ?? "—";
    const latencyCell = document.createElement("td"); latencyCell.className = check.latency_ms == null ? "muted-cell latency-cell" : "latency-cell"; latencyCell.textContent = check.latency_ms == null ? "—" : `${Number(check.latency_ms).toLocaleString()} ms`;
    const timeCell = document.createElement("td"); timeCell.textContent = formatDate(check.checked_at);
    row.append(urlCell, statusCell, codeCell, latencyCell, timeCell); elements.rows.append(row);
  }
}

function renderSummary(summary) {
  elements.total.textContent = Number(summary.total_checks).toLocaleString();
  elements.success.textContent = Number(summary.successful_checks).toLocaleString();
  elements.failed.textContent = Number(summary.failed_checks).toLocaleString();
  elements.latency.textContent = summary.average_latency_ms == null ? "—" : `${Number(summary.average_latency_ms).toLocaleString()} ms`;
}

async function loadDashboard() {
  const refreshButton = $("refresh-history");
  const refreshLabel = refreshButton.querySelector("span:last-child");
  refreshButton.disabled = true;
  refreshButton.setAttribute("aria-busy", "true");
  refreshLabel.textContent = "Refreshing…";
  elements.error.hidden = true;
  elements.table.hidden = false;
  elements.empty.hidden = true;
  elements.footer.hidden = false;
  setConnection(elements.apiDot, elements.apiStatus, "checking", "Connecting to API");
  setConnection(elements.dbDot, elements.dbStatus, "checking", "Database");
  const [health, ready, history] = await Promise.allSettled([
    getJson("/health"), getJson("/health/ready"), getJson("/api/v1/checks?limit=100"),
  ]);
  if (health.status === "fulfilled") setConnection(elements.apiDot, elements.apiStatus, "online", "API connected");
  else setConnection(elements.apiDot, elements.apiStatus, "offline", "API unavailable");
  if (ready.status === "fulfilled") setConnection(elements.dbDot, elements.dbStatus, "online", "Database ready");
  else setConnection(elements.dbDot, elements.dbStatus, "offline", "Database unavailable");
  if (history.status === "rejected") {
    elements.total.textContent = "—";
    elements.success.textContent = "—";
    elements.failed.textContent = "—";
    elements.latency.textContent = "—";
    elements.table.hidden = true; elements.footer.hidden = true; elements.error.hidden = false;
    elements.errorText.textContent = history.reason.message;
    refreshButton.disabled = false;
    refreshButton.removeAttribute("aria-busy");
    refreshLabel.textContent = "Refresh";
    return;
  }
  renderSummary(history.value.summary);
  renderRows(history.value.checks);
  elements.empty.hidden = history.value.checks.length !== 0;
  elements.table.hidden = history.value.checks.length === 0;
  elements.footer.hidden = history.value.checks.length === 0;
  elements.count.textContent = `Showing ${history.value.checks.length} recent ${history.value.checks.length === 1 ? "check" : "checks"}`;
  refreshButton.disabled = false;
  refreshButton.removeAttribute("aria-busy");
  refreshLabel.textContent = "Refresh";
}

function showResult(kind, title, detail) {
  elements.result.className = `result-banner ${kind}`;
  elements.result.replaceChildren();
  const strong = document.createElement("strong"); strong.textContent = title;
  const message = document.createElement("span"); message.textContent = ` ${detail}`;
  elements.result.append(strong, message); elements.result.hidden = false;
}

function validateForm() {
  const url = elements.url.value.trim();
  const timeout = Number(elements.timeout.value);
  let valid = true;
  let urlMessage = "";
  try {
    const parsed = new URL(url);
    if (!["http:", "https:"].includes(parsed.protocol) || !parsed.hostname) urlMessage = "Enter a complete HTTP or HTTPS URL.";
    if (parsed.username || parsed.password) urlMessage = "URLs with embedded credentials are not allowed.";
  } catch { urlMessage = "Enter a valid HTTP or HTTPS URL."; }
  if (urlMessage) valid = false;
  $("url-error").textContent = urlMessage;
  elements.url.setAttribute("aria-invalid", String(Boolean(urlMessage)));
  let timeoutMessage = "";
  if (!Number.isFinite(timeout) || timeout <= 0 || timeout > 30) timeoutMessage = "Choose a timeout greater than 0 and up to 30 seconds.";
  $("timeout-error").textContent = timeoutMessage;
  elements.timeout.setAttribute("aria-invalid", String(Boolean(timeoutMessage)));
  if (timeoutMessage) valid = false;
  return valid;
}

elements.form.addEventListener("submit", async (event) => {
  event.preventDefault(); elements.result.hidden = true;
  if (!validateForm()) return;
  elements.submit.disabled = true; elements.submit.classList.add("is-loading"); elements.submit.setAttribute("aria-busy", "true");
  try {
    const result = await getJson("/api/v1/check", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: elements.url.value.trim(), timeout_seconds: Number(elements.timeout.value) }),
    });
    if (result.status === "healthy") showResult("success", "Endpoint responded successfully.", `HTTP ${result.status_code} in ${result.latency_ms} ms.`);
    else if (result.status === "degraded" && result.status_code != null) showResult("failure", "Endpoint returned an HTTP error or slow response.", `HTTP ${result.status_code} in ${result.latency_ms} ms.`);
    else if (result.status_code != null) showResult("failure", "Endpoint returned an HTTP error.", `HTTP ${result.status_code}.`);
    else showResult("failure", "Endpoint is unreachable.", result.error || "The request did not receive a response.");
    await loadDashboard();
  } catch (error) {
    if (error.status === 422) showResult("info", "Endpoint input was rejected.", error.message);
    else if (error.status === 503) showResult("failure", "The API or database could not complete the check.", error.message);
    else showResult("failure", "Check could not be completed.", error.message);
  } finally {
    elements.submit.disabled = false; elements.submit.classList.remove("is-loading"); elements.submit.removeAttribute("aria-busy");
  }
});

$("refresh-history").addEventListener("click", loadDashboard);
$("retry-history").addEventListener("click", loadDashboard);
$("open-check").addEventListener("click", () => { elements.url.focus(); document.querySelector("#endpoints").scrollIntoView({ behavior: "smooth", block: "center" }); });
$("empty-check").addEventListener("click", () => { elements.url.focus(); document.querySelector("#endpoints").scrollIntoView({ behavior: "smooth", block: "center" }); });
for (const field of [elements.url, elements.timeout]) field.addEventListener("input", () => { if (field.getAttribute("aria-invalid") === "true") validateForm(); });

loadDashboard();
