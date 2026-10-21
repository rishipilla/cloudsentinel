const configuredBase = document.querySelector('meta[name="cloudsentinel-api-base-url"]')?.content ?? "";
const API_BASE = configuredBase.replace(/\/$/, "");
const $ = (id) => document.getElementById(id);
let tokenPrompt = null;
let dashboardRequestActive = false;
let scheduleRequestActive = false;
let lastSuccessfulUpdate = null;
let hasLoadedSchedules = false;
let hasLoadedIncidents = false;

const elements = {
  apiDot: $("api-dot"), apiStatus: $("api-status"), dbDot: $("db-dot"), dbStatus: $("db-status"),
  total: $("metric-total"), success: $("metric-success"), failed: $("metric-failed"), latency: $("metric-latency"),
  rows: $("history-rows"), table: $("table-wrap"), empty: $("empty-state"), footer: $("table-footer"), count: $("row-count"),
  error: $("history-error"), errorText: $("history-error-text"), form: $("check-form"), url: $("endpoint-url"), timeout: $("timeout"),
  result: $("result-banner"), submit: $("submit-check"),
  scheduleForm: $("schedule-form"), scheduleId: $("schedule-id"), scheduleUrl: $("schedule-url"),
  scheduleInterval: $("schedule-interval"), scheduleTimeout: $("schedule-timeout"), scheduleFailures: $("schedule-failures"), scheduleRows: $("schedule-rows"),
  scheduleTable: $("schedule-table-wrap"), scheduleEmpty: $("schedule-empty"), scheduleError: $("schedule-error"),
  scheduleLoading: $("schedule-loading"), incidentLoading: $("incident-loading"),
  scheduleSave: $("save-schedule"), scheduleCancel: $("cancel-schedule-edit"),
  scheduleHistory: $("schedule-history"), scheduleHistoryRows: $("schedule-history-rows"),
  scheduleHistoryTitle: $("schedule-history-title"),
  incidentRows: $("incident-rows"), incidentTable: $("incident-table-wrap"), incidentEmpty: $("incident-empty"),
  incidentError: $("incident-error"),
  notificationRows: $("notification-rows"), notificationTable: $("notification-table-wrap"),
  notificationEmpty: $("notification-empty"), notificationError: $("notification-error"),
  notificationLoading: $("notification-loading"), reputationForm: $("reputation-form"),
  reputationType: $("reputation-type"), reputationIndicator: $("reputation-indicator"),
  reputationSubmit: $("reputation-submit"), reputationError: $("reputation-error"),
  reputationResult: $("reputation-result"),
  endpointNodes: $("endpoint-nodes"), topologyCount: $("topology-count"), topologyState: $("topology-state"),
  lastUpdated: $("last-updated"),
};

document.querySelectorAll(".nav-link").forEach((link) => {
  link.addEventListener("click", () => {
    document.querySelectorAll(".nav-link").forEach((item) => {
      item.classList.remove("active");
      item.removeAttribute("aria-current");
    });
    link.classList.add("active");
    link.setAttribute("aria-current", "page");
  });
});

function setConnection(dot, label, state, text) {
  dot.className = `status-dot ${state}`;
  label.textContent = text;
}

async function getJson(path, options = {}) {
  const controller = new AbortController();
  const timeoutMs = path === "/api/v1/check" ? 35000 : path === "/api/v1/reputation" ? 15000 : 10000;
  const timeout = window.setTimeout(() => controller.abort(), timeoutMs);
  try {
    let token = sessionStorage.getItem("cloudsentinel-api-token") || "";
    let response = await fetch(`${API_BASE}${path}`, {
      ...options,
      headers: { ...(options.headers || {}), ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      signal: controller.signal,
    });
    if (response.status === 401) {
      if (!tokenPrompt) {
        tokenPrompt = Promise.resolve(window.prompt("Enter the CloudSentinel API access token:") || "")
          .then((value) => {
            if (value) sessionStorage.setItem("cloudsentinel-api-token", value);
            return value;
          })
          .finally(() => { tokenPrompt = null; });
      }
      token = await tokenPrompt;
      if (token) {
        response = await fetch(`${API_BASE}${path}`, {
          ...options,
          headers: { ...(options.headers || {}), Authorization: `Bearer ${token}` },
          signal: controller.signal,
        });
      }
    }
    if (response.status === 401) sessionStorage.removeItem("cloudsentinel-api-token");
  } catch (cause) {
    if (cause.name === "AbortError") {
      throw new Error("The API request timed out. Check the connection and try again.");
    }
    throw new Error("Could not reach the API. Confirm the backend is running and the API base URL is correct.");
  } finally {
    window.clearTimeout(timeout);
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
    const detailCell = document.createElement("td");
    detailCell.className = check.error ? "check-detail" : "muted-cell check-detail";
    detailCell.textContent = check.error || "—";
    if (check.error) detailCell.title = check.error;
    row.append(urlCell, statusCell, codeCell, latencyCell, timeCell, detailCell); elements.rows.append(row);
  }
}

function renderSummary(summary) {
  elements.total.textContent = Number(summary.total_checks).toLocaleString();
  elements.success.textContent = Number(summary.successful_checks).toLocaleString();
  elements.failed.textContent = Number(summary.failed_checks).toLocaleString();
  elements.latency.textContent = summary.average_latency_ms == null ? "—" : `${Number(summary.average_latency_ms).toLocaleString()} ms`;
}

function textCell(value, className = "") {
  const cell = document.createElement("td");
  if (className) cell.className = className;
  cell.textContent = value ?? "—";
  return cell;
}

function actionButton(label, handler, className = "text-button") {
  const button = document.createElement("button");
  button.type = "button";
  button.className = className;
  button.textContent = label;
  button.addEventListener("click", handler);
  return button;
}

function renderSchedules(schedules) {
  elements.scheduleRows.replaceChildren();
  renderEndpointNodes(schedules);
  for (const schedule of schedules) {
    const row = document.createElement("tr");
    const endpoint = textCell(safeUrlLabel(schedule.url), "url-cell");
    endpoint.title = schedule.url;
    const latest = schedule.latest_check;
    const latestText = latest
      ? `${latest.status}${latest.status_code == null ? "" : ` · HTTP ${latest.status_code}`}${latest.latency_ms == null ? "" : ` · ${latest.latency_ms} ms`} · ${formatDate(latest.checked_at)}`
      : "No checks yet";
    const stateCell = document.createElement("td");
    const state = document.createElement("span");
    state.className = `status-badge ${schedule.enabled ? "healthy" : "unknown"}`;
    state.textContent = schedule.enabled ? "Enabled" : "Paused";
    stateCell.append(state);
    const actions = document.createElement("td");
    actions.className = "schedule-actions";
    actions.append(
      actionButton("History", () => showScheduleHistory(schedule.id, schedule.url)),
      actionButton("Edit", () => editSchedule(schedule)),
      actionButton(schedule.enabled ? "Pause" : "Resume", () => updateSchedule(schedule.id, { enabled: !schedule.enabled })),
      actionButton("Delete", () => deleteSchedule(schedule.id), "text-button destructive-action"),
    );
    row.append(
      endpoint,
      textCell(`${Math.round(schedule.interval_seconds / 60)} min`),
      stateCell,
      textCell(latestText),
      textCell(schedule.enabled ? formatDate(schedule.next_run_at) : "—"),
      actions,
    );
    elements.scheduleRows.append(row);
  }
  elements.scheduleTable.hidden = schedules.length === 0;
  elements.scheduleEmpty.hidden = schedules.length !== 0;
}

function renderEndpointNodes(schedules) {
  elements.endpointNodes.replaceChildren();
  const enabled = schedules.filter((schedule) => schedule.enabled);
  elements.topologyCount.textContent = `${enabled.length} active · ${schedules.length} configured`;
  elements.topologyState.hidden = schedules.length > 0;
  elements.topologyState.textContent = "No scheduled endpoints are configured. Create a schedule to monitor an endpoint.";
  for (const schedule of enabled) {
    const latest = schedule.latest_check;
    const status = latest?.status || "unknown";
    const item = document.createElement("li");
    item.className = "endpoint-node";
    const marker = document.createElement("span");
    marker.className = `node-marker ${status}`;
    marker.setAttribute("aria-hidden", "true");
    const info = document.createElement("span");
    info.className = "node-info";
    const name = document.createElement("strong");
    name.textContent = safeUrlLabel(schedule.url);
    name.title = schedule.url;
    const detail = document.createElement("small");
    detail.textContent = latest
      ? `${latest.status_code == null ? "No HTTP response" : `HTTP ${latest.status_code}`}${latest.latency_ms == null ? "" : ` · ${Number(latest.latency_ms).toLocaleString()} ms`} · ${formatDate(latest.checked_at)}`
      : "Awaiting first scheduled check";
    const badge = document.createElement("span");
    badge.className = `status-badge ${status}`;
    badge.textContent = status[0].toUpperCase() + status.slice(1);
    info.append(name, detail);
    item.append(marker, info, badge);
    elements.endpointNodes.append(item);
  }
}

function renderIncidents(incidents) {
  elements.incidentRows.replaceChildren();
  for (const incident of incidents) {
    const row = document.createElement("tr");
    const badge = document.createElement("span");
    badge.className = `status-badge ${incident.status === "open" ? "down" : "healthy"}`;
    badge.textContent = incident.status === "open" ? "Open" : "Resolved";
    const state = document.createElement("td"); state.append(badge);
    row.append(
      textCell(incident.url ? safeUrlLabel(incident.url) : `Schedule #${incident.schedule_id}`, "url-cell"),
      state, textCell(incident.failure_count),
      textCell(formatDate(incident.started_at)), textCell(formatDate(incident.resolved_at)),
      textCell(incident.latest_error, "check-detail"),
    );
    elements.incidentRows.append(row);
  }
  elements.incidentTable.hidden = incidents.length === 0;
  elements.incidentEmpty.hidden = incidents.length !== 0;
}

async function loadSchedules() {
  if (scheduleRequestActive) return;
  scheduleRequestActive = true;
  try {
  elements.scheduleError.hidden = true;
  elements.incidentError.hidden = true;
  elements.scheduleLoading.hidden = false;
  elements.incidentLoading.hidden = false;
  const [scheduleResult, incidentResult] = await Promise.allSettled([
    getJson("/api/v1/schedules?limit=100"),
    getJson("/api/v1/incidents?limit=100"),
  ]);
  if (scheduleResult.status === "fulfilled") {
    renderSchedules(scheduleResult.value.schedules);
    hasLoadedSchedules = true;
  }
  else {
    if (!hasLoadedSchedules) {
      elements.scheduleTable.hidden = true;
      elements.scheduleEmpty.hidden = true;
    }
    elements.scheduleError.textContent = hasLoadedSchedules
      ? `Showing the last successful inventory. Refresh failed: ${scheduleResult.reason.message}`
      : scheduleResult.reason.message;
    elements.scheduleError.hidden = false;
  }
  if (incidentResult.status === "fulfilled") {
    renderIncidents(incidentResult.value.incidents);
    hasLoadedIncidents = true;
  }
  else {
    if (!hasLoadedIncidents) {
      elements.incidentTable.hidden = true;
      elements.incidentEmpty.hidden = true;
    }
    elements.incidentError.textContent = hasLoadedIncidents
      ? `Showing the last successful incident list. Refresh failed: ${incidentResult.reason.message}`
      : incidentResult.reason.message;
    elements.incidentError.hidden = false;
  }
  elements.scheduleLoading.hidden = true;
  elements.incidentLoading.hidden = true;
  await loadNotifications();
  } finally {
  scheduleRequestActive = false;
  }
}

function renderNotifications(notifications) {
  elements.notificationRows.replaceChildren();
  for (const item of notifications) {
    const row = document.createElement("tr");
    const attemptText = item.attempts.length
      ? item.attempts.map((attempt) => `#${attempt.number} ${attempt.provider}: ${attempt.status}`).join(" · ")
      : "No delivery attempt";
    for (const value of [
      item.event_type === "opened" ? "Incident opened" : "Incident resolved",
      `#${item.incident_id}`,
      item.status,
      attemptText,
      formatDate(item.created_at),
      formatDate(item.delivered_at),
      item.last_error || "—",
    ]) {
      const cell = document.createElement("td");
      cell.textContent = value;
      row.append(cell);
    }
    elements.notificationRows.append(row);
  }
  elements.notificationTable.hidden = notifications.length === 0;
  elements.notificationEmpty.hidden = notifications.length !== 0;
}

async function loadNotifications() {
  elements.notificationLoading.hidden = false;
  elements.notificationError.hidden = true;
  try {
    const result = await getJson("/api/v1/notifications?limit=100");
    renderNotifications(result.notifications);
  } catch (error) {
    elements.notificationTable.hidden = true;
    elements.notificationEmpty.hidden = true;
    elements.notificationError.textContent = error.message;
    elements.notificationError.hidden = false;
  } finally {
    elements.notificationLoading.hidden = true;
  }
}

function showReputation(result) {
  elements.reputationResult.replaceChildren();
  const heading = document.createElement("strong");
  heading.textContent = `${result.provider} · ${result.assessment}`;
  const summary = document.createElement("p");
  const stats = result.last_analysis_stats;
  summary.textContent = `${result.indicator_type}: ${result.indicator} · malicious ${stats.malicious}, suspicious ${stats.suspicious}, harmless ${stats.harmless}, undetected ${stats.undetected}${result.cached ? " · cached" : ""}`;
  const notice = document.createElement("p");
  notice.textContent = result.signal_notice;
  elements.reputationResult.append(heading, summary, notice);
  elements.reputationResult.hidden = false;
}

function resetScheduleForm() {
  elements.scheduleForm.reset();
  elements.scheduleId.value = "";
  elements.scheduleSave.textContent = "Create schedule";
  elements.scheduleCancel.hidden = true;
  elements.scheduleUrl.removeAttribute("readonly");
}

function editSchedule(schedule) {
  elements.scheduleId.value = schedule.id;
  elements.scheduleUrl.value = schedule.url;
  elements.scheduleInterval.value = Math.round(schedule.interval_seconds / 60);
  elements.scheduleTimeout.value = schedule.timeout_seconds;
  elements.scheduleFailures.value = schedule.failure_threshold;
  elements.scheduleSave.textContent = "Save changes";
  elements.scheduleCancel.hidden = false;
  document.querySelector("#scheduled").scrollIntoView({ behavior: "smooth", block: "center" });
  elements.scheduleUrl.focus();
}

async function updateSchedule(id, changes) {
  try {
    await getJson(`/api/v1/schedules/${id}`, {
      method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify(changes),
    });
    await loadSchedules();
  } catch (error) {
    elements.scheduleError.textContent = error.message;
    elements.scheduleError.hidden = false;
  }
}

async function deleteSchedule(id) {
  if (!window.confirm("Delete this schedule? Its check and incident history will be retained.")) return;
  try {
    await getJson(`/api/v1/schedules/${id}`, { method: "DELETE" });
    await loadSchedules();
    if (elements.scheduleId.value === String(id)) resetScheduleForm();
  } catch (error) {
    elements.scheduleError.textContent = error.message;
    elements.scheduleError.hidden = false;
  }
}

async function showScheduleHistory(id, url) {
  elements.scheduleHistory.hidden = false;
  elements.scheduleHistoryTitle.textContent = `Recent checks · ${safeUrlLabel(url)}`;
  elements.scheduleHistoryRows.textContent = "Loading scheduled check history…";
  try {
    const response = await getJson(`/api/v1/schedules/${id}/history?limit=20`);
    elements.scheduleHistoryRows.replaceChildren();
    if (response.checks.length === 0) {
      elements.scheduleHistoryRows.textContent = "No scheduled checks have run yet.";
      return;
    }
    for (const check of response.checks) {
      const item = document.createElement("div");
      item.className = "schedule-history-row";
      item.textContent = `${check.status.toUpperCase()} · ${formatDate(check.checked_at)} · ${check.latency_ms == null ? "no response time" : `${check.latency_ms} ms`}${check.error ? ` · ${check.error}` : ""}`;
      elements.scheduleHistoryRows.append(item);
    }
  } catch (error) {
    elements.scheduleHistoryRows.textContent = error.message;
  }
}

async function loadDashboard() {
  if (dashboardRequestActive) return;
  dashboardRequestActive = true;
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
    if (!lastSuccessfulUpdate) {
      elements.total.textContent = "—";
      elements.success.textContent = "—";
      elements.failed.textContent = "—";
      elements.latency.textContent = "—";
      elements.table.hidden = true;
      elements.footer.hidden = true;
    }
    elements.error.hidden = false;
    elements.errorText.textContent = lastSuccessfulUpdate
      ? `Showing the last successful snapshot. Refresh failed: ${history.reason.message}`
      : history.reason.message;
    elements.lastUpdated.textContent = lastSuccessfulUpdate
      ? `STALE · Last synced ${formatDate(lastSuccessfulUpdate)}`
      : "No successful sync yet";
    refreshButton.disabled = false;
    refreshButton.removeAttribute("aria-busy");
    refreshLabel.textContent = "Refresh";
    dashboardRequestActive = false;
    return;
  }
  lastSuccessfulUpdate = new Date();
  elements.lastUpdated.textContent = `Last synced ${formatDate(lastSuccessfulUpdate)}`;
  renderSummary(history.value.summary);
  renderRows(history.value.checks);
  elements.empty.hidden = history.value.checks.length !== 0;
  elements.table.hidden = history.value.checks.length === 0;
  elements.footer.hidden = history.value.checks.length === 0;
  elements.count.textContent = `Showing ${history.value.checks.length} recent ${history.value.checks.length === 1 ? "check" : "checks"}`;
  refreshButton.disabled = false;
  refreshButton.removeAttribute("aria-busy");
  refreshLabel.textContent = "Refresh";
  dashboardRequestActive = false;
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
$("refresh-schedules").addEventListener("click", loadSchedules);
$("refresh-notifications").addEventListener("click", loadNotifications);
$("close-schedule-history").addEventListener("click", () => { elements.scheduleHistory.hidden = true; });
elements.scheduleCancel.addEventListener("click", resetScheduleForm);
elements.scheduleForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (elements.scheduleForm.dataset.busy === "true") return;
  elements.scheduleError.hidden = true;
  const url = elements.scheduleUrl.value.trim();
  const intervalMinutes = Number(elements.scheduleInterval.value);
  const timeoutSeconds = Number(elements.scheduleTimeout.value);
  const threshold = Number(elements.scheduleFailures.value);
  if (!url || !Number.isInteger(intervalMinutes) || intervalMinutes < 1 || intervalMinutes > 1440 || !Number.isFinite(timeoutSeconds) || timeoutSeconds <= 0 || timeoutSeconds > 30 || !Number.isInteger(threshold) || threshold < 1 || threshold > 10) {
    elements.scheduleError.textContent = "Enter a URL, an interval from 1 to 1440 minutes, a timeout up to 30 seconds, and a failure threshold from 1 to 10.";
    elements.scheduleError.hidden = false;
    return;
  }
  const body = { url, interval_seconds: intervalMinutes * 60, timeout_seconds: timeoutSeconds, failure_threshold: threshold };
  const id = elements.scheduleId.value;
  elements.scheduleForm.dataset.busy = "true";
  elements.scheduleSave.disabled = true;
  elements.scheduleSave.setAttribute("aria-busy", "true");
  try {
    await getJson(id ? `/api/v1/schedules/${id}` : "/api/v1/schedules", {
      method: id ? "PATCH" : "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    resetScheduleForm();
    await loadSchedules();
  } catch (error) {
    elements.scheduleError.textContent = error.message;
    elements.scheduleError.hidden = false;
  } finally {
    delete elements.scheduleForm.dataset.busy;
    elements.scheduleSave.disabled = false;
    elements.scheduleSave.removeAttribute("aria-busy");
  }
});
$("open-check").addEventListener("click", () => { elements.url.focus(); document.querySelector("#endpoints").scrollIntoView({ behavior: "smooth", block: "center" }); });
$("empty-check").addEventListener("click", () => { elements.url.focus(); document.querySelector("#endpoints").scrollIntoView({ behavior: "smooth", block: "center" }); });
for (const field of [elements.url, elements.timeout]) field.addEventListener("input", () => { if (field.getAttribute("aria-invalid") === "true") validateForm(); });

elements.reputationForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (elements.reputationForm.dataset.busy === "true") return;
  elements.reputationError.hidden = true;
  elements.reputationResult.hidden = true;
  const indicator = elements.reputationIndicator.value.trim();
  if (!indicator) {
    elements.reputationError.textContent = "Enter a public domain or IP address.";
    elements.reputationError.hidden = false;
    return;
  }
  elements.reputationForm.dataset.busy = "true";
  elements.reputationSubmit.disabled = true;
  elements.reputationSubmit.setAttribute("aria-busy", "true");
  try {
    const result = await getJson("/api/v1/reputation", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ indicator_type: elements.reputationType.value, indicator }),
    });
    showReputation(result);
  } catch (error) {
    elements.reputationError.textContent = error.message;
    elements.reputationError.hidden = false;
  } finally {
    delete elements.reputationForm.dataset.busy;
    elements.reputationSubmit.disabled = false;
    elements.reputationSubmit.removeAttribute("aria-busy");
  }
});

loadDashboard();
loadSchedules();
window.setInterval(() => {
  if (document.visibilityState === "visible") {
    loadDashboard();
    loadSchedules();
  }
}, 30000);
