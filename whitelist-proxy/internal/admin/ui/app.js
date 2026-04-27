// Whitelist Proxy — front-end vanilla. Sem build, sem framework.

const TOKEN_KEY = "wlp_token";

// ---------- estado ----------

const state = {
  rules: [],   // [{pattern, type, note}, ...]
  dirty: false,
  logsTimer: null,
  statusTimer: null,
};

// ---------- bootstrap ----------

document.addEventListener("DOMContentLoaded", () => {
  // Token via ?t=... tem prioridade (link aberto pelo subcomando "ui").
  const url = new URL(location.href);
  const fromQuery = url.searchParams.get("t");
  if (fromQuery) {
    localStorage.setItem(TOKEN_KEY, fromQuery);
    url.searchParams.delete("t");
    history.replaceState({}, "", url.toString());
  }

  bindNav();
  bindLogin();
  bindWhitelist();
  bindLogs();
  bindStatus();

  if (localStorage.getItem(TOKEN_KEY)) {
    enterApp();
  } else {
    showView("login");
  }
});

// ---------- HTTP helper ----------

async function api(path, opts = {}) {
  const token = localStorage.getItem(TOKEN_KEY);
  const headers = Object.assign(
    { "Content-Type": "application/json" },
    opts.headers || {},
    token ? { "Authorization": "Bearer " + token } : {}
  );
  const resp = await fetch(path, Object.assign({}, opts, { headers }));
  if (resp.status === 401) {
    localStorage.removeItem(TOKEN_KEY);
    showView("login");
    throw new Error("unauthorized");
  }
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(text || resp.statusText);
  }
  const ct = resp.headers.get("Content-Type") || "";
  return ct.includes("application/json") ? resp.json() : resp.text();
}

// ---------- navegação ----------

function bindNav() {
  document.querySelectorAll(".tab").forEach(btn => {
    btn.addEventListener("click", () => showView(btn.dataset.tab));
  });
  document.getElementById("logout").addEventListener("click", () => {
    localStorage.removeItem(TOKEN_KEY);
    location.reload();
  });
}

function showView(name) {
  // Esconde todas as views.
  document.querySelectorAll(".view").forEach(v => v.hidden = true);
  // Mostra a alvo.
  const target = document.getElementById("view-" + name);
  if (target) target.hidden = false;
  // Atualiza tabs ativos.
  document.querySelectorAll(".tab").forEach(t => {
    t.classList.toggle("active", t.dataset.tab === name);
  });

  // Pausa/retoma timers conforme a aba.
  stopLogsAuto();
  stopStatusAuto();
  if (name === "logs") {
    refreshLogs();
    if (document.getElementById("auto-refresh").checked) startLogsAuto();
  }
  if (name === "status") {
    refreshStatus();
    startStatusAuto();
  }
  if (name === "whitelist") {
    refreshRules();
  }
}

// ---------- login ----------

function bindLogin() {
  const submit = () => {
    const tok = document.getElementById("token-input").value.trim();
    if (!tok) return;
    localStorage.setItem(TOKEN_KEY, tok);
    enterApp();
  };
  document.getElementById("token-submit").addEventListener("click", submit);
  document.getElementById("token-input").addEventListener("keydown", e => {
    if (e.key === "Enter") submit();
  });
}

async function enterApp() {
  // Valida o token chamando /api/status.
  try {
    await api("/api/status");
  } catch (err) {
    document.getElementById("login-error").textContent = "Token inválido.";
    document.getElementById("login-error").hidden = false;
    showView("login");
    return;
  }
  setStatusPill("ok", "online");
  showView("whitelist");
}

function setStatusPill(kind, text) {
  const el = document.getElementById("status-pill");
  el.className = "pill pill-" + (kind === "ok" ? "ok" : kind === "err" ? "err" : "muted");
  el.textContent = text;
}

// ---------- WHITELIST ----------

function bindWhitelist() {
  document.getElementById("add-rule").addEventListener("click", () => {
    state.rules.push({ pattern: "", type: "exact", note: "" });
    markDirty();
    renderRules();
  });
  document.getElementById("save-rules").addEventListener("click", saveRules);
  document.getElementById("reload-disk").addEventListener("click", reloadFromDisk);
}

async function refreshRules() {
  if (state.dirty) return; // não derruba edições do usuário
  try {
    const data = await api("/api/whitelist");
    state.rules = (data.rules || []).map(r => ({
      pattern: r.pattern || "",
      type: r.type || "exact",
      note: r.note || "",
    }));
    state.dirty = false;
    updateDirtyUI();
    renderRules();
  } catch (err) {
    console.error(err);
  }
}

function renderRules() {
  const tbody = document.getElementById("rules-body");
  tbody.innerHTML = "";
  state.rules.forEach((rule, i) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><input type="text" data-field="pattern" value="${escapeAttr(rule.pattern)}"
            placeholder="ex.: *.exemplo.com"></td>
      <td>
        <select data-field="type">
          <option value="exact"    ${rule.type === "exact"    ? "selected" : ""}>exact</option>
          <option value="wildcard" ${rule.type === "wildcard" ? "selected" : ""}>wildcard</option>
          <option value="regex"    ${rule.type === "regex"    ? "selected" : ""}>regex</option>
        </select>
      </td>
      <td><input type="text" data-field="note" value="${escapeAttr(rule.note)}"
            placeholder="(opcional)"></td>
      <td class="row-actions">
        <button class="icon-btn" data-action="delete" title="Remover">✕</button>
      </td>
    `;
    tr.querySelectorAll("[data-field]").forEach(input => {
      input.addEventListener("input", () => {
        state.rules[i][input.dataset.field] = input.value;
        markDirty();
      });
    });
    tr.querySelector("[data-action=delete]").addEventListener("click", () => {
      state.rules.splice(i, 1);
      markDirty();
      renderRules();
    });
    tbody.appendChild(tr);
  });
}

function markDirty() {
  state.dirty = true;
  updateDirtyUI();
}

function updateDirtyUI() {
  document.getElementById("dirty-flag").hidden = !state.dirty;
  document.getElementById("save-rules").disabled = !state.dirty;
}

async function saveRules() {
  // Filtra regras com pattern vazio para não corromper o arquivo.
  const cleaned = state.rules
    .filter(r => r.pattern.trim() !== "")
    .map(r => ({
      pattern: r.pattern.trim(),
      type: r.type,
      note: r.note.trim() || undefined,
    }));
  try {
    const result = await api("/api/whitelist", {
      method: "PUT",
      body: JSON.stringify({ rules: cleaned }),
    });
    state.dirty = false;
    updateDirtyUI();
    toast("Salvas " + result.saved + " regras.");
    state.rules = cleaned.map(r => ({
      pattern: r.pattern,
      type: r.type,
      note: r.note || "",
    }));
    renderRules();
  } catch (err) {
    alert("Erro ao salvar: " + err.message);
  }
}

async function reloadFromDisk() {
  if (state.dirty && !confirm("Você tem alterações não salvas. Descartar?")) return;
  try {
    const result = await api("/api/whitelist/reload", { method: "POST" });
    toast("Recarregadas " + result.reloaded + " regras do disco.");
    state.dirty = false;
    updateDirtyUI();
    refreshRules();
  } catch (err) {
    alert("Erro ao recarregar: " + err.message);
  }
}

// ---------- LOGS ----------

function bindLogs() {
  document.getElementById("refresh-logs").addEventListener("click", refreshLogs);
  document.getElementById("auto-refresh").addEventListener("change", e => {
    if (e.target.checked) startLogsAuto();
    else stopLogsAuto();
  });
  document.getElementById("filter-action").addEventListener("change", refreshLogs);
  document.getElementById("filter-host").addEventListener("input", debounce(refreshLogs, 200));
}

function startLogsAuto() {
  stopLogsAuto();
  state.logsTimer = setInterval(refreshLogs, 3000);
}

function stopLogsAuto() {
  if (state.logsTimer) {
    clearInterval(state.logsTimer);
    state.logsTimer = null;
  }
}

async function refreshLogs() {
  try {
    const data = await api("/api/logs/recent?n=300");
    const filterAction = document.getElementById("filter-action").value;
    const filterHost = document.getElementById("filter-host").value.trim().toLowerCase();
    let decisions = data.decisions || [];
    if (filterAction) decisions = decisions.filter(d => d.action === filterAction);
    if (filterHost)   decisions = decisions.filter(d => (d.host || "").toLowerCase().includes(filterHost));

    const tbody = document.getElementById("logs-body");
    // Mais recentes em cima.
    decisions.reverse();
    tbody.innerHTML = decisions.map(d => `
      <tr>
        <td>${formatTime(d.time)}</td>
        <td class="action-${d.action}">${d.action}</td>
        <td>${escapeHtml(d.proto || "")}</td>
        <td>${escapeHtml(d.host || "")}</td>
        <td>${escapeHtml(d.client || "")}</td>
        <td>${escapeHtml(d.reason || "")}</td>
      </tr>
    `).join("");
    if (decisions.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" class="muted" style="text-align:center;padding:24px">
        Nenhuma decisão para os filtros atuais.
      </td></tr>`;
    }
  } catch (err) {
    console.error(err);
  }
}

// ---------- STATUS ----------

function bindStatus() {
  document.getElementById("test-submit").addEventListener("click", runTest);
  document.getElementById("test-host").addEventListener("keydown", e => {
    if (e.key === "Enter") runTest();
  });
}

function startStatusAuto() {
  stopStatusAuto();
  state.statusTimer = setInterval(refreshStatus, 5000);
}

function stopStatusAuto() {
  if (state.statusTimer) {
    clearInterval(state.statusTimer);
    state.statusTimer = null;
  }
}

async function refreshStatus() {
  try {
    const s = await api("/api/status");
    document.getElementById("s-proxy").textContent     = s.proxy_addr;
    document.getElementById("s-admin").textContent     = s.admin_addr;
    document.getElementById("s-whitelist").textContent = s.whitelist_path;
    document.getElementById("s-rules").textContent     = s.rule_count;
    document.getElementById("s-started").textContent   = formatTime(s.started_at);
    document.getElementById("s-uptime").textContent    = formatUptime(s.uptime_seconds);
    document.getElementById("s-allow").textContent     = s.allow_count;
    document.getElementById("s-block").textContent     = s.block_count;
    setStatusPill("ok", "online");
  } catch (err) {
    setStatusPill("err", "offline");
  }
}

async function runTest() {
  const host = document.getElementById("test-host").value.trim();
  if (!host) return;
  const result = document.getElementById("test-result");
  try {
    const data = await api("/api/test?host=" + encodeURIComponent(host), { method: "POST" });
    result.hidden = false;
    result.className = "test-result " + (data.allowed ? "allow" : "block");
    result.textContent = data.allowed
      ? `✓ "${data.host}" seria PERMITIDO`
      : `✕ "${data.host}" seria BLOQUEADO`;
  } catch (err) {
    result.hidden = false;
    result.className = "test-result block";
    result.textContent = "Erro: " + err.message;
  }
}

// ---------- helpers ----------

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
}

function escapeAttr(s) { return escapeHtml(s); }

function formatTime(t) {
  if (!t) return "";
  const d = new Date(t);
  if (isNaN(d.getTime())) return t;
  return d.toLocaleString();
}

function formatUptime(sec) {
  if (sec == null) return "—";
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = sec % 60;
  if (d > 0) return `${d}d ${h}h ${m}m`;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

function debounce(fn, ms) {
  let t;
  return (...args) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...args), ms);
  };
}

function toast(msg) {
  // Toast simples — usa o status pill como canal de feedback temporário.
  const el = document.getElementById("status-pill");
  const oldText = el.textContent, oldClass = el.className;
  el.className = "pill pill-ok";
  el.textContent = msg;
  setTimeout(() => {
    el.className = oldClass;
    el.textContent = oldText;
  }, 1800);
}
