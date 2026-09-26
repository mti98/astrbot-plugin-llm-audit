const bridge = window.AstrBotPluginPage;
const $ = (selector) => document.querySelector(selector);

function showNotice(message, isError = false) {
  const notice = $("#notice");
  notice.textContent = message;
  notice.classList.toggle("error", isError);
  notice.hidden = !message;
}

function cell(text, className = "") {
  const td = document.createElement("td");
  td.textContent = text || "—";
  if (className) td.className = className;
  return td;
}

function accountCell(name, id) {
  const td = document.createElement("td");
  const primary = document.createElement("div");
  primary.className = "account";
  primary.textContent = name || id || "未知账号";
  const secondary = document.createElement("div");
  secondary.className = "subline";
  secondary.textContent = id || "";
  td.append(primary, secondary);
  return td;
}

function renderScores(items) {
  const body = $("#scores-body");
  body.replaceChildren();
  $("#scores-empty").hidden = items.length > 0;
  for (const item of items) {
    const row = document.createElement("tr");
    row.append(accountCell(item.sender_name, item.user_id));
    row.append(cell(`${item.platform || "—"}${item.group_id ? ` / ${item.group_id}` : " / 私聊"}`));
    const score = document.createElement("td");
    const pill = document.createElement("span");
    pill.className = "score-pill";
    pill.textContent = `${item.score} 分`;
    score.append(pill);
    row.append(score);
    const hitText = Array.isArray(item.hits)
      ? item.hits.map((hit) => `${hit.word || ""}（${hit.score || 0}）`).join("、")
      : "";
    row.append(cell(hitText));
    row.append(cell(item.reset_at));
    body.append(row);
  }
}

function renderBlocked(items) {
  const body = $("#blocked-body");
  body.replaceChildren();
  $("#blocked-empty").hidden = items.length > 0;
  for (const item of items) {
    const row = document.createElement("tr");
    row.append(accountCell(item.sender_name, item.user_id));
    const scope = item.ban_scope === "global"
      ? "全局"
      : item.ban_scope === "private"
        ? "私聊"
        : `群 ${item.group_id || "—"}`;
    row.append(cell(scope));
    row.append(cell(item.reason));
    row.append(cell(String(item.strike_count || 0)));
    const status = document.createElement("td");
    const pill = document.createElement("span");
    pill.className = `status-pill${item.permanent ? " permanent" : ""}`;
    pill.textContent = item.permanent ? "永久封禁" : `至 ${item.blocked_until || "—"}`;
    status.append(pill);
    row.append(status);
    const action = document.createElement("td");
    const button = document.createElement("button");
    button.className = "button danger-button";
    button.type = "button";
    button.textContent = "解除封禁";
    button.addEventListener("click", () => unban(item.user_key, item.sender_name || item.user_id));
    action.append(button);
    row.append(action);
    body.append(row);
  }
}

async function loadDashboard() {
  const result = await bridge.apiGet("dashboard");
  renderScores(result.scores || []);
  renderBlocked(result.blocked || []);
  $("#score-count").textContent = String(result.score_count ?? 0);
  $("#blocked-count").textContent = String(result.blocked_count ?? 0);
  $("#updated-at").textContent = result.updated_at || "—";
}

async function unban(userKey, label) {
  if (!window.confirm(`要解除「${label}」的封禁吗？`)) return;
  try {
    await bridge.apiPost("unban", { user_key: userKey });
    showNotice("封禁已解除，风险积分已按配置恢复。");
    await loadDashboard();
  } catch (error) {
    showNotice(error.message || "解除封禁失败。", true);
  }
}

function makeField(field) {
  const wrapper = document.createElement("div");
  wrapper.className = "field";
  const isWide = ["text", "custom_keywords"].includes(field.type) || ["audit_prompt", "blocked_notice", "custom_keywords"].includes(field.key);
  if (isWide) wrapper.classList.add("wide");

  if (field.type === "bool") {
    const label = document.createElement("label");
    label.className = "check-row";
    const input = document.createElement("input");
    input.type = "checkbox";
    input.checked = Boolean(field.value);
    input.dataset.key = field.key;
    input.dataset.type = "bool";
    const text = document.createElement("span");
    text.textContent = field.label;
    label.append(input, text);
    wrapper.append(label);
  } else {
    const label = document.createElement("label");
    label.htmlFor = `setting-${field.key}`;
    label.textContent = field.label;
    wrapper.append(label);
    if (field.hint) {
      const hint = document.createElement("p");
      hint.className = "field-hint";
      hint.textContent = field.hint;
      wrapper.append(hint);
    }

    let input;
    if (field.options?.length) {
      input = document.createElement("select");
      field.options.forEach((option, index) => {
        const choice = document.createElement("option");
        choice.value = option;
        choice.textContent = field.labels?.[index] || option;
        input.append(choice);
      });
      input.value = field.value ?? field.default ?? "";
    } else if (["text", "audit_prompt", "custom_keywords", "blocked_notice"].includes(field.type) || field.key === "custom_keywords") {
      input = document.createElement("textarea");
      input.value = field.value ?? field.default ?? "";
      if (field.key === "audit_prompt") input.classList.add("prompt");
    } else {
      input = document.createElement("input");
      input.type = field.type === "int" || field.type === "float" ? "number" : "text";
      if (field.type === "int") input.step = "1";
      if (field.type === "float") input.step = "0.1";
      input.value = field.value ?? field.default ?? "";
    }
    input.id = `setting-${field.key}`;
    input.dataset.key = field.key;
    input.dataset.type = field.type;
    wrapper.append(input);
  }
  return wrapper;
}

async function loadSettings() {
  const result = await bridge.apiGet("settings");
  const form = $("#settings-form");
  form.replaceChildren(...(result.fields || []).map(makeField));
  $("#settings-status").textContent = "";
}

async function saveSettings(event) {
  event.preventDefault();
  const button = $("#save-settings");
  button.disabled = true;
  $("#settings-status").textContent = "正在保存…";
  const settings = {};
  for (const input of $("#settings-form").querySelectorAll("[data-key]")) {
    const type = input.dataset.type;
    let value = type === "bool" ? input.checked : input.value;
    if (type === "int") value = Number.parseInt(value, 10);
    if (type === "float") value = Number.parseFloat(value);
    settings[input.dataset.key] = value;
  }
  try {
    const result = await bridge.apiPost("settings/save", { settings });
    $("#settings-status").textContent = result.message || "配置已保存。";
    showNotice("配置已保存并生效。");
    await loadSettings();
  } catch (error) {
    $("#settings-status").textContent = "保存失败";
    showNotice(error.message || "配置保存失败。", true);
  } finally {
    button.disabled = false;
  }
}

async function refresh() {
  showNotice("");
  try {
    await Promise.all([loadDashboard(), loadSettings()]);
  } catch (error) {
    showNotice(error.message || "读取插件数据失败，请确认 AstrBot 插件页 API 可用。", true);
  }
}

await bridge.ready();
document.title = bridge.t("pages.blacklist.title", "LLM 内容审核插件");
$("#refresh").addEventListener("click", refresh);
$("#settings-form").addEventListener("submit", saveSettings);
document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((item) => item.classList.toggle("active", item === tab));
    document.querySelectorAll(".tab-panel").forEach((panel) => {
      panel.hidden = panel.id !== tab.dataset.tab;
    });
  });
});
await refresh();
