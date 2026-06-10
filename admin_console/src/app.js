import { LANGUAGES, directionFor, getLanguage, setLanguage, t } from "./i18n.js";

const CONFIG_KEY = "novasentinel.admin.config";

const state = {
  language: getLanguage(),
  view: "overview",
  config: loadConfig(),
  cloud: {
    ok: false,
    message: ""
  },
  script: "",
  toast: ""
};

function loadConfig() {
  try {
    const parsed = JSON.parse(window.localStorage.getItem(CONFIG_KEY) || "{}");
  return {
      cloudUrl: typeof parsed.cloudUrl === "string" ? parsed.cloudUrl : "",
      organizationKey: typeof parsed.organizationKey === "string" ? parsed.organizationKey : "",
      installerUrl: typeof parsed.installerUrl === "string" ? parsed.installerUrl : "",
      installerSha256: typeof parsed.installerSha256 === "string" ? parsed.installerSha256 : "",
      groupName: typeof parsed.groupName === "string" ? parsed.groupName : "default",
      deploymentMode: typeof parsed.deploymentMode === "string" ? parsed.deploymentMode : "install"
    };
  } catch {
    return {
      cloudUrl: "",
      organizationKey: "",
      installerUrl: "",
      installerSha256: "",
      groupName: "default",
      deploymentMode: "install"
    };
  }
}

function validSha256(value) {
  return /^[a-fA-F0-9]{64}$/.test(String(value || "").trim());
}

function saveConfig() {
  window.localStorage.setItem(CONFIG_KEY, JSON.stringify(state.config));
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function fileSafeName(value) {
  return String(value || "default").replace(/[^a-z0-9._-]+/gi, "-").replace(/^-+|-+$/g, "") || "default";
}

function isHttpUrl(value) {
  try {
    const parsed = new URL(value);
    return parsed.protocol === "https:" || parsed.protocol === "http:";
  } catch {
    return false;
  }
}

function hasDeploymentConfig() {
  return Boolean(
    state.config.cloudUrl
      && state.config.organizationKey
      && state.config.installerUrl
      && validSha256(state.config.installerSha256)
      && isHttpUrl(state.config.cloudUrl)
      && isHttpUrl(state.config.installerUrl)
  );
}

function downloadText(filename, text, type) {
  const blob = new Blob([text], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function packagePayload() {
  return {
    product: "NovaSentinel",
    package_type: "premium_mass_deployment",
    cloud_url: state.config.cloudUrl,
    premium_key: state.config.organizationKey,
    installer_url: state.config.installerUrl,
    installer_sha256: state.config.installerSha256,
    deployment_group: state.config.groupName || "default",
    deployment_mode: state.config.deploymentMode || "install",
    generated_at: new Date().toISOString()
  };
}

function deploymentScript() {
  if (!hasDeploymentConfig()) {
    return "";
  }

  const payload = JSON.stringify(packagePayload(), null, 2);
  const shouldInstall = state.config.deploymentMode !== "config";
  const shouldUpdate = state.config.deploymentMode === "update";
  const download = [
    `$cloudUrl = '${state.config.cloudUrl.replaceAll("'", "''")}'`,
    `$premiumKey = '${state.config.organizationKey.replaceAll("'", "''")}'`,
    `$installerUrl = '${state.config.installerUrl.replaceAll("'", "''")}'`,
    `$installerSha256 = '${state.config.installerSha256.toLowerCase().trim()}'`,
    `$deploymentMode = '${state.config.deploymentMode || "install"}'`,
    `$deploymentGroup = '${state.config.groupName.replaceAll("'", "''")}'`,
  ];

  return [
    "$ErrorActionPreference = 'Stop'",
    "$ProgressPreference = 'SilentlyContinue'",
    "if (!$PSVersionTable.PSVersion) { Write-Error 'PowerShell Core requis.'; exit 1 }",
    ...download,
    "$target = Join-Path $env:ProgramData 'NovaSentinel'",
    "New-Item -ItemType Directory -Force -Path $target | Out-Null",
    "$configPath = Join-Path $target 'premium_deployment.json'",
    "@'",
    payload,
    "'@ | Set-Content -LiteralPath $configPath -Encoding UTF8",
    shouldInstall ? "$installer = Join-Path $env:TEMP 'NovaSentinel-Setup.exe'" : "# Preconfiguration mode: installer download skipped.",
    shouldInstall ? "$expectedSha256 = $InstallerSha256.ToLower()" : "",
    shouldInstall ? "Invoke-WebRequest -Uri $installerUrl -OutFile $installer -UseBasicParsing" : "",
    shouldInstall ? "$actualSha256 = (Get-FileHash -Path $installer -Algorithm SHA256).Hash.ToLower()" : "",
    shouldInstall ? "if ($actualSha256 -ne $expectedSha256) { Write-Error ('Empreinte SHA-256 invalide: ' + $actualSha256 + ' != ' + $expectedSha256); exit 1 }" : "",
    shouldInstall ? `$arguments = '/quiet /norestart /premium-config=\"' + $configPath + '\"${shouldUpdate ? " /update" : ""}'` : "",
    shouldInstall ? "Start-Process -FilePath $installer -ArgumentList $arguments -Wait -WindowStyle Hidden" : "",
    "Write-Host 'NovaSentinel Premium deployment prepared.'"
  ].filter(Boolean).join("\n");
}

function navItem(view, label) {
  const active = state.view === view ? "is-active" : "";
  return `<button class="nav-item ${active}" data-view="${view}" type="button">${escapeHtml(label)}</button>`;
}

function statusPill(ok, labelOk, labelKo) {
  return `<span class="status-pill ${ok ? "is-ok" : "is-muted"}">${escapeHtml(ok ? labelOk : labelKo)}</span>`;
}

function renderLanguageSelector() {
  const options = LANGUAGES.map((language) => {
    const selected = language.code === state.language ? " selected" : "";
    return `<option value="${language.code}"${selected}>${escapeHtml(language.label)}</option>`;
  }).join("");
  return `
    <label class="language-select">
      <span>${escapeHtml(t("language", state.language))}</span>
      <select data-action="language">${options}</select>
    </label>
  `;
}

function renderShell() {
  document.documentElement.lang = state.language;
  document.documentElement.dir = directionFor(state.language);

  const app = document.querySelector("#app");
  app.innerHTML = `
    <aside class="sidebar">
      <div class="brand-block">
        <div class="brand-mark">NS</div>
        <div>
          <h1>${escapeHtml(t("appName", state.language))}</h1>
          <p>${escapeHtml(t("appSubtitle", state.language))}</p>
        </div>
      </div>
      <nav class="side-nav" aria-label="Admin Console">
        ${navItem("overview", t("overview", state.language))}
        ${navItem("deployment", t("deployment", state.language))}
        ${navItem("licenses", t("licenses", state.language))}
        ${navItem("packages", t("packages", state.language))}
        ${navItem("settings", t("settings", state.language))}
      </nav>
    </aside>
    <main class="main-panel">
      <header class="topbar">
        <div class="status-line">
          ${statusPill(true, t("localReady", state.language), t("localReady", state.language))}
          ${statusPill(state.cloud.ok, t("connected", state.language), t("disconnected", state.language))}
        </div>
        ${renderLanguageSelector()}
      </header>
      <section class="content-area">${renderView()}</section>
      ${state.toast ? `<div class="toast" role="status">${escapeHtml(state.toast)}</div>` : ""}
    </main>
  `;
}

function renderView() {
  if (state.view === "deployment") {
    return renderDeployment();
  }
  if (state.view === "licenses") {
    return renderLicenses();
  }
  if (state.view === "packages") {
    return renderPackages();
  }
  if (state.view === "settings") {
    return renderSettings();
  }
  return renderOverview();
}

function renderOverview() {
  return `
    <div class="hero-strip">
      <div>
        <p>${escapeHtml(t("readiness", state.language))}</p>
        <h2>${escapeHtml(t("appSubtitle", state.language))}</h2>
      </div>
      <button class="primary-button" data-view="deployment" type="button">${escapeHtml(t("prepareDeployment", state.language))}</button>
    </div>
    <div class="metrics-grid">
      ${metric(t("cloudConnection", state.language), state.cloud.ok ? t("connected", state.language) : t("disconnected", state.language), state.cloud.message || t("testConnection", state.language))}
      ${metric(t("organizationKey", state.language), state.config.organizationKey ? t("configured", state.language) : t("notConfigured", state.language), t("premiumOnly", state.language))}
      ${metric(t("installerUrl", state.language), state.config.installerUrl ? t("configured", state.language) : t("notConfigured", state.language), t("massDeployment", state.language))}
    </div>
    <section class="action-board">
      <button class="action-tile" data-view="settings" type="button">
        <strong>${escapeHtml(t("configureCloud", state.language))}</strong>
        <span>${escapeHtml(t("cloudConnection", state.language))}</span>
      </button>
      <button class="action-tile" data-view="deployment" type="button">
        <strong>${escapeHtml(t("prepareDeployment", state.language))}</strong>
        <span>${escapeHtml(t("noDestructiveAction", state.language))}</span>
      </button>
      <button class="action-tile" data-view="licenses" type="button">
        <strong>${escapeHtml(t("manageLicenses", state.language))}</strong>
        <span>${escapeHtml(t("endpointRequired", state.language))}</span>
      </button>
    </section>
  `;
}

function metric(label, value, detail) {
  return `
    <article class="metric-panel">
      <span>${escapeHtml(label)}</span>
      <strong>${escapeHtml(value)}</strong>
      <small>${escapeHtml(detail)}</small>
    </article>
  `;
}

function renderDeployment() {
  return `
    <div class="page-heading">
      <div>
        <h2>${escapeHtml(t("massDeployment", state.language))}</h2>
        <p>${escapeHtml(t("deploymentText", state.language))}</p>
      </div>
      <button class="ghost-button" data-action="generate-script" type="button">${escapeHtml(t("generateScript", state.language))}</button>
    </div>
    ${renderConfigForm("deployment")}
    <section class="wide-panel">
      <div class="panel-heading">
        <h3>${escapeHtml(t("generateScript", state.language))}</h3>
        <span class="quiet">${escapeHtml(t("noDestructiveAction", state.language))}</span>
      </div>
      ${state.script
        ? `<pre class="script-box"><code>${escapeHtml(state.script)}</code></pre>`
        : `<div class="empty-state">${escapeHtml(t("missingDeploymentConfig", state.language))}</div>`}
      <div class="button-row">
        <button class="primary-button" data-action="copy-script" type="button" ${state.script ? "" : "disabled"}>${escapeHtml(t("copyScript", state.language))}</button>
        <button class="secondary-button" data-action="download-script" type="button" ${state.script ? "" : "disabled"}>${escapeHtml(t("downloadScript", state.language))}</button>
      </div>
    </section>
  `;
}

function renderLicenses() {
  return `
    <div class="page-heading">
      <div>
        <h2>${escapeHtml(t("licenseOperations", state.language))}</h2>
        <p>${escapeHtml(t("premiumOnlyText", state.language))}</p>
      </div>
      <button class="ghost-button" data-action="test-cloud" type="button">${escapeHtml(t("refresh", state.language))}</button>
    </div>
    <section class="wide-panel split-panel">
      <div>
        <h3>${escapeHtml(t("licensePool", state.language))}</h3>
        <div class="empty-state compact">
          <strong>${escapeHtml(t("noLicenseData", state.language))}</strong>
          <span>${escapeHtml(t("endpointRequired", state.language))}</span>
        </div>
      </div>
      <div>
        <h3>${escapeHtml(t("quickActions", state.language))}</h3>
        <div class="stacked-actions">
          <button class="secondary-button" data-action="copy-key" type="button" ${state.config.organizationKey ? "" : "disabled"}>${escapeHtml(t("copyKey", state.language))}</button>
          <button class="secondary-button" data-action="download-csv" type="button">${escapeHtml(t("downloadCsv", state.language))}</button>
        </div>
      </div>
    </section>
  `;
}

function renderPackages() {
  const ready = state.config.cloudUrl && state.config.organizationKey && isHttpUrl(state.config.cloudUrl);
  return `
    <div class="page-heading">
      <div>
        <h2>${escapeHtml(t("packageBuilder", state.language))}</h2>
        <p>${escapeHtml(t("packageText", state.language))}</p>
      </div>
      <button class="primary-button" data-action="download-config" type="button" ${ready ? "" : "disabled"}>${escapeHtml(t("downloadConfig", state.language))}</button>
    </div>
    <section class="wide-panel">
      <pre class="script-box"><code>${escapeHtml(JSON.stringify(packagePayload(), null, 2))}</code></pre>
    </section>
  `;
}

function renderSettings() {
  return `
    <div class="page-heading">
      <div>
        <h2>${escapeHtml(t("settings", state.language))}</h2>
        <p>${escapeHtml(t("cloudConnectionText", state.language))}</p>
      </div>
      <button class="ghost-button" data-action="test-cloud" type="button">${escapeHtml(t("testConnection", state.language))}</button>
    </div>
    ${renderConfigForm("settings")}
    <section class="wide-panel">
      <h3>${escapeHtml(t("premiumOnly", state.language))}</h3>
      <p>${escapeHtml(t("premiumOnlyText", state.language))}</p>
    </section>
  `;
}

function renderConfigForm(scope) {
  return `
    <section class="wide-panel">
      <form class="config-form ${scope === "deployment" ? "is-wide" : ""}" data-action="save-config">
        ${field("cloudUrl", "url", t("cloudUrl", state.language), "http://127.0.0.1:8780")}
        ${field("organizationKey", "text", t("organizationKey", state.language), "NSP-PREMIUM-...")}
        ${field("installerUrl", "url", t("installerUrl", state.language), "https://github.com/.../NovaSentinel-Setup.exe")}
        ${field("installerSha256", "text", t("installerSha256", state.language), "e3b0c44298fc1c149...")}
        ${field("groupName", "text", t("groupName", state.language), "HQ-Windows")}
        <label>
          <span>${escapeHtml(t("deploymentMode", state.language))}</span>
          <select name="deploymentMode">
            ${modeOption("install", "deploymentModeInstall")}
            ${modeOption("update", "deploymentModeUpdate")}
            ${modeOption("config", "deploymentModeConfig")}
          </select>
        </label>
        <div class="button-row">
          <button class="primary-button" type="submit">${escapeHtml(t("save", state.language))}</button>
          <button class="secondary-button" data-action="test-cloud" type="button">${escapeHtml(t("testConnection", state.language))}</button>
        </div>
      </form>
    </section>
  `;
}

function field(name, type, label, placeholder) {
  return `
    <label>
      <span>${escapeHtml(label)}</span>
      <input name="${escapeHtml(name)}" type="${escapeHtml(type)}" value="${escapeHtml(state.config[name])}" placeholder="${escapeHtml(placeholder)}" autocomplete="off" />
    </label>
  `;
}

function modeOption(value, labelKey) {
  const selected = state.config.deploymentMode === value ? " selected" : "";
  return `<option value="${value}"${selected}>${escapeHtml(t(labelKey, state.language))}</option>`;
}

function showToast(message) {
  state.toast = message;
  renderShell();
  window.setTimeout(() => {
    state.toast = "";
    renderShell();
  }, 2400);
}

function updateConfigFromForm(form) {
  const formData = new FormData(form);
  state.config.cloudUrl = String(formData.get("cloudUrl") || "").trim().replace(/\/+$/, "");
  state.config.organizationKey = String(formData.get("organizationKey") || "").trim();
  state.config.installerUrl = String(formData.get("installerUrl") || "").trim();
  state.config.installerSha256 = String(formData.get("installerSha256") || "").trim();
  state.config.groupName = String(formData.get("groupName") || "").trim() || "default";
  state.config.deploymentMode = String(formData.get("deploymentMode") || "install");
  saveConfig();
}

async function testCloudConnection() {
  if (!state.config.cloudUrl || !isHttpUrl(state.config.cloudUrl)) {
    state.cloud.ok = false;
    state.cloud.message = t("connectionFailed", state.language);
    showToast(state.cloud.message);
    return;
  }
  try {
    const response = await fetch(`/api/cloud/health?url=${encodeURIComponent(state.config.cloudUrl)}`);
    const result = await response.json();
    state.cloud.ok = Boolean(result.ok);
    state.cloud.message = result.ok ? t("connectionOk", state.language) : t("connectionFailed", state.language);
    showToast(state.cloud.message);
  } catch {
    state.cloud.ok = false;
    state.cloud.message = t("connectionFailed", state.language);
    showToast(state.cloud.message);
  }
}

function generateScript() {
  state.script = deploymentScript();
  showToast(state.script ? t("scriptReady", state.language) : t("missingDeploymentConfig", state.language));
}

async function copyTextOrDownload(text, fallbackFilename, successKey, fallbackKey) {
  try {
    await navigator.clipboard.writeText(text);
    showToast(t(successKey, state.language));
  } catch {
    downloadText(fallbackFilename, text, "text/plain;charset=utf-8");
    showToast(t(fallbackKey, state.language));
  }
}

function downloadDeploymentScript() {
  if (!state.script) {
    return;
  }
  const filename = `NovaSentinel-${fileSafeName(state.config.groupName)}-deploy.ps1`;
  downloadText(filename, state.script, "text/plain;charset=utf-8");
  showToast(t("scriptDownloaded", state.language));
}

function downloadConfigPackage() {
  const filename = `NovaSentinel-${fileSafeName(state.config.groupName)}-premium-config.json`;
  downloadText(filename, JSON.stringify(packagePayload(), null, 2), "application/json;charset=utf-8");
  showToast(t("packageReady", state.language));
}

function downloadCsvTemplate() {
  const csv = "device_name,assigned_user,email,notes\n";
  downloadText("NovaSentinel-license-import-template.csv", csv, "text/csv;charset=utf-8");
  showToast(t("csvDownloaded", state.language));
}

function bindEvents() {
  document.addEventListener("click", async (event) => {
    const target = event.target.closest("[data-view], [data-action]");
    if (!target) {
      return;
    }

    if (target.dataset.view) {
      state.view = target.dataset.view;
      renderShell();
      return;
    }

    if (target.dataset.action === "test-cloud") {
      await testCloudConnection();
      return;
    }

    if (target.dataset.action === "generate-script") {
      generateScript();
      return;
    }

    if (target.dataset.action === "copy-script" && state.script) {
      await copyTextOrDownload(state.script, `NovaSentinel-${fileSafeName(state.config.groupName)}-deploy.ps1`, "scriptCopied", "scriptDownloaded");
      return;
    }

    if (target.dataset.action === "download-script") {
      downloadDeploymentScript();
      return;
    }

    if (target.dataset.action === "download-config") {
      downloadConfigPackage();
      return;
    }

    if (target.dataset.action === "download-csv") {
      downloadCsvTemplate();
      return;
    }

    if (target.dataset.action === "copy-key" && state.config.organizationKey) {
      await copyTextOrDownload(state.config.organizationKey, "NovaSentinel-premium-key.txt", "keyCopied", "packageReady");
    }
  });

  document.addEventListener("change", (event) => {
    if (event.target.matches("[data-action='language']")) {
      state.language = setLanguage(event.target.value);
      renderShell();
    }
  });

  document.addEventListener("submit", (event) => {
    const form = event.target.closest("[data-action='save-config']");
    if (!form) {
      return;
    }
    event.preventDefault();
    updateConfigFromForm(form);
    state.script = "";
    showToast(t("saved", state.language));
  });
}

bindEvents();
renderShell();
