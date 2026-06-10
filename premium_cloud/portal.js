const premiumSeatPrice = 12;

let loginChallengeId = "";
let csrfToken = "";

function qs(selector, root = document) {
  return root.querySelector(selector);
}

function qsa(selector, root = document) {
  return Array.from(root.querySelectorAll(selector));
}

function showPanel(target) {
  qsa(".superadmin-tab").forEach((tab) => {
    tab.classList.toggle("active", tab.dataset.panel === target);
  });
  qsa(".superadmin-panel").forEach((panel) => {
    panel.classList.toggle("active", panel.dataset.panel === target);
  });
}

function showAuthMode(target) {
  qsa("[data-auth-mode]").forEach((button) => {
    button.classList.toggle("active", button.dataset.authMode === target);
  });
  qsa("[data-auth-panel]").forEach((panel) => {
    panel.classList.toggle("active", panel.dataset.authPanel === target);
  });
}

qsa(".superadmin-tab").forEach((tab) => {
  tab.addEventListener("click", () => showPanel(tab.dataset.panel));
});

qsa("[data-auth-mode]").forEach((button) => {
  button.addEventListener("click", () => showAuthMode(button.dataset.authMode));
});

async function api(path, options = {}) {
  const method = String(options.method || "GET").toUpperCase();
  if (method !== "GET" && !csrfToken && path !== "/api/login" && path !== "/api/login/verify" && path !== "/api/organizations/claim" && path !== "/api/setup/superadmin" && path !== "/api/checkout/sessions") {
    await loadCsrfToken();
  }
  const response = await fetch(path, {
    credentials: "same-origin",
    headers: {
      Accept: "application/json",
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...(csrfToken && method !== "GET" ? { "X-CSRF-Token": csrfToken } : {}),
      ...(options.headers || {}),
    },
    ...options,
    body: options.body ? JSON.stringify(options.body) : undefined,
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(payload.message || payload.error || `HTTP ${response.status}`);
    error.status = response.status;
    error.payload = payload;
    throw error;
  }
  if (payload.csrf_token) csrfToken = payload.csrf_token;
  return payload;
}

async function loadCsrfToken() {
  const response = await fetch("/api/session", {
    credentials: "same-origin",
    headers: { Accept: "application/json" },
  });
  const payload = await response.json().catch(() => ({}));
  csrfToken = payload.csrf_token || csrfToken;
  return csrfToken;
}

function setText(selector, value) {
  const node = qs(selector);
  if (node) node.textContent = value ?? "";
}

function safeLocalPath(value, fallback = "/") {
  const candidate = String(value || "").trim();
  if (!candidate || !candidate.startsWith("/")) {
    return fallback;
  }
  if (candidate.startsWith("//")) {
    return fallback;
  }
  if (candidate.includes("..") || candidate.includes("\\") || candidate.includes("\0")) {
    return fallback;
  }
  return candidate;
}

function safeHref(value, fallback = "") {
  try {
    const parsed = new URL(value, window.location.origin);
    if (!["http:", "https:"].includes(parsed.protocol)) return fallback;
    return parsed.toString();
  } catch {
    return fallback;
  }
}

function statusBox(selector, message, variant = "info", action) {
  const node = qs(selector);
  if (!node) return;
  node.dataset.variant = variant;
  node.innerHTML = "";
  const text = document.createElement("span");
  text.textContent = message;
  node.append(text);
  if (action) {
    const link = document.createElement("a");
    link.className = "state-action";
    link.href = action.href;
    link.textContent = action.label;
    node.append(link);
  }
}

function humanError(error) {
  const code = error.payload?.error || "";
  const message = error.message || "";
  const map = {
    invalid_credentials: "Email ou mot de passe incorrect.",
    invalid_mfa: "Code 2FA incorrect. Vérifiez votre application TOTP.",
    challenge_expired: "La vérification 2FA a expiré. Recommencez la connexion.",
    license_not_found: "Clé Premium introuvable ou inactive.",
    billing_email_required: "L'email doit être l'email de facturation de la licence.",
    weak_password: "Le mot de passe doit contenir au moins 14 caractères.",
    password_policy: "Le mot de passe doit contenir au moins 14 caractères, une minuscule, une majuscule, un chiffre et un symbole.",
    organization_already_claimed: "Cette organisation a déjà un compte client.",
    invalid_bootstrap_token: "Token bootstrap incorrect.",
    bootstrap_unavailable: "Le bootstrap est désactivé car un superadmin existe déjà ou le token serveur manque.",
    invalid_checkout_payload: "Organisation, email et nombre de postes sont requis.",
    invalid_license_issue_payload: "Organisation, email et nombre de postes sont requis.",
    license_inactive_or_unknown: "Licence inactive ou inconnue.",
    seat_limit_reached: "Tous les postes de cette licence sont déjà utilisés.",
    installer_required: "Ajoutez un installateur .exe ou une URL externe avant de publier.",
    sha256_required: "Le SHA-256 est requis pour publier une URL externe. Utilisez la récupération GitHub ou uploadez l'installateur.",
    installer_invalid_file_type: "Le fichier d'installation doit avoir l'extension .exe.",
    installer_too_large: "Le fichier d'installation est trop volumineux.",
    invalid_json: "La requête envoyée est mal formée. Rechargez la page puis réessayez.",
    version_required: "Indiquez le numéro de version à publier.",
    invalid_release_channel: "Choisissez le canal stable ou beta.",
    github_release_url_invalid: "Collez l'URL de téléchargement d'un asset GitHub Release.",
    rate_limited: "Trop de tentatives. Réessayez dans quelques minutes.",
    temporarily_locked: "Accès temporairement verrouillé après trop d'échecs.",
    invalid_csrf: "Session expirée ou formulaire invalide. Rechargez la page puis réessayez.",
  };
  if (map[code]) return map[code];
  if (message.includes("STRIPE_SECRET_KEY")) return "Stripe n'est pas configuré sur ce serveur local. Ajoutez STRIPE_SECRET_KEY pour créer une vraie session Checkout.";
  if (message.includes("PREMIUM_ED25519_PRIVATE_KEY_PEM")) return "La clé de signature Premium n'est pas configurée côté serveur.";
  if (error.status === 401) return "Session requise. Connectez-vous pour accéder à cette page.";
  if (error.status === 403) return "Action refusée pour ce rôle.";
  return message || "Une erreur inattendue est survenue.";
}

function redirectToLogin() {
  window.location.href = `/login/?next=${encodeURIComponent(window.location.pathname)}`;
}

function nextUrl(fallback) {
  const next = new URLSearchParams(window.location.search).get("next");
  return safeLocalPath(next || "", fallback);
}

function setBusy(form, busy, label = "Traitement...") {
  if (!form) return;
  const submit = form.querySelector("button[type='submit']");
  if (!submit) return;
  if (busy) {
    submit.dataset.previousText = submit.textContent;
    submit.textContent = label;
    submit.disabled = true;
  } else {
    submit.textContent = submit.dataset.previousText || submit.textContent;
    submit.disabled = false;
  }
}

function money(value) {
  return `${Number(value || 0).toLocaleString("fr-FR")} EUR`;
}

function bytes(value) {
  const size = Number(value || 0);
  if (!size) return "n/a";
  if (size < 1024 * 1024) return `${Math.round(size / 1024)} Ko`;
  return `${(size / 1024 / 1024).toFixed(1)} Mo`;
}

function isGithubReleaseAssetUrl(value) {
  try {
    const url = new URL(value);
    const parts = url.pathname.split("/").filter(Boolean);
    return url.protocol === "https:" && url.hostname === "github.com" && parts[2] === "releases" && parts[3] === "download" && parts.length >= 6;
  } catch {
    return false;
  }
}

function renderRows(selector, rows, emptyText = "Aucune donnée") {
  const node = qs(selector);
  if (!node) return;
  node.innerHTML = "";
  if (!rows.length) {
    const empty = document.createElement("div");
    empty.className = "empty-row";
    empty.textContent = emptyText;
    node.append(empty);
    return;
  }
  rows.forEach((row) => node.append(row));
}

function renderSecret(selector, title, secret, otpauth, qrDataUrl) {
  const node = qs(selector);
  if (!node) return;
  node.innerHTML = "";
  node.dataset.variant = "success";
  const heading = document.createElement("strong");
  heading.textContent = title;
  const feedback = document.createElement("small");
  feedback.className = "copy-feedback";

  node.append(heading);

  if (qrDataUrl) {
    const card = document.createElement("div");
    card.className = "mfa-qr-card";
    const image = document.createElement("img");
    image.src = qrDataUrl;
    image.alt = "QR code 2FA NovaSentinel";
    const copy = document.createElement("div");
    const titleNode = document.createElement("strong");
    titleNode.textContent = "Scannez ce QR code avec votre application 2FA";
    const help = document.createElement("span");
    help.textContent = "Ouvrez Google Authenticator, Microsoft Authenticator, 1Password ou équivalent, puis ajoutez un compte par QR code.";
    copy.append(titleNode, help);
    card.append(image, copy);
    node.append(card);
  }

  const fallback = document.createElement("details");
  fallback.className = "mfa-manual-key";
  const summary = document.createElement("summary");
  summary.textContent = qrDataUrl ? "Afficher la clé manuelle de secours" : "Afficher la clé 2FA";
  const secretValue = document.createElement("code");
  secretValue.textContent = secret;
  const copySecret = document.createElement("button");
  copySecret.type = "button";
  copySecret.textContent = "Copier la clé";
  copySecret.addEventListener("click", async () => {
    feedback.textContent = (await copySilently(secret)) ? "Clé copiée." : "Copie impossible, sélectionnez le texte.";
  });
  fallback.append(summary, secretValue, copySecret);
  node.append(fallback, feedback);

  if (otpauth) {
    const uri = document.createElement("textarea");
    uri.readOnly = true;
    uri.value = otpauth;
    const copyUri = document.createElement("button");
    copyUri.type = "button";
    copyUri.textContent = "Copier l'URI TOTP";
    copyUri.addEventListener("click", async () => {
      feedback.textContent = (await copySilently(otpauth)) ? "URI TOTP copiée." : "Copie impossible, sélectionnez le texte.";
    });
    fallback.append(uri, copyUri);
  }
}

async function copyText(value, statusSelector) {
  try {
    await navigator.clipboard.writeText(value);
    statusBox(statusSelector, "Copié dans le presse-papiers.", "success");
  } catch {
    statusBox(statusSelector, "Copie automatique impossible. Sélectionnez le texte manuellement.", "error");
  }
}

async function copySilently(value) {
  try {
    await navigator.clipboard.writeText(value);
    return true;
  } catch {
    return false;
  }
}

async function hydrateSessionBanner() {
  if (!qs("[data-auth-page]")) return;
  try {
    const session = await api("/api/session");
    qs("[data-auth-mode='setup']")?.toggleAttribute("hidden", !session.bootstrap_available);
    if (session.authenticated) {
      const target = session.user?.role === "superadmin" ? "/dashboard/superadmin/" : "/dashboard/user/";
      statusBox("#loginState", `Déjà connecté en tant que ${session.user.email}.`, "success", { href: target, label: "Ouvrir le dashboard" });
    } else if (session.bootstrap_available) {
      statusBox("#loginState", "Aucun superadmin n'existe encore. Créez d'abord le compte fondateur via l'onglet Bootstrap.", "info");
    } else {
      statusBox("#loginState", "Connectez-vous ou revendiquez une licence Premium active.", "info");
    }
  } catch (error) {
    statusBox("#loginState", humanError(error), "error");
  }
}

const passwordStep = qs("#passwordStep");
const twoFactorStep = qs("#twoFactorStep");
const backToPassword = qs("#backToPassword");

passwordStep?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = new FormData(passwordStep);
  setBusy(passwordStep, true, "Vérification...");
  try {
    const result = await api("/api/login", {
      method: "POST",
      body: {
        email: data.get("email"),
        password: data.get("password"),
      },
    });
    loginChallengeId = result.challenge_id;
    passwordStep.classList.add("auth-hidden");
    twoFactorStep?.classList.remove("auth-hidden");
    qs("#twoFactorStep input[name='code']")?.focus();
    statusBox("#loginState", "Mot de passe validé. Entrez votre code 2FA.", "success");
  } catch (error) {
    statusBox("#loginState", humanError(error), "error");
  } finally {
    setBusy(passwordStep, false);
  }
});

backToPassword?.addEventListener("click", () => {
  twoFactorStep?.classList.add("auth-hidden");
  passwordStep?.classList.remove("auth-hidden");
  statusBox("#loginState", "Connexion réinitialisée. Entrez à nouveau votre mot de passe.", "info");
});

twoFactorStep?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = new FormData(twoFactorStep);
  setBusy(twoFactorStep, true, "Ouverture...");
  try {
    const result = await api("/api/login/verify", {
      method: "POST",
      body: {
        challenge_id: loginChallengeId,
        code: data.get("code"),
      },
    });
    window.location.href = nextUrl(result.redirect);
  } catch (error) {
    statusBox("#loginState", humanError(error), "error");
  } finally {
    setBusy(twoFactorStep, false);
  }
});

qs("#claimForm")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = new FormData(form);
  setBusy(form, true, "Activation...");
  try {
    const result = await api("/api/organizations/claim", {
      method: "POST",
      body: {
        license_key: data.get("license_key"),
        email: data.get("email"),
        password: data.get("password"),
      },
    });
    renderSecret(
      "#claimState",
      "Compte client créé. Configurez maintenant le 2FA sur smartphone.",
      result.mfa_secret,
      result.otpauth,
      result.mfa_qr_data_url,
    );
    form.reset();
  } catch (error) {
    statusBox("#claimState", humanError(error), "error");
  } finally {
    setBusy(form, false);
  }
});

qs("#setupSuperadminForm")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = new FormData(form);
  setBusy(form, true, "Création...");
  try {
    const result = await api("/api/setup/superadmin", {
      method: "POST",
      body: {
        email: data.get("email"),
        password: data.get("password"),
        bootstrap_token: data.get("bootstrap_token"),
      },
    });
    renderSecret("#setupState", "Superadmin créé. Configurez maintenant le 2FA.", result.mfa_secret, result.otpauth, result.mfa_qr_data_url);
    form.reset();
  } catch (error) {
    statusBox("#setupState", humanError(error), "error");
  } finally {
    setBusy(form, false);
  }
});

const subscriptionForm = qs("#subscriptionForm");
const subscribeSeats = qs("#subscribeSeats");

function renderSubscriptionSummary() {
  if (!subscribeSeats) return;
  const seats = Math.max(1, Number.parseInt(subscribeSeats.value || "1", 10));
  setText("#subscribeSeatSummary", String(seats));
  setText("#subscribePriceSummary", money(seats * premiumSeatPrice));
}

subscribeSeats?.addEventListener("input", renderSubscriptionSummary);
subscriptionForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = new FormData(subscriptionForm);
  setBusy(subscriptionForm, true, "Stripe...");
  try {
    statusBox("#checkoutState", "Création de la session Stripe...", "info");
    const result = await api("/api/checkout/sessions", {
      method: "POST",
      body: {
        org: data.get("org"),
        email: data.get("email"),
        seats: data.get("seats"),
      },
    });
    statusBox("#checkoutState", "Session Stripe créée. Redirection...", "success");
    window.location.href = result.stripe_checkout_url;
  } catch (error) {
    statusBox("#checkoutState", humanError(error), "error");
  } finally {
    setBusy(subscriptionForm, false);
  }
});

async function loadUserDashboard() {
  if (!qs("[data-dashboard='user']")) return;
  try {
    const data = await api("/api/dashboard/user");
    statusBox("#userDashboardState", "Dashboard synchronisé.", "success");
    setText("#userOrgName", data.organization?.name || "Organisation");
    setText("#userSeats", data.metrics.seats);
    setText("#userActiveSeats", data.metrics.active_seats);
    setText("#userAvailableSeats", `${data.metrics.available_seats} disponibles`);
    setText("#userLastActivation", data.metrics.last_activation);
    setText("#userUpdateChannel", data.metrics.channel);
    setText("#userAppVersion", data.metrics.version);
    renderUserLicenses(data.licenses || []);
    renderActivations(data.activations || []);
    renderDeployment(data.deployment);
  } catch (error) {
    if (error.status === 401) {
      redirectToLogin();
      return;
    }
    statusBox("#userDashboardState", humanError(error), "error", { href: "/login/", label: "Se connecter" });
  }
}

function renderUserLicenses(licenses) {
  renderRows(
    "#userLicenseRows",
    licenses.map((license) => {
      const row = document.createElement("div");
      const key = document.createElement("strong");
      const seats = document.createElement("span");
      const active = document.createElement("span");
      const status = document.createElement("mark");
      key.textContent = license.license_key || "";
      seats.textContent = `${license.seats} postes`;
      active.textContent = `${license.active_seats} actifs`;
      status.textContent = license.status || "";
      row.append(key, seats, active, status);
      return row;
    }),
    "Aucune licence active",
  );
  const copyButton = qs("#copyOrgKey");
  if (copyButton) {
    copyButton.disabled = !licenses[0];
    copyButton.onclick = async () => {
      await copyText(licenses[0].license_key, "#userDashboardState");
    };
  }
}

function renderActivations(activations) {
  renderRows(
    "#activationRows",
    activations.map((activation) => {
      const row = document.createElement("div");
      const device = document.createElement("strong");
      const appVersion = document.createElement("span");
      const channel = document.createElement("span");
      const lastSeen = document.createElement("mark");
      device.textContent = activation.device_name || "";
      appVersion.textContent = activation.app_version || "";
      channel.textContent = activation.channel || "";
      lastSeen.textContent = new Date(activation.last_seen_at).toLocaleString("fr-FR");
      row.append(device, appVersion, channel, lastSeen);
      return row;
    }),
    "Aucune activation",
  );
}

function renderDeployment(deployment) {
  const pre = qs("#deploymentScript");
  if (!pre) return;
  if (!deployment) {
    pre.textContent = "Aucune licence active.";
    return;
  }
  pre.textContent = [
    "%ProgramData%\\NovaSentinel\\premium_deployment.json",
    JSON.stringify(deployment.premium_deployment_json, null, 2),
    "",
    "Intune / PowerShell",
    deployment.intune_script,
  ].join("\n");
}

qs("#exportActivations")?.addEventListener("click", async () => {
  try {
    const data = await api("/api/dashboard/user");
    downloadBlob(new Blob([JSON.stringify(data.activations || [], null, 2)], { type: "application/json" }), "novasentinel-activations.json");
    statusBox("#userDashboardState", "Export activations généré.", "success");
  } catch (error) {
    statusBox("#userDashboardState", humanError(error), "error");
  }
});

async function loadSuperadminDashboard() {
  if (!qs("[data-dashboard='superadmin']")) return;
  try {
    const data = await api("/api/dashboard/superadmin");
    statusBox("#superadminState", "Dashboard superadmin synchronisé.", "success");
    setText("#superadminOrgs", data.metrics.organizations);
    setText("#superadminSeats", data.metrics.active_seats);
    setText("#superadminSeatsNote", `sur ${data.metrics.seats} achetés`);
    setText("#superadminMrr", money(data.metrics.mrr_eur));
    setText("#superadminAlerts", data.metrics.admin_alerts);
    renderSuperadminLicenses(data.licenses || []);
    renderAudit(data.audit_events || []);
    renderReleases(data.releases || []);
  } catch (error) {
    if (error.status === 401) {
      redirectToLogin();
      return;
    }
    statusBox("#superadminState", humanError(error), "error", { href: "/login/", label: "Se connecter" });
  }
}

function renderSuperadminLicenses(licenses) {
  renderRows(
    "#superadminLicenseRows",
    licenses.map((license) => {
      const row = document.createElement("div");
      const organizationName = document.createElement("strong");
      const licenseKey = document.createElement("span");
      const seats = document.createElement("span");
      const status = document.createElement("mark");
      const resignButton = document.createElement("button");
      const revokeButton = document.createElement("button");
      organizationName.textContent = license.organization_name || "";
      licenseKey.textContent = license.license_key || "";
      seats.textContent = `${license.active_seats} / ${license.seats}`;
      status.textContent = license.status || "";
      resignButton.type = "button";
      resignButton.dataset.action = "resign";
      resignButton.dataset.license = String(license.id);
      resignButton.textContent = "Resigner";
      revokeButton.type = "button";
      revokeButton.dataset.action = "revoke";
      revokeButton.dataset.license = String(license.id);
      revokeButton.textContent = "Révoquer";
      row.append(organizationName, licenseKey, seats, status, resignButton, revokeButton);
      return row;
    }),
    "Aucune licence",
  );
}

function renderAudit(events) {
  renderRows(
    "#auditRows",
    events.slice(0, 10).map((event) => {
      const row = document.createElement("div");
      const date = document.createElement("span");
      const action = document.createElement("strong");
      date.textContent = new Date(event.created_at).toLocaleString("fr-FR");
      action.textContent = event.action || "";
      row.append(date, action);
      return row;
    }),
    "Aucun audit",
  );
}

function renderReleases(releases) {
  renderRows(
    "#releaseRows",
    releases.map((release) => {
      const row = document.createElement("div");
      const channel = document.createElement("span");
      const version = document.createElement("strong");
      const link = document.createElement("a");
      const details = document.createElement("small");
      const href = safeHref(release.installer_url, "");
      channel.textContent = release.channel || "";
      version.textContent = release.version || "";
      link.textContent = href ? "Installateur" : "Sans URL";
      if (href) link.href = href;
      details.textContent = `${release.sha256 ? `SHA-256 ${release.sha256.slice(0, 12)}...` : "SHA-256 absent"} - ${bytes(release.size_bytes)}`;
      row.append(channel, version, link, details);
      return row;
    }),
    "Aucune release publiée",
  );
}

qs("#superadminLicenseRows")?.addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-action]");
  if (!button) return;
  const id = button.dataset.license;
  const action = button.dataset.action;
  const endpoint = `/api/superadmin/licenses/${id}/${action}`;
  if (action === "revoke" && !window.confirm("Révoquer cette licence ? Cette action est auditée.")) return;
  button.disabled = true;
  try {
    await api(endpoint, { method: "POST", body: action === "revoke" ? { reason: "superadmin dashboard" } : {} });
    statusBox("#superadminState", `Action ${action} effectuée.`, "success");
    loadSuperadminDashboard();
  } catch (error) {
    statusBox("#superadminState", humanError(error), "error");
  } finally {
    button.disabled = false;
  }
});

qs("#issueLicenseForm")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = new FormData(form);
  setBusy(form, true, "Émission...");
  try {
    const result = await api("/api/superadmin/licenses/issue", {
      method: "POST",
      body: {
        org: data.get("org"),
        email: data.get("email"),
        seats: data.get("seats"),
      },
    });
    renderSecret("#issueLicenseState", "Licence Premium créée. Utilisez cette clé pour activer le compte client.", result.license.license_key);
    if (await copySilently(result.license.license_key)) {
      const copied = document.createElement("small");
      copied.className = "copy-feedback";
      copied.textContent = "Clé copiée automatiquement.";
      qs("#issueLicenseState")?.append(copied);
    }
    form.reset();
    loadSuperadminDashboard();
  } catch (error) {
    statusBox("#issueLicenseState", humanError(error), "error");
  } finally {
    setBusy(form, false);
  }
});

let githubInspectTimer = 0;

async function inspectGithubReleaseUrl(force = false) {
  const form = qs("#releaseForm");
  const input = form?.elements.installer_url;
  const button = qs("#inspectGithubRelease");
  const state = qs("#githubReleaseState");
  const installerUrl = String(input?.value || "").trim();
  if (!form || !input || !state) return;
  if (!installerUrl) {
    state.textContent = "Collez une URL d'asset GitHub Release pour préremplir automatiquement.";
    return;
  }
  if (!isGithubReleaseAssetUrl(installerUrl)) {
    if (force) state.textContent = "Cette URL n'est pas une URL d'asset GitHub Release.";
    return;
  }
  button?.setAttribute("disabled", "");
  state.textContent = "Récupération GitHub et calcul SHA-256...";
  try {
    const result = await api("/api/superadmin/releases/inspect-github-url", {
      method: "POST",
      body: { installer_url: installerUrl },
    });
    const release = result.release || {};
    form.elements.version.value = release.version || form.elements.version.value;
    form.elements.channel.value = release.channel || form.elements.channel.value || "stable";
    form.elements.sha256.value = release.sha256 || "";
    form.elements.notes.value = release.notes || form.elements.notes.value;
    input.value = release.installer_url || installerUrl;
    state.textContent = `GitHub OK: ${release.owner}/${release.repo} ${release.tag}, ${bytes(release.size_bytes)}.`;
  } catch (error) {
    state.textContent = humanError(error);
  } finally {
    button?.removeAttribute("disabled");
  }
}

qs("#inspectGithubRelease")?.addEventListener("click", () => inspectGithubReleaseUrl(true));

qs("#releaseForm input[name='installer_url']")?.addEventListener("input", () => {
  clearTimeout(githubInspectTimer);
  githubInspectTimer = window.setTimeout(() => inspectGithubReleaseUrl(false), 900);
});

qs("#releaseForm input[name='installer_url']")?.addEventListener("change", () => inspectGithubReleaseUrl(false));

qs("#releaseForm")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = new FormData(form);
  setBusy(form, true, "Publication...");
  try {
    const installer = data.get("installer");
    if (!(installer instanceof File) || !installer.size) data.delete("installer");
    if (!data.get("installer") && !String(data.get("installer_url") || "").trim()) {
      statusBox("#superadminState", "Ajoutez un installateur .exe ou une URL externe avant de publier.", "error");
      return;
    }
    await loadCsrfToken();
    const response = await fetch("/api/superadmin/releases/publish", {
      method: "POST",
      credentials: "same-origin",
      headers: { Accept: "application/json", ...(csrfToken ? { "X-CSRF-Token": csrfToken } : {}) },
      body: data,
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) {
      const error = new Error(result.message || result.error || `HTTP ${response.status}`);
      error.status = response.status;
      error.payload = result;
      throw error;
    }
    const hash = result.release?.sha256 ? ` SHA-256 ${result.release.sha256.slice(0, 12)}...` : "";
    statusBox("#superadminState", `Release publiée.${hash}`, "success");
    form.reset();
    loadSuperadminDashboard();
  } catch (error) {
    statusBox("#superadminState", humanError(error), "error");
  } finally {
    setBusy(form, false);
  }
});

qs("#exportAudit")?.addEventListener("click", async () => {
  try {
    const data = await api("/api/superadmin/audit/export");
    downloadBlob(new Blob([JSON.stringify(data.audit_events || [], null, 2)], { type: "application/json" }), "novasentinel-audit.json");
    statusBox("#superadminState", "Audit exporté.", "success");
  } catch (error) {
    statusBox("#superadminState", humanError(error), "error");
  }
});

qs("#createBackup")?.addEventListener("click", async () => {
  try {
    const result = await api("/api/superadmin/backups/create", { method: "POST", body: {} });
    statusBox("#superadminState", `Sauvegarde créée: ${result.backup || "ok"}.`, "success");
  } catch (error) {
    statusBox("#superadminState", humanError(error), "error");
  }
});

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

hydrateSessionBanner();
renderSubscriptionSummary();
loadUserDashboard();
loadSuperadminDashboard();
