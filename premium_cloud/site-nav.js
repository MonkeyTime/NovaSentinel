const navLanguageKey = "novasentinel_premium_language";

const navLabels = {
  fr: {
    home: "Accueil",
    download: "Télécharger",
    premium: "Entreprise",
    security: "Sécurité",
    subscribe: "Acheter",
    dashboard: "Dashboard",
    login: "Connexion",
    logout: "Se déconnecter",
    language: "Langue",
  },
  en: {
    home: "Home",
    download: "Download",
    premium: "Enterprise",
    security: "Security",
    subscribe: "Buy",
    dashboard: "Dashboard",
    login: "Sign in",
    logout: "Log out",
    language: "Language",
  },
  es: {
    home: "Inicio",
    download: "Descargar",
    premium: "Empresa",
    security: "Seguridad",
    subscribe: "Comprar",
    dashboard: "Dashboard",
    login: "Iniciar sesión",
    logout: "Cerrar sesión",
    language: "Idioma",
  },
  de: {
    home: "Start",
    download: "Download",
    premium: "Enterprise",
    security: "Sicherheit",
    subscribe: "Kaufen",
    dashboard: "Dashboard",
    login: "Anmelden",
    logout: "Abmelden",
    language: "Sprache",
  },
  it: {
    home: "Home",
    download: "Download",
    premium: "Enterprise",
    security: "Sicurezza",
    subscribe: "Acquista",
    dashboard: "Dashboard",
    login: "Accedi",
    logout: "Disconnetti",
    language: "Lingua",
  },
  pt: {
    home: "Início",
    download: "Transferir",
    premium: "Empresa",
    security: "Segurança",
    subscribe: "Comprar",
    dashboard: "Dashboard",
    login: "Entrar",
    logout: "Terminar sessão",
    language: "Idioma",
  },
  ar: {
    home: "الرئيسية",
    download: "تنزيل",
    premium: "Enterprise",
    security: "الأمان",
    subscribe: "شراء",
    dashboard: "Dashboard",
    login: "تسجيل الدخول",
    logout: "تسجيل الخروج",
    language: "اللغة",
  },
};

function navLanguage() {
  const stored = localStorage.getItem(navLanguageKey) || navigator.language || "fr";
  const code = stored.toLowerCase().slice(0, 2);
  return Object.hasOwn(navLabels, code) ? code : "fr";
}

function navT(key) {
  return navLabels[navLanguage()]?.[key] || navLabels.fr[key] || key;
}

function navLink(href, label) {
  const link = document.createElement("a");
  link.href = href;
  link.textContent = label;
  return link;
}

async function navApi(path, options = {}) {
  const sessionToken = String(document.body?.dataset?.novaCsrf || "");
  const response = await fetch(path, {
    credentials: "same-origin",
    headers: {
      Accept: "application/json",
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...(sessionToken ? { "X-CSRF-Token": sessionToken } : {}),
      ...(options.headers || {}),
    },
    ...options,
    body: options.body ? JSON.stringify(options.body) : undefined,
  });
  return response.ok ? response.json() : {};
}

function renderLanguageSlot() {
  const slot = document.querySelector("[data-nav-language]");
  if (!slot || slot.querySelector("select")) return;
  const label = document.createElement("label");
  label.className = "language-select compact-language-select";
  label.htmlFor = "siteLanguageSelect";
  const text = document.createElement("span");
  text.textContent = navT("language");
  const select = document.createElement("select");
  select.id = "siteLanguageSelect";
  select.setAttribute("aria-label", navT("language"));
  [
    ["fr", "Français"],
    ["en", "English"],
    ["es", "Español"],
    ["de", "Deutsch"],
    ["it", "Italiano"],
    ["pt", "Português"],
    ["ar", "العربية"],
  ].forEach(([value, labelText]) => {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = labelText;
    select.append(option);
  });
  select.value = localStorage.getItem(navLanguageKey) || navLanguage();
  select.addEventListener("change", () => {
    localStorage.setItem(navLanguageKey, select.value);
    window.location.reload();
  });
  label.append(text, select);
  slot.append(label);
}

async function renderSiteNav() {
  const anchors = document.querySelector("[data-nav-anchors]");
  const account = document.querySelector("[data-nav-account]");
  if (!anchors || !account) return;

  anchors.innerHTML = "";
  account.innerHTML = "";

  anchors.append(
    navLink("/", navT("home")),
    navLink("/#download", navT("download")),
    navLink("/#premium", navT("premium")),
    navLink("/#security", navT("security")),
  );

  const session = await navApi("/api/session").catch(() => ({ authenticated: false }));
  const csrfToken = session.csrf_token || "";
  document.body?.setAttribute("data-nova-csrf", csrfToken);
  account.append(navLink("/subscribe/", navT("subscribe")));

  if (session.authenticated) {
    const dashboardHref = session.user?.role === "superadmin" ? "/dashboard/superadmin/" : "/dashboard/user/";
    account.append(navLink(dashboardHref, navT("dashboard")));
    const logout = document.createElement("button");
    logout.className = "nav-button-link";
    logout.type = "button";
    logout.textContent = navT("logout");
    logout.addEventListener("click", async () => {
      await navApi("/api/logout", {
        method: "POST",
        headers: csrfToken ? { "X-CSRF-Token": csrfToken } : {},
      }).catch(() => null);
      window.location.href = "/login/";
    });
    account.append(logout);
  } else {
    account.append(navLink("/dashboard/user/", navT("dashboard")), navLink("/login/", navT("login")));
  }

  renderLanguageSlot();
}

document.addEventListener("DOMContentLoaded", renderSiteNav);
