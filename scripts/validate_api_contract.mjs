#!/usr/bin/env node
import fs from "node:fs";

const root = process.cwd();

const contract = JSON.parse(fs.readFileSync(`${root}/docs/api-contract-common-v1.json`, "utf8"));
const cloudSource = fs.readFileSync(`${root}/premium_cloud/server.js`, "utf8");
const adminSource = fs.readFileSync(`${root}/admin_console/server.js`, "utf8");
const desktopSource = fs.readFileSync(`${root}/novaguard/core/premium.py`, "utf8");

const sources = {
  "cloud-website": cloudSource,
  "cloud-desktop": cloudSource,
  "admin-console-local": adminSource,
};

const failures = [];
const checks = [];

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function routeExists(source, method, path) {
  const escaped = escapeRegExp(path);
  const methodMatcher = new RegExp(`req\\.method\\s*===\\s*["']${method}["']`);
  const exactMatcher = new RegExp(`req\\.method\\s*===\\s*["']${method}["'][\\s\\S]{0,220}url\\.pathname\\s*===\\s*["']${escaped}["']`);
  return methodMatcher.test(source) && (exactMatcher.test(source) || exactMatcher.test(source.replace(`"${path}"`, `\"${path}\"`)));
}

function hasReleaseAliasRoute() {
  return /\["\/api\/releases\/latest",\s*"\/api\/premium\/releases\/latest"\]/.test(cloudSource)
    || /\["\/api\/premium\/releases\/latest",\s*"\/api\/releases\/latest"\]/.test(cloudSource)
    || ( /\/api\/releases\/latest/.test(cloudSource) && /\/api\/premium\/releases\/latest/.test(cloudSource));
}

function includesMethodAndPath(source, method, path) {
  const methodBlock = source.includes(`req.method === "${method}"`);
  return methodBlock && source.includes(`"${path}"`);
}

for (const route of contract.routes) {
  const source = sources[route.scope] ?? cloudSource;

  if (route.path === "/api/releases/latest") {
    if (!hasReleaseAliasRoute() && !routeExists(source, "GET", "/api/releases/latest")) {
      failures.push(`Missing GET route for ${route.path}`);
    } else {
      checks.push({ method: "GET", path: "/api/releases/latest" });
    }
    if (!hasReleaseAliasRoute() && !routeExists(source, "POST", "/api/releases/latest")) {
      failures.push(`Missing POST route for ${route.path}`);
    } else {
      checks.push({ method: "POST", path: "/api/releases/latest" });
    }
    continue;
  }

  if (route.path === "/api/premium/releases/latest") {
    if (!hasReleaseAliasRoute() && !routeExists(source, "GET", "/api/premium/releases/latest")) {
      failures.push(`Missing GET route for ${route.path}`);
    } else {
      checks.push({ method: "GET", path: route.path });
    }
    continue;
  }

  if (route.path.includes(":id")) {
    const action = route.path.split("/").pop();
    const hasAction = source.includes(`/${action}`) && source.includes("/api/superadmin/licenses/");
    const methodBound = source.includes(`req.method === "${route.method}"`);
    if (!methodBound || !hasAction) {
      failures.push(`Missing dynamic route ${route.method} ${route.path}`);
      continue;
    }
    checks.push({ method: route.method, path: route.path });
    continue;
  }

  if (!routeExists(source, route.method, route.path)) {
    if (!includesMethodAndPath(source, route.method, route.path) && !hasReleaseAliasRoute()) {
      failures.push(`Missing route ${route.method} ${route.path}`);
      continue;
    }
  }
  checks.push({ method: route.method, path: route.path });
}

for (const binding of contract.desktopBindings) {
  if (!desktopSource.includes(binding.mustContain)) {
    failures.push(`Missing desktop binding: ${binding.name}`);
  }
}

if (failures.length > 0) {
  console.error("NovaSentinel API contract validation FAILED");
  for (const failure of failures) {
    console.error(` - ${failure}`);
  }
  process.exit(1);
}

console.log(`NovaSentinel API contract validation OK (${checks.length} checks)`);
for (const check of checks) {
  console.log(` - ${check.method} ${check.path}`);
}
