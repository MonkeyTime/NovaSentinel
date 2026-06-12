# NovaSentinel Premium website

This folder is the hosted NovaSentinel web property and Node backend:

- marketing home page
- `/login` authentication and 2FA entry point
- `/subscribe` Premium subscription/Stripe checkout entry point
- `/dashboard/user` customer/IT dashboard
- `/dashboard/superadmin` NovaSentinel-only internal dashboard
- `/api/*` JSON API backed by SQLite
- NovaSentinel download hero
- Premium seat-count selection
- Stripe checkout integration target
- hosted license/API explanation
- Admin Console download/integration preparation

Run locally with:

```powershell
cd premium_cloud
node server.js
```

The server listens on `http://127.0.0.1:8780` by default and stores runtime state in `premium_cloud/data/premium_cloud.sqlite3`.

Node 24+ is required because the backend uses the built-in `node:sqlite` module. The database starts empty. No demo users, licenses, organizations, or fake fixtures are inserted.

Required production environment:

- `STRIPE_SECRET_KEY`: creates real Stripe Checkout Sessions.
- `STRIPE_WEBHOOK_SECRET`: verifies Stripe webhook signatures.
- `PUBLIC_BASE_URL`: public origin used in Stripe success/cancel URLs.
- `PREMIUM_ED25519_PRIVATE_KEY_PEM`: Ed25519 private key used to sign desktop entitlements.
- `GITHUB_TOKEN`: optional token used to inspect GitHub Releases assets and private release metadata.
- `NOVASENTINEL_BACKUP_INTERVAL_HOURS`: SQLite backup interval, default `24`.
- `NOVASENTINEL_BACKUP_RETENTION`: number of SQLite backups to keep, default `14`.
- `NOVASENTINEL_DISABLE_DB_BACKUPS=1`: disables scheduled local backups.

The IT Admin Console itself is a separate downloadable app for fleet managers. It should run on the customer's side and can optionally sync with NovaSentinel hosted services.

## Superadmin dashboard

The hosted service also needs a NovaSentinel-only Superadmin dashboard. It is not part of the customer IT portal and must be deployed behind a separate internal authentication boundary.

Superadmin accounts are provisioned directly by the server operator in SQLite during deployment. The public frontend never creates a superadmin account. `/api/dashboard/superadmin` and sensitive actions check the server-side role.

Security controls enabled by default:

- rate limiting on login, organization claim, and Premium activation;
- temporary lockout after repeated password, MFA, claim, or activation failures;
- CSRF token required for every superadmin mutation;
- `Secure` session cookies automatically when `PUBLIC_BASE_URL` is HTTPS or `NODE_ENV=production`;
- HTTP security headers including CSP, frame blocking, nosniff, referrer policy, and HSTS in production;
- append-only SQLite audit log enforced with triggers;
- scheduled SQLite backups in `premium_cloud/data/backups/`.

## Debian production deployment

For a Debian host running other web apps (behind Nginx/Traefik/Apache reverse proxy), run:

```bash
sudo bash premium_cloud/tools/deploy-debian.sh
```

Defaults used by the deploy script:

- install dir: `/opt/novasentinel-premium-cloud`
- service name: `novasentinel-premium-cloud`
- user/group: `novasentinel`
- public bind: `0.0.0.0:8780`
- sqlite path: `/var/lib/novasentinel-premium-cloud/premium_cloud.sqlite3`
- downloads dir: `/var/lib/novasentinel-premium-cloud/downloads`

You can override with environment variables:

```bash
sudo NOVASENTINEL_CLOUD_APP_DIR=/srv/novasentinel/cloud \
     NOVASENTINEL_CLOUD_APP_NAME=novasentinel-premium-cloud \
     NOVASENTINEL_CLOUD_APP_USER=novasentinel \
     NOVASENTINEL_CLOUD_APP_GROUP=novasentinel \
     NOVASENTINEL_CLOUD_HOST=127.0.0.1 \
     NOVASENTINEL_CLOUD_PORT=8780 \
     bash premium_cloud/tools/deploy-debian.sh
```

Manage the service with:

```bash
systemctl status novasentinel-premium-cloud
systemctl restart novasentinel-premium-cloud
systemctl stop novasentinel-premium-cloud
```

The deploy script initializes or migrates the SQLite schema before starting systemd. Existing data in `/var/lib/novasentinel-premium-cloud` is preserved. If release assets are available in the repository `release/` directory, the latest `NovaSentinel-Setup-*.exe` and `novasentinel-admin-console-*.zip` are copied to:

- `/var/lib/novasentinel-premium-cloud/downloads/NovaSentinelSetup.exe`
- `/var/lib/novasentinel-premium-cloud/downloads/NovaSentinelAdminConsole.zip`

The public website serves those files through:

- `/downloads/NovaSentinelSetup.exe`
- `/downloads/NovaSentinelAdminConsole.zip`

## Production payment flow

1. Buyer selects the number of Premium seats on this site.
2. Frontend calls `POST /api/checkout/sessions`, which creates a real Stripe Checkout Session.
3. Stripe handles payment.
4. Backend listens on `POST /api/stripe/webhook` and verifies the Stripe signature.
5. Only after `checkout.session.completed` does the backend create the organization license key and invite/claim path.
6. Backend signs NovaSentinel entitlements with the private Ed25519 key.

The private signing key and Stripe secret key must never be shipped in frontend code or the desktop app.

## API surface

- `GET /api/health`: minimal public service health.
- `POST /api/login` then `POST /api/login/verify`: password plus TOTP, creates an HTTP-only session.
- `POST /api/checkout/sessions`: creates a real Stripe Checkout Session.
- `POST /api/stripe/webhook`: confirms payment and creates organization/license.
- `POST /api/organizations/claim`: first customer admin claims an active license.
- `POST /api/premium/verify`: desktop app verifies a license key, consumes/updates one seat, and receives a signed entitlement.
- `GET /api/dashboard/user`: customer organization metrics, licenses, activations, deployment payload.
- `GET /api/dashboard/superadmin`: internal metrics, licenses, releases, audit log.
- `POST /api/superadmin/licenses/issue`: manually issues a Premium license as an audited superadmin action, useful for local testing, offline sales, or support.
- `POST /api/superadmin/licenses/:id/revoke`: revokes a license and writes audit.
- `POST /api/superadmin/licenses/:id/resign`: increments entitlement version and writes audit.
- `POST /api/superadmin/releases/inspect-github-url`: inspects a GitHub Release asset URL, reads release metadata, downloads the asset server-side, and returns version, notes, URL, size, and SHA-256.
- `POST /api/superadmin/releases/publish`: publishes a release with either an uploaded installer or an external installer URL, computes SHA-256 for uploads, and writes audit.
- `GET /api/releases/latest?channel=stable&current_version=0.1.3`: public release lookup for NovaSentinel desktop update checks.
- `GET /api/superadmin/audit/export`: exports audit events as JSON.
- `POST /api/superadmin/backups/create`: creates an immediate SQLite backup as an audited superadmin action.

Uploaded installers are stored under `premium_cloud/data/release_uploads/` and served through `/release-downloads/<file>`.
