# NovaSentinel Admin Console

This folder contains the downloadable Admin Console foundation for Premium IT fleet managers.
It is distributed as a portable package (zip) that IT teams can run on their local workstation after licensing.

The console is intentionally separate from `premium_cloud`:

- `premium_cloud` is the hosted NovaSentinel service that owns licenses, payments, releases, and cloud data.
- `admin_console` is the customer-side local panel that fleet managers can download and run on their workstation.

The console is intentionally focused on:

- mass deployment preparation;
- bulk Premium license handling;
- deployment packages for GPO, Intune, RMM, or administrator execution;
- cloud connectivity checks against the hosted NovaSentinel portal.

It is not a second antivirus cockpit and it does not manage detection, alerts, or endpoint protection logic.

The first implementation has multilingual support from the initial UI layer. All visible strings live in `src/i18n.js` for French, English, Spanish, German, Italian, Portuguese, and Arabic.

Run locally (quickest, with Node on PATH):

```powershell
npm --prefix admin_console run start
```

or with scripts included in the package:

```bash
cd admin_console
./tools/run-admin-console.sh
```

```bat
cd admin_console
tools\run-admin-console.bat
```

Open:

```text
http://127.0.0.1:8790
```

You can override the bind and env values by copying `.env.example` to `.env` (or defining env vars).

The local server exposes:

- `GET /api/local/health`: local console health.
- `GET /api/cloud/health?url=<premium-cloud-url>`: server-side health check against the hosted Premium Cloud portal.

No fake fleet or license data is inserted. Bulk license data remains empty until the Premium Cloud API exposes the real Admin Console license endpoints.

## Package for distribution

Build a downloadable zip package from the repo root:

```powershell
pwsh .\scripts\package_admin_console.ps1
```

This creates a zip in `release/` including the console and launchers.

Add `-IncludeEmbeddedNode` if you copy a portable Node runtime in `admin_console/node` and want it embedded in the archive.
