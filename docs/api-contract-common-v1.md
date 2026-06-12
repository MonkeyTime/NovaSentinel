# Contrat API commun NovaSentinel (v1)

Ce contrat couvre les échanges entre:
- le client **desktop** (`novaguard`)
- le portail premium web (`premium_cloud`)
- la console admin (`admin_console`) lorsqu’elle requiert un cloud externe.

Toutes les requêtes d’API utilisent `Content-Type: application/json` pour les corps JSON.
Les cookies `ns_session` sont `HttpOnly` et `SameSite=Strict`.

## 1) Entités de sécurité

### Entitlement Premium (desktop)
- `entitlement`
  - `license_id` (string)
  - `plan` (string, valeur `premium`)
  - `status` (string: `active|trialing|expired|revoked|...`)
  - `customer` (string)
  - `device_id` (string, UUID)
  - `features` (array de chaînes)
  - `expires_at` (ISO-8601 UTC)
  - `checked_at` (ISO-8601 UTC)
- `signature`
  - chaîne base64url Ed25519 de la signature du JSON canonique (`sort_keys=true`, séparateurs compacts)

## 2) API cloud ↔ desktop

### `POST /api/premium/verify`

Demande envoyée par le desktop:

```json
{
  "key": "NSP-CLIENT-KEY",
  "key_fingerprint": "sha256-of-key",
  "device_id": "uuid-v4",
  "app_version": "0.1.9",
  "channel": "stable"
}
```

Réponse 200:

```json
{
  "entitlement": { ... },
  "signature": "BASE64URL_SIGNATURE"
}
```

Codes d’erreur possibles:
- `license_inactive_or_unknown`
- `seat_limit_reached`
- `license_key_and_device_id_required`

### `GET /api/releases/latest` (ou `POST /api/releases/latest`)

Paramètres (`GET`) :  
- `channel` (`stable` ou `beta`, défaut `stable`)  
- `current_version` (ex: `0.1.9`)

Réponse 200 (desktop):

```json
{
  "update": {
    "version": "0.1.9",
    "tag": "v0.1.9",
    "asset_name": "NovaSentinel-Setup-0.1.9.exe",
    "download_url": "https://...",
    "sha256": "64hex",
    "release_url": "https://...",
    "published_at": "2026-06-10T00:00:00Z"
  },
  "signature": "BASE64URL_SIGNATURE"
}
```

Le desktop doit refuser les mises à jour si:
- `version` non plus récente
- `sha256` invalide
- `download_url` non HTTPS / hôte inattendu
- signature invalide

## 3) API portail premium (`premium_cloud`)

| Méthode | Endpoint | Description |
| --- | --- | --- |
| `GET` | `/api/health` | Santé publique minimale du service |
| `GET` | `/api/session` | Session courante + token CSRF |
| `POST` | `/api/setup/superadmin` | Bootstrap du premier superadmin (token bootstrap requis) |
| `POST` | `/api/login` | Étape 1: vérification email/mot de passe |
| `POST` | `/api/login/verify` | Étape 2: TOTP + création de session |
| `POST` | `/api/logout` | Fermeture session |
| `POST` | `/api/organizations/claim` | Activation initiale d’une licence pour une organisation |
| `GET` | `/api/dashboard/user` | Dashboard client (role `user`) |
| `GET` | `/api/dashboard/superadmin` | Dashboard interne (role `superadmin`) |
| `POST` | `/api/checkout/sessions` | Création d’une session Stripe Checkout |
| `POST` | `/api/stripe/webhook` | Réception Stripe webhook |
| `POST` | `/api/superadmin/releases/inspect-github-url` | Préremplit métadonnées release depuis GitHub |
| `POST` | `/api/superadmin/releases/publish` | Publication release (fichier `.exe` ou URL) |
| `GET` | `/api/superadmin/audit/export` | Export audit JSON |
| `POST` | `/api/superadmin/backups/create` | Snapshot SQLite |
| `POST` | `/api/superadmin/licenses/issue` | Émission licence manuelle |
| `POST` | `/api/superadmin/licenses/:id/revoke` | Révocation licence |
| `POST` | `/api/superadmin/licenses/:id/resign` | Renouvellement signature licence |
| `GET` | `/api/releases/latest` | API versionnée pour update desktop (publique) |
| `POST` | `/api/premium/releases/latest` | Variante alias POST (interop webhooks/outils) |
| `GET` | `/api/release-packages/:filename` | Package d’installation local (optionnel, legacy) |

### AuthN/AuthZ
- Les actions superadmin et mutations sensibles exigent `X-CSRF-Token` et rôle `superadmin`.
- Toutes les routes de session sont basées cookie `ns_session`.

## 4) API console admin locale (`admin_console`)

La console admin ne possède pas d’API métier propre. Elle expose :
- `GET /api/local/health`
- `GET /api/cloud/health?url=<cloud>` (proxy de vérification santé)

## 5) Conventions de conformité

Un artefact de validation exécutable est disponible ici:
- `scripts/validate_api_contract.mjs`

Il vérifie:
- la présence des routes contractuelles dans `premium_cloud/server.js`;
- la présence des URLs contractuelles dans le code desktop (`novaguard/core/premium.py`);
- la cohérence de la console admin avec `/api/cloud/health`.
