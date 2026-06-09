# NovaSentinel Premium contract

NovaSentinel Premium is activated by a website-controlled license service. The desktop app must not contain the private signing key or a list of premium customers.

## Activation endpoint

Default URL:

```text
https://novasentinel.app/api/premium/verify
```

The app sends:

```json
{
  "key": "NSP-CLIENT-KEY",
  "key_fingerprint": "sha256-of-key",
  "device_id": "stable-device-uuid",
  "app_version": "0.1.5"
}
```

The server returns an entitlement signed with Ed25519:

```json
{
  "entitlement": {
    "license_id": "lic_123",
    "plan": "premium",
    "status": "active",
    "customer": "Customer",
    "device_id": "same-stable-device-uuid",
    "features": [
      "premium_updates",
      "large_file_scans",
      "extended_forensics",
      "recovery_vault"
    ],
    "expires_at": "2027-01-01T00:00:00Z",
    "checked_at": "2026-06-09T10:00:00Z"
  },
  "signature": "base64url-ed25519-signature"
}
```

The signature is calculated over the canonical JSON bytes of `entitlement`: sorted keys, compact separators, ASCII escaping.

## Public key

The premium build must include the raw Ed25519 public key in `novaguard/core/premium.py`:

```python
PREMIUM_PUBLIC_KEY = "<base64url raw Ed25519 public key>"
```

Only the public key goes into the app. The private key stays on the website or license service. Environment-based public-key override is intentionally limited to development mode (`NOVASENTINEL_PREMIUM_DEV_MODE=1`) and should not be used for production premium builds.

## Premium update endpoint

Default URL:

```text
https://novasentinel.app/api/premium/releases/latest
```

When the premium update channel is enabled, the app sends its signed entitlement back to the server. The server returns:

```json
{
  "update": {
    "version": "0.1.5",
    "tag": "v0.1.5",
    "asset_name": "NovaSentinel-Setup-0.1.5.exe",
    "download_url": "https://github.com/MonkeyTime/NovaSentinel/releases/download/v0.1.5/NovaSentinel-Setup-0.1.5.exe",
    "sha256": "64-hex-sha256",
    "release_url": "https://github.com/MonkeyTime/NovaSentinel/releases/tag/v0.1.5",
    "published_at": "2026-06-09T10:00:00Z"
  },
  "signature": "base64url-ed25519-signature"
}
```

The app verifies the signature, exact installer name, HTTPS download URL, and SHA-256 digest before launching the installer.
