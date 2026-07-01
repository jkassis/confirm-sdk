# Confirm TypeScript SDK

TypeScript package for server-side Confirm requester applications.

Current scope:

- typed builders for login, session-refresh, and multi-artifact request bodies
- canonical JSON and `sha256:<base64url>` request body hashes
- `confirm-request-v1` signing with RS256
- registered-origin binding through `x-confirm-origin`
- `confirm-response+jwt` verification against Confirm JWKS
- replay-cache interface keyed by response `jti` and receipt id
- HTTP helpers using `fetch`

Requester private keys belong on requester application servers only. Browser helpers must not sign requests or verify final authorization by themselves.

```ts
import {
  createLoginConfirmationRequest,
  signConfirmationRequest,
} from "@confirm/service-sdk";

const body = createLoginConfirmationRequest({
  accountId: "acct_123",
  requesterId: "app_123",
  appName: "Example App",
  responder: { email: "person@example.com" },
  expiresAt: "2026-06-25T00:00:00Z",
});

const signed = signConfirmationRequest({
  requesterId: "app_123",
  keyId: "key_2026_01",
  privateKeyPem,
  origin: "https://app.example.com",
  createdAt: 1_700_000_000,
  expiresAt: 1_700_000_300,
  nonce: "unique-nonce",
  body,
});

// POST signed.body to /v1/confirmation-requests with signed.headers.
```
