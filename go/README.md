# Confirm Go SDK

Go package for server-side Confirm requester applications.

Current scope:

- typed builders for login, session-refresh, and multi-artifact request bodies
- canonical JSON and `sha256:<base64url>` request body hashes
- `confirm-request-v1` signing with RS256
- registered-origin binding through `x-confirm-origin`
- `confirm-response+jwt` verification against Confirm JWKS
- replay-cache interface keyed by response `jti` and receipt id
- HTTP helpers using `net/http`

Requester private keys belong on requester application servers only. Browser helpers must not sign requests or verify final authorization by themselves.

```go
body := confirm.CreateLoginConfirmationRequest(confirm.IdentityConfirmationRequestInput{
	AccountID:   "acct_123",
	RequesterID: "app_123",
	AppName:     "Example App",
	Responder:   map[string]any{"email": "person@example.com"},
	ExpiresAt:   "2026-06-25T00:00:00Z",
})

signed, err := confirm.SignConfirmationRequest(confirm.SignConfirmationRequestInput{
	RequesterID:    "app_123",
	KeyID:          "key_2026_01",
	PrivateKeyPEM: privateKeyPEM,
	Origin:        "https://app.example.com",
	CreatedAt:     1_700_000_000,
	ExpiresAt:     1_700_000_300,
	Nonce:         "unique-nonce",
	Body:          body,
})
if err != nil {
	return err
}

// POST signed.Body to /v1/confirmation-requests with signed.Headers.
```
