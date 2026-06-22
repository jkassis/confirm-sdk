# Confirm SDK

SDKs and integration helpers for requester applications that use Confirm.

## Packages

- `rust/`: Rust server SDK for building signed confirmation requests, submitting requests, and verifying receipts.
- `typescript/`: planned TypeScript/JavaScript package.
- `go/`: planned Go package.
- `fixtures/`: planned shared conformance fixtures for canonical request bodies, signatures, response tokens, and receipts.

## Repository Layout

Each language package should expose the same core integration contract:

- build login, session-refresh, and multi-artifact confirmation request bodies
- canonicalize request JSON and compute `sha256:<base64url>` body hashes
- sign `confirm-request-v1` envelopes with requester private keys
- submit requests and return workflow metadata
- verify receipt-backed `confirm-response+jwt` values with Confirm JWKS
- expose replay-cache hooks for `jti` and `receipt_id`

Requester private keys belong on requester application servers only. Browser helpers may coordinate redirects or popup completion, but they must not sign requests or verify final authorization by themselves.

## Rust

See [rust/README.md](rust/README.md).
