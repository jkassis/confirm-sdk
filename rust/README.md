# Confirm Rust SDK

Rust crate for server-side Confirm requester applications.

Current scope:

- typed builders for login and session-refresh request bodies
- canonical JSON and `sha256:<base64url>` request body hashes
- `confirm-request-v1` signing with RS256
- registered-origin binding through `x-confirm-origin`
- `confirm-response+jwt` verification against Confirm JWKS
- replay-cache trait keyed by response `jti` and receipt id
- optional `http` feature for submitting signed requests with `reqwest`

## Sign A Confirmation Request

```rust
use confirm_service_sdk::{
  create_login_confirmation_request, sign_confirmation_request,
  IdentityConfirmationRequestInput, SignConfirmationRequestInput,
};

let body = create_login_confirmation_request(IdentityConfirmationRequestInput {
  account_id: "acct_123".to_string(),
  requester_id: "app_123".to_string(),
  app_name: "Example App".to_string(),
  responder: serde_json::json!({ "email": "person@example.com" }),
  expires_at: "2026-06-25T00:00:00Z".to_string(),
  prompt: None,
  identity_label: None,
  metadata: None,
})?;

let signed = sign_confirmation_request(SignConfirmationRequestInput {
  requester_id: "app_123".to_string(),
  key_id: "key_2026_01".to_string(),
  private_key_pem,
  origin: "https://app.example.com".to_string(),
  created_at: 1_700_000_000,
  expires_at: 1_700_000_300,
  nonce: "unique-nonce".to_string(),
  body,
})?;

// POST signed.body to /v1/confirmation-requests with signed.headers.
```

With the optional `http` feature:

```rust
use confirm_service_sdk::ConfirmHttpClient;

let client = ConfirmHttpClient::new("https://confirm.example.com")?;
let created = client.submit_confirmation_request(&signed).await?;

assert_eq!(created.status, "submitted");
println!("{}", created.workflow_url);
```

## Build A Multi-Artifact Request

```rust
use confirm_service_sdk::{
  completion_delivery_async, create_multi_artifact_confirmation_request,
  ConfirmationArtifactInput, ConfirmationRequestInput, DeliveryChannel, RendererRequirement,
};

let body = create_multi_artifact_confirmation_request(ConfirmationRequestInput {
  account_id: "acct_123".to_string(),
  requester_id: "app_123".to_string(),
  requester_display_name: Some("Example App".to_string()),
  responder: serde_json::json!({ "email": "person@example.com" }),
  artifacts: vec![
    ConfirmationArtifactInput::inline_markdown("statement", "Please review these terms."),
    ConfirmationArtifactInput::fetched_uri(
      "terms_pdf",
      "application/pdf",
      "https://app.example.com/terms.pdf",
      "sha256:expected-content-hash",
    )
    .with_renderer(RendererRequirement::required("pdf/v1")),
  ],
  expires_at: "2026-06-25T00:00:00Z".to_string(),
  workflow_template_id: String::new(),
  audiences: None,
  disclosure_policy: None,
  evidence_policy: None,
  notification_policy: None,
  completion_delivery: Some(completion_delivery_async(vec![
    DeliveryChannel::pull(),
    DeliveryChannel::webhook("https://app.example.com/webhooks/confirm"),
  ])),
  metadata: None,
})?;
```

## Verify A Confirmation Response

```rust
use confirm_service_sdk::{
  verify_confirmation_response_token, Jwks, MemoryResponseReplayCache,
  VerifyConfirmationResponseInput,
};

let jwks: Jwks = serde_json::from_str(jwks_json)?;
let mut replay_cache = MemoryResponseReplayCache::default();
let verified = verify_confirmation_response_token(
  response_token,
  &jwks,
  VerifyConfirmationResponseInput {
    issuer: Some("https://confirm.example.com"),
    audience: Some("app_123"),
    workflow_template_id: Some("single_responder.tight_confirm.v1"),
    registered_origin: Some("https://app.example.com"),
    now: None,
    require_confirmed: true,
  },
  Some(&mut replay_cache),
)?;

assert_eq!(verified.claims.decision, "confirmed");
```
