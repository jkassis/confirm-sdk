use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::rngs::OsRng;
use rsa::{
    pkcs1v15,
    pkcs8::DecodePrivateKey,
    signature::{RandomizedSigner, SignatureEncoding, Verifier},
    BigUint, RsaPrivateKey, RsaPublicKey,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashSet};

pub const REQUESTER_SIGNATURE_ALGORITHM: &str = "RS256";
pub const CONFIRM_RESPONSE_TOKEN_TYPE: &str = "confirm-response+jwt";
pub const TIGHT_CONFIRM_WORKFLOW: &str = "single_responder.tight_confirm.v1";
pub const MULTI_ARTIFACT_REVIEW_WORKFLOW: &str = "single_responder.multi_artifact_review.v1";

#[derive(Debug, thiserror::Error)]
pub enum ConfirmSdkError {
    #[error("invalid RSA private key: {0}")]
    InvalidPrivateKey(String),
    #[error("invalid RSA public key: {0}")]
    InvalidPublicKey(String),
    #[error("invalid JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("invalid JWT shape")]
    InvalidJwtShape,
    #[error("invalid base64url: {0}")]
    InvalidBase64Url(#[from] base64::DecodeError),
    #[error("unexpected token type: {0}")]
    UnexpectedTokenType(String),
    #[error("unsupported token algorithm: {0}")]
    UnsupportedTokenAlgorithm(String),
    #[error("missing token key id")]
    MissingTokenKeyId,
    #[error("no JWK found for key {0}")]
    MissingJwk(String),
    #[error("JWK algorithm mismatch for key {0}")]
    JwkAlgorithmMismatch(String),
    #[error("invalid token signature")]
    InvalidTokenSignature,
    #[error("token expired")]
    TokenExpired,
    #[error("issuer mismatch")]
    IssuerMismatch,
    #[error("audience mismatch")]
    AudienceMismatch,
    #[error("workflow template mismatch")]
    WorkflowTemplateMismatch,
    #[error("confirmation decision is not confirmed")]
    DecisionNotConfirmed,
    #[error("missing receipt id")]
    MissingReceiptId,
    #[error("missing jti")]
    MissingJti,
    #[error("registered origin mismatch")]
    RegisteredOriginMismatch,
    #[error("confirmation response replay detected")]
    ReplayDetected,
    #[error("receipt is missing responseToken")]
    MissingResponseToken,
    #[error("receipt id mismatch")]
    ReceiptIdMismatch,
    #[error("receipt attestation is missing signed_payload_hash")]
    MissingSignedPayloadHash,
    #[error("receipt attestation signed_payload_hash is not a sha256 hash")]
    InvalidSignedPayloadHash,
    #[cfg(feature = "http")]
    #[error("invalid URL: {0}")]
    InvalidUrl(String),
    #[cfg(feature = "http")]
    #[error("HTTP request failed: {0}")]
    HttpRequest(#[from] reqwest::Error),
    #[cfg(feature = "http")]
    #[error("Confirm API returned {status}: {body}")]
    ConfirmApi { status: u16, body: String },
}

pub type Result<T> = std::result::Result<T, ConfirmSdkError>;

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct SignedRequestEnvelope {
    #[serde(rename = "requesterId")]
    pub requester_id: String,
    #[serde(rename = "keyId")]
    pub key_id: String,
    pub algorithm: String,
    #[serde(rename = "createdAt")]
    pub created_at: u64,
    #[serde(rename = "expiresAt")]
    pub expires_at: u64,
    pub nonce: String,
    pub origin: String,
    #[serde(rename = "bodySha256")]
    pub body_sha256: String,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedConfirmationRequest {
    pub body: String,
    pub envelope: SignedRequestEnvelope,
    pub headers: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct ConfirmationRequestCreateResponse {
    #[serde(rename = "request_id")]
    pub request_id: String,
    #[serde(rename = "workflow_id")]
    pub workflow_id: String,
    #[serde(rename = "workflow_url")]
    pub workflow_url: String,
    pub status: String,
    #[serde(rename = "expires_at")]
    pub expires_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ConfirmationReceiptResponse {
    pub receipt: ConfirmationReceipt,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ConfirmationReceiptDisclosureResponse {
    pub receipt: Value,
    #[serde(rename = "disclosureRecord")]
    pub disclosure_record: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ConfirmationReceipt {
    #[serde(rename = "receiptId")]
    pub receipt_id: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    pub status: String,
    #[serde(default)]
    pub artifacts: Vec<Value>,
    #[serde(default)]
    pub decision: Value,
    #[serde(rename = "evidenceRecords", default)]
    pub evidence_records: Vec<Value>,
    #[serde(rename = "satisfiedEvidenceBranch", default)]
    pub satisfied_evidence_branch: Option<Value>,
    #[serde(rename = "createdAt", default)]
    pub created_at: Option<u64>,
    #[serde(default)]
    pub attestation: Value,
    #[serde(rename = "responseToken", default)]
    pub response_token: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedConfirmationReceipt {
    pub receipt: ConfirmationReceipt,
    pub response: VerifiedConfirmationResponse,
}

#[cfg(feature = "http")]
#[derive(Clone, Debug)]
pub struct ConfirmHttpClient {
    base_url: String,
    client: reqwest::Client,
}

#[cfg(feature = "http")]
impl ConfirmHttpClient {
    pub fn new(base_url: impl Into<String>) -> Result<Self> {
        Self::with_client(base_url, reqwest::Client::new())
    }

    pub fn with_client(base_url: impl Into<String>, client: reqwest::Client) -> Result<Self> {
        let base_url = base_url.into().trim_end_matches('/').to_string();
        if base_url.is_empty() {
            return Err(ConfirmSdkError::InvalidUrl("empty base URL".to_string()));
        }
        Ok(Self { base_url, client })
    }

    pub async fn submit_confirmation_request(
        &self,
        signed: &SignedConfirmationRequest,
    ) -> Result<ConfirmationRequestCreateResponse> {
        submit_confirmation_request(&self.client, &self.base_url, signed).await
    }

    pub async fn get_confirmation_receipt(
        &self,
        receipt_id: &str,
    ) -> Result<ConfirmationReceiptResponse> {
        get_confirmation_receipt(&self.client, &self.base_url, receipt_id).await
    }

    pub async fn get_receipt_disclosure(
        &self,
        receipt_id: &str,
        audience: DisclosureAudience,
    ) -> Result<ConfirmationReceiptDisclosureResponse> {
        get_receipt_disclosure(&self.client, &self.base_url, receipt_id, audience).await
    }
}

#[cfg(feature = "http")]
pub async fn submit_confirmation_request(
    client: &reqwest::Client,
    base_url: &str,
    signed: &SignedConfirmationRequest,
) -> Result<ConfirmationRequestCreateResponse> {
    let url = format!(
        "{}/v1/confirmation-requests",
        base_url.trim_end_matches('/')
    );
    let mut request = client.post(url).body(signed.body.clone());
    for (name, value) in &signed.headers {
        request = request.header(name.as_str(), value.as_str());
    }
    let response = request.send().await?;
    let status = response.status();
    let body = response.text().await?;
    if !status.is_success() {
        return Err(ConfirmSdkError::ConfirmApi {
            status: status.as_u16(),
            body,
        });
    }
    Ok(serde_json::from_str(&body)?)
}

#[cfg(feature = "http")]
pub async fn get_confirmation_receipt(
    client: &reqwest::Client,
    base_url: &str,
    receipt_id: &str,
) -> Result<ConfirmationReceiptResponse> {
    let url = format!(
        "{}/v1/confirmation-receipts/{}",
        base_url.trim_end_matches('/'),
        receipt_id
    );
    get_json(client, url).await
}

#[cfg(feature = "http")]
pub async fn get_receipt_disclosure(
    client: &reqwest::Client,
    base_url: &str,
    receipt_id: &str,
    audience: DisclosureAudience,
) -> Result<ConfirmationReceiptDisclosureResponse> {
    let url = format!(
        "{}/v1/confirmation-receipts/{}/disclosure",
        base_url.trim_end_matches('/'),
        receipt_id
    );
    let response = client
        .get(url)
        .header("x-confirm-audience", audience.as_str())
        .send()
        .await?;
    response_json(response).await
}

#[cfg(feature = "http")]
async fn get_json<T: for<'de> Deserialize<'de>>(
    client: &reqwest::Client,
    url: String,
) -> Result<T> {
    let response = client.get(url).send().await?;
    response_json(response).await
}

#[cfg(feature = "http")]
async fn response_json<T: for<'de> Deserialize<'de>>(response: reqwest::Response) -> Result<T> {
    let status = response.status();
    let body = response.text().await?;
    if !status.is_success() {
        return Err(ConfirmSdkError::ConfirmApi {
            status: status.as_u16(),
            body,
        });
    }
    Ok(serde_json::from_str(&body)?)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DisclosureAudience {
    Requester,
    Responder,
    Operator,
}

impl DisclosureAudience {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requester => "requester",
            Self::Responder => "responder",
            Self::Operator => "operator",
        }
    }
}

#[derive(Clone, Debug)]
pub struct SignConfirmationRequestInput {
    pub requester_id: String,
    pub key_id: String,
    pub private_key_pem: String,
    pub origin: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub nonce: String,
    pub body: Value,
}

#[derive(Clone, Copy, Debug)]
pub struct SignConfirmationRequestBodyInput<'a> {
    pub body: &'a str,
    pub requester_id: &'a str,
    pub key_id: &'a str,
    pub private_key_pem: &'a str,
    pub origin: &'a str,
    pub created_at: u64,
    pub expires_at: u64,
    pub nonce: &'a str,
}

pub fn sign_confirmation_request(
    input: SignConfirmationRequestInput,
) -> Result<SignedConfirmationRequest> {
    let body = canonical_json(&input.body)?;
    sign_confirmation_request_body(SignConfirmationRequestBodyInput {
        body: &body,
        requester_id: &input.requester_id,
        key_id: &input.key_id,
        private_key_pem: &input.private_key_pem,
        origin: &input.origin,
        created_at: input.created_at,
        expires_at: input.expires_at,
        nonce: &input.nonce,
    })
}

pub fn sign_confirmation_request_body(
    input: SignConfirmationRequestBodyInput<'_>,
) -> Result<SignedConfirmationRequest> {
    let private_key = RsaPrivateKey::from_pkcs8_pem(input.private_key_pem)
        .map_err(|err| ConfirmSdkError::InvalidPrivateKey(err.to_string()))?;
    let mut envelope = SignedRequestEnvelope {
        requester_id: input.requester_id.to_string(),
        key_id: input.key_id.to_string(),
        algorithm: REQUESTER_SIGNATURE_ALGORITHM.to_string(),
        created_at: input.created_at,
        expires_at: input.expires_at,
        nonce: input.nonce.to_string(),
        origin: input.origin.to_string(),
        body_sha256: signed_request_body_sha256(input.body.as_bytes()),
        signature: String::new(),
    };
    let signing_key = pkcs1v15::SigningKey::<Sha256>::new(private_key);
    let signature = signing_key.sign_with_rng(
        &mut OsRng,
        requester_signature_payload(&envelope).as_bytes(),
    );
    envelope.signature = base64_url(signature.to_vec());
    let mut headers = BTreeMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers.insert(
        "x-confirm-requester-id".to_string(),
        envelope.requester_id.clone(),
    );
    headers.insert("x-confirm-key-id".to_string(), envelope.key_id.clone());
    headers.insert(
        "x-confirm-algorithm".to_string(),
        envelope.algorithm.clone(),
    );
    headers.insert(
        "x-confirm-created-at".to_string(),
        envelope.created_at.to_string(),
    );
    headers.insert(
        "x-confirm-expires-at".to_string(),
        envelope.expires_at.to_string(),
    );
    headers.insert("x-confirm-nonce".to_string(), envelope.nonce.clone());
    headers.insert("x-confirm-origin".to_string(), envelope.origin.clone());
    headers.insert(
        "x-confirm-body-sha256".to_string(),
        envelope.body_sha256.clone(),
    );
    headers.insert(
        "x-confirm-signature".to_string(),
        envelope.signature.clone(),
    );
    Ok(SignedConfirmationRequest {
        body: input.body.to_string(),
        envelope,
        headers,
    })
}

pub fn requester_signature_payload(envelope: &SignedRequestEnvelope) -> String {
    format!(
    "confirm-request-v1\nrequester_id:{}\nkey_id:{}\nalgorithm:{}\ncreated_at:{}\nexpires_at:{}\nnonce:{}\norigin:{}\nbody_sha256:{}",
    envelope.requester_id,
    envelope.key_id,
    envelope.algorithm,
    envelope.created_at,
    envelope.expires_at,
    envelope.nonce,
    envelope.origin,
    envelope.body_sha256
  )
}

pub fn signed_request_body_sha256(input: &[u8]) -> String {
    format!("sha256:{}", sha256_base64_url(input))
}

pub fn sha256_base64_url(input: &[u8]) -> String {
    base64_url(Sha256::digest(input))
}

pub fn base64_url(input: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(input)
}

pub fn canonical_json(value: &Value) -> Result<String> {
    Ok(serde_json::to_string(&sort_json(value))?)
}

fn sort_json(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(sort_json).collect()),
        Value::Object(map) => {
            let mut sorted = Map::new();
            let keys = map.keys().collect::<BTreeSet<_>>();
            for key in keys {
                if let Some(value) = map.get(key) {
                    sorted.insert(key.clone(), sort_json(value));
                }
            }
            Value::Object(sorted)
        }
        other => other.clone(),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfirmationArtifactInput {
    pub id: String,
    #[serde(rename = "media_type")]
    pub media_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub renderer: Option<Value>,
}

impl ConfirmationArtifactInput {
    pub fn inline_text(id: impl Into<String>, content: impl Into<String>) -> Self {
        Self::inline(id, "text/plain", content)
    }

    pub fn inline_markdown(id: impl Into<String>, content: impl Into<String>) -> Self {
        Self::inline(id, "text/markdown", content)
    }

    pub fn inline_json(id: impl Into<String>, value: &Value) -> Result<Self> {
        Ok(Self::inline(id, "application/json", canonical_json(value)?))
    }

    pub fn fetched_uri(
        id: impl Into<String>,
        media_type: impl Into<String>,
        uri: impl Into<String>,
        sha256: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            media_type: media_type.into(),
            content: None,
            uri: Some(uri.into()),
            sha256: Some(sha256.into()),
            renderer: None,
        }
    }

    pub fn with_renderer(mut self, renderer: RendererRequirement) -> Self {
        self.renderer = Some(renderer.into_value());
        self
    }

    fn inline(
        id: impl Into<String>,
        media_type: impl Into<String>,
        content: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            media_type: media_type.into(),
            content: Some(content.into()),
            uri: None,
            sha256: None,
            renderer: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RendererRequirement {
    pub id: String,
    pub required: bool,
    pub version: Option<String>,
}

impl RendererRequirement {
    pub fn required(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            required: true,
            version: None,
        }
    }

    pub fn optional(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            required: false,
            version: None,
        }
    }

    pub fn version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    pub fn into_value(self) -> Value {
        let mut renderer = Map::new();
        renderer.insert("id".to_string(), Value::String(self.id));
        renderer.insert("required".to_string(), Value::Bool(self.required));
        if let Some(version) = self.version {
            renderer.insert("version".to_string(), Value::String(version));
        }
        Value::Object(renderer)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryChannel {
    channel_type: String,
    url: Option<String>,
}

impl DeliveryChannel {
    pub fn pull() -> Self {
        Self {
            channel_type: "pull".to_string(),
            url: None,
        }
    }

    pub fn webhook(url: impl Into<String>) -> Self {
        Self {
            channel_type: "webhook".to_string(),
            url: Some(url.into()),
        }
    }

    pub fn redirect(url: impl Into<String>) -> Self {
        Self {
            channel_type: "redirect".to_string(),
            url: Some(url.into()),
        }
    }

    fn into_value(self) -> Value {
        let mut channel = Map::new();
        channel.insert("type".to_string(), Value::String(self.channel_type));
        if let Some(url) = self.url {
            channel.insert("url".to_string(), Value::String(url));
        }
        Value::Object(channel)
    }
}

pub fn completion_delivery_async(channels: Vec<DeliveryChannel>) -> Value {
    serde_json::json!({
        "mode": "async",
        "channels": channels.into_iter().map(DeliveryChannel::into_value).collect::<Vec<_>>()
    })
}

pub fn completion_delivery_sync(channels: Vec<DeliveryChannel>) -> Value {
    serde_json::json!({
        "mode": "sync",
        "channels": channels.into_iter().map(DeliveryChannel::into_value).collect::<Vec<_>>()
    })
}

#[derive(Clone, Debug)]
pub struct ConfirmationRequestInput {
    pub account_id: String,
    pub requester_id: String,
    pub requester_display_name: Option<String>,
    pub responder: Value,
    pub artifacts: Vec<ConfirmationArtifactInput>,
    pub expires_at: String,
    pub workflow_template_id: String,
    pub audiences: Option<Value>,
    pub disclosure_policy: Option<Value>,
    pub evidence_policy: Option<Value>,
    pub notification_policy: Option<Value>,
    pub completion_delivery: Option<Value>,
    pub metadata: Option<Value>,
}

pub fn confirmation_request_body(input: ConfirmationRequestInput) -> Result<Value> {
    let artifacts = input
        .artifacts
        .into_iter()
        .map(serde_json::to_value)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(serde_json::json!({
      "account_id": input.account_id,
      "requester": {
        "id": input.requester_id,
        "display_name": input.requester_display_name,
      },
      "responder": input.responder,
      "artifacts": artifacts,
      "audiences": input.audiences.unwrap_or_else(default_audiences),
      "disclosure_policy": input.disclosure_policy.unwrap_or_else(default_disclosure_policy),
      "evidence_policy": input.evidence_policy.unwrap_or_else(default_evidence_policy),
      "notification_policy": input.notification_policy.unwrap_or_else(default_notification_policy),
      "completion_delivery": input.completion_delivery.unwrap_or_else(default_completion_delivery),
      "workflow_template_id": input.workflow_template_id,
      "expires_at": input.expires_at,
      "metadata": input.metadata.unwrap_or_else(|| serde_json::json!({})),
    }))
}

pub fn create_multi_artifact_confirmation_request(
    mut input: ConfirmationRequestInput,
) -> Result<Value> {
    input.workflow_template_id = MULTI_ARTIFACT_REVIEW_WORKFLOW.to_string();
    confirmation_request_body(input)
}

#[derive(Clone, Debug)]
pub struct IdentityConfirmationRequestInput {
    pub account_id: String,
    pub requester_id: String,
    pub app_name: String,
    pub responder: Value,
    pub expires_at: String,
    pub prompt: Option<String>,
    pub identity_label: Option<String>,
    pub metadata: Option<Value>,
}

pub fn create_login_confirmation_request(input: IdentityConfirmationRequestInput) -> Result<Value> {
    let prompt = input.prompt.clone().unwrap_or_else(|| {
        format!(
            "You would like to share your identity with {}.",
            input.app_name
        )
    });
    identity_confirmation_request(input, "login_prompt", &prompt)
}

pub fn create_session_refresh_confirmation_request(
    input: IdentityConfirmationRequestInput,
) -> Result<Value> {
    let prompt = input.prompt.clone().unwrap_or_else(|| {
        input
            .identity_label
            .as_ref()
            .map(|label| {
                format!(
                    "You are still {} and wish to resume your session with {}.",
                    label, input.app_name
                )
            })
            .unwrap_or_else(|| format!("You wish to resume your session with {}.", input.app_name))
    });
    identity_confirmation_request(input, "session_refresh_prompt", &prompt)
}

fn identity_confirmation_request(
    input: IdentityConfirmationRequestInput,
    artifact_id: &str,
    prompt: &str,
) -> Result<Value> {
    confirmation_request_body(ConfirmationRequestInput {
        account_id: input.account_id,
        requester_id: input.requester_id,
        requester_display_name: Some(input.app_name),
        responder: input.responder,
        artifacts: vec![ConfirmationArtifactInput {
            id: artifact_id.to_string(),
            media_type: "text/markdown".to_string(),
            content: Some(prompt.to_string()),
            uri: None,
            sha256: None,
            renderer: None,
        }],
        expires_at: input.expires_at,
        workflow_template_id: TIGHT_CONFIRM_WORKFLOW.to_string(),
        audiences: None,
        disclosure_policy: None,
        evidence_policy: None,
        notification_policy: None,
        completion_delivery: None,
        metadata: input.metadata,
    })
}

fn default_audiences() -> Value {
    serde_json::json!([{
      "id": "primary_audience",
      "mode": "restricted",
      "members": [{ "type": "requester" }, { "type": "responder" }]
    }])
}

fn default_disclosure_policy() -> Value {
    serde_json::json!({
      "rules": [{ "audience": "primary_audience", "target": "artifacts", "access": "full" }]
    })
}

fn default_evidence_policy() -> Value {
    serde_json::json!({
      "any_of": [{ "all_of": [{ "method": "oauth", "provider": "google" }] }]
    })
}

fn default_notification_policy() -> Value {
    serde_json::json!({ "mode": "requester_managed", "channels": [] })
}

fn default_completion_delivery() -> Value {
    serde_json::json!({ "mode": "async", "channels": [{ "type": "pull" }] })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    pub kid: Option<String>,
    pub alg: Option<String>,
    #[serde(rename = "use")]
    pub key_use: Option<String>,
    pub n: String,
    pub e: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct JwtHeader {
    pub alg: String,
    pub typ: Option<String>,
    pub kid: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct ConfirmationResponseClaims {
    pub iss: Option<String>,
    pub aud: String,
    pub sub: Option<String>,
    #[serde(rename = "request_id")]
    pub request_id: Option<String>,
    #[serde(rename = "receipt_id")]
    pub receipt_id: String,
    #[serde(rename = "workflow_template_id")]
    pub workflow_template_id: String,
    pub decision: String,
    #[serde(rename = "confirmed_at")]
    pub confirmed_at: Option<u64>,
    pub iat: Option<u64>,
    pub exp: Option<u64>,
    pub jti: Option<String>,
    #[serde(rename = "artifact_set_hash")]
    pub artifact_set_hash: Option<String>,
    #[serde(rename = "registered_origin")]
    pub registered_origin: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct VerifyConfirmationResponseInput<'a> {
    pub issuer: Option<&'a str>,
    pub audience: Option<&'a str>,
    pub workflow_template_id: Option<&'a str>,
    pub registered_origin: Option<&'a str>,
    pub now: Option<u64>,
    pub require_confirmed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedConfirmationResponse {
    pub header: JwtHeader,
    pub claims: ConfirmationResponseClaims,
}

pub trait ResponseReplayCache {
    fn check_and_store(&mut self, jti: &str, receipt_id: &str) -> Result<()>;
}

#[derive(Clone, Debug, Default)]
pub struct MemoryResponseReplayCache {
    jtis: HashSet<String>,
    receipt_ids: HashSet<String>,
}

impl ResponseReplayCache for MemoryResponseReplayCache {
    fn check_and_store(&mut self, jti: &str, receipt_id: &str) -> Result<()> {
        if self.jtis.contains(jti) || self.receipt_ids.contains(receipt_id) {
            return Err(ConfirmSdkError::ReplayDetected);
        }
        self.jtis.insert(jti.to_string());
        self.receipt_ids.insert(receipt_id.to_string());
        Ok(())
    }
}

pub fn verify_confirmation_response_token(
    token: &str,
    jwks: &Jwks,
    input: VerifyConfirmationResponseInput<'_>,
    mut replay_cache: Option<&mut dyn ResponseReplayCache>,
) -> Result<VerifiedConfirmationResponse> {
    let parts = token.split('.').collect::<Vec<_>>();
    if parts.len() != 3 {
        return Err(ConfirmSdkError::InvalidJwtShape);
    }
    let header: JwtHeader = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0])?)?;
    if header.typ.as_deref() != Some(CONFIRM_RESPONSE_TOKEN_TYPE) {
        return Err(ConfirmSdkError::UnexpectedTokenType(
            header.typ.unwrap_or_else(|| "missing".to_string()),
        ));
    }
    if header.alg != REQUESTER_SIGNATURE_ALGORITHM {
        return Err(ConfirmSdkError::UnsupportedTokenAlgorithm(header.alg));
    }
    let kid = header
        .kid
        .as_deref()
        .ok_or(ConfirmSdkError::MissingTokenKeyId)?;
    let jwk = jwks
        .keys
        .iter()
        .find(|key| key.kid.as_deref() == Some(kid))
        .ok_or_else(|| ConfirmSdkError::MissingJwk(kid.to_string()))?;
    if jwk.alg.as_deref().is_some_and(|alg| alg != header.alg) {
        return Err(ConfirmSdkError::JwkAlgorithmMismatch(kid.to_string()));
    }
    let public_key = jwk_rsa_public_key(jwk)?;
    let signature = pkcs1v15::Signature::try_from(URL_SAFE_NO_PAD.decode(parts[2])?.as_slice())
        .map_err(|err| ConfirmSdkError::InvalidPublicKey(err.to_string()))?;
    let verifying_key = pkcs1v15::VerifyingKey::<Sha256>::new(public_key);
    verifying_key
        .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
        .map_err(|_| ConfirmSdkError::InvalidTokenSignature)?;
    let claims: ConfirmationResponseClaims =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1])?)?;
    let now = input.now.unwrap_or_else(current_unix_seconds);
    if claims.exp.is_some_and(|exp| exp <= now) {
        return Err(ConfirmSdkError::TokenExpired);
    }
    if input
        .issuer
        .is_some_and(|issuer| claims.iss.as_deref() != Some(issuer))
    {
        return Err(ConfirmSdkError::IssuerMismatch);
    }
    if input
        .audience
        .is_some_and(|audience| claims.aud != audience)
    {
        return Err(ConfirmSdkError::AudienceMismatch);
    }
    if input
        .workflow_template_id
        .is_some_and(|workflow| claims.workflow_template_id != workflow)
    {
        return Err(ConfirmSdkError::WorkflowTemplateMismatch);
    }
    if input.require_confirmed && claims.decision != "confirmed" {
        return Err(ConfirmSdkError::DecisionNotConfirmed);
    }
    if claims.receipt_id.trim().is_empty() {
        return Err(ConfirmSdkError::MissingReceiptId);
    }
    if input
        .registered_origin
        .is_some_and(|origin| claims.registered_origin.as_deref() != Some(origin))
    {
        return Err(ConfirmSdkError::RegisteredOriginMismatch);
    }
    if let Some(cache) = replay_cache.as_mut() {
        let jti = claims
            .jti
            .as_deref()
            .filter(|jti| !jti.trim().is_empty())
            .ok_or(ConfirmSdkError::MissingJti)?;
        cache.check_and_store(jti, &claims.receipt_id)?;
    }
    Ok(VerifiedConfirmationResponse { header, claims })
}

pub fn verify_confirmation_receipt(
    receipt: ConfirmationReceipt,
    jwks: &Jwks,
    input: VerifyConfirmationResponseInput<'_>,
    replay_cache: Option<&mut dyn ResponseReplayCache>,
) -> Result<VerifiedConfirmationReceipt> {
    let signed_payload_hash = receipt
        .attestation
        .get("signed_payload_hash")
        .and_then(Value::as_str)
        .ok_or(ConfirmSdkError::MissingSignedPayloadHash)?;
    if !signed_payload_hash.starts_with("sha256:") {
        return Err(ConfirmSdkError::InvalidSignedPayloadHash);
    }
    let response_token = receipt
        .response_token
        .as_deref()
        .ok_or(ConfirmSdkError::MissingResponseToken)?;
    let response = verify_confirmation_response_token(response_token, jwks, input, replay_cache)?;
    if response.claims.receipt_id != receipt.receipt_id {
        return Err(ConfirmSdkError::ReceiptIdMismatch);
    }
    Ok(VerifiedConfirmationReceipt { receipt, response })
}

fn jwk_rsa_public_key(jwk: &Jwk) -> Result<RsaPublicKey> {
    if jwk.kty != "RSA" {
        return Err(ConfirmSdkError::InvalidPublicKey(format!(
            "unsupported kty {}",
            jwk.kty
        )));
    }
    let n = BigUint::from_bytes_be(&URL_SAFE_NO_PAD.decode(&jwk.n)?);
    let e = BigUint::from_bytes_be(&URL_SAFE_NO_PAD.decode(&jwk.e)?);
    RsaPublicKey::new(n, e).map_err(|err| ConfirmSdkError::InvalidPublicKey(err.to_string()))
}

fn current_unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "http")]
    use axum::{
        body::Bytes,
        extract::State,
        http::{HeaderMap, StatusCode},
        routing::post,
        Router,
    };
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use rsa::{
        pkcs8::{EncodePrivateKey, LineEnding},
        traits::PublicKeyParts,
    };
    #[cfg(feature = "http")]
    use std::sync::Arc;
    #[cfg(feature = "http")]
    use tokio::sync::Mutex;

    fn test_private_key() -> RsaPrivateKey {
        RsaPrivateKey::new(&mut OsRng, 2048).expect("rsa key")
    }

    fn test_jwk(public_key: &RsaPublicKey, kid: &str) -> Jwk {
        Jwk {
            kty: "RSA".to_string(),
            kid: Some(kid.to_string()),
            alg: Some("RS256".to_string()),
            key_use: Some("sig".to_string()),
            n: base64_url(public_key.n().to_bytes_be()),
            e: base64_url(public_key.e().to_bytes_be()),
        }
    }

    #[test]
    fn stable_request_body_hash_matches_service_fixture() {
        assert_eq!(
            signed_request_body_sha256(br#"{"ok":true}"#),
            "sha256:QGLtr3UPuAdOfoPgyQKMlOMkaKi28WFHdDKO8EUVD5M"
        );
    }

    #[test]
    fn canonical_json_sorts_object_keys_recursively() {
        let value = serde_json::json!({
          "z": 1,
          "a": { "y": 2, "b": 3 },
          "list": [{ "d": 4, "c": 5 }]
        });
        assert_eq!(
            canonical_json(&value).expect("canonical json"),
            r#"{"a":{"b":3,"y":2},"list":[{"c":5,"d":4}],"z":1}"#
        );
    }

    #[test]
    fn sign_confirmation_request_emits_origin_bound_rs256_headers() {
        let private_key = test_private_key();
        let public_key = RsaPublicKey::from(&private_key);
        let private_key_pem = private_key
            .to_pkcs8_pem(LineEnding::LF)
            .expect("private pem")
            .to_string();
        let signed = sign_confirmation_request(SignConfirmationRequestInput {
            requester_id: "app_123".to_string(),
            key_id: "kid_123".to_string(),
            private_key_pem,
            origin: "https://requester.example.com".to_string(),
            created_at: 1_700_000_000,
            expires_at: 1_700_000_300,
            nonce: "nonce_123".to_string(),
            body: serde_json::json!({
              "requester": { "id": "app_123" },
              "account_id": "acct_123"
            }),
        })
        .expect("signed request");

        assert_eq!(
            signed
                .headers
                .get("x-confirm-requester-id")
                .map(String::as_str),
            Some("app_123")
        );
        assert_eq!(
            signed.headers.get("x-confirm-origin").map(String::as_str),
            Some("https://requester.example.com")
        );
        assert!(requester_signature_payload(&signed.envelope)
            .contains("origin:https://requester.example.com"));

        let signature = pkcs1v15::Signature::try_from(
            URL_SAFE_NO_PAD
                .decode(&signed.envelope.signature)
                .expect("signature b64")
                .as_slice(),
        )
        .expect("signature");
        let verifying_key = pkcs1v15::VerifyingKey::<Sha256>::new(public_key);
        verifying_key
            .verify(
                requester_signature_payload(&signed.envelope).as_bytes(),
                &signature,
            )
            .expect("signature verifies");
    }

    #[test]
    fn identity_confirmation_builders_create_tight_workflows() {
        let login = create_login_confirmation_request(IdentityConfirmationRequestInput {
            account_id: "acct_123".to_string(),
            requester_id: "app_123".to_string(),
            app_name: "Example App".to_string(),
            responder: serde_json::json!({ "email": "person@example.com" }),
            expires_at: "2026-06-25T00:00:00Z".to_string(),
            prompt: None,
            identity_label: None,
            metadata: None,
        })
        .expect("login body");
        assert_eq!(
            login
                .pointer("/workflow_template_id")
                .and_then(Value::as_str),
            Some(TIGHT_CONFIRM_WORKFLOW)
        );
        assert_eq!(
            login
                .pointer("/artifacts/0/media_type")
                .and_then(Value::as_str),
            Some("text/markdown")
        );
        assert!(login
            .pointer("/artifacts/0/content")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .contains("share your identity with Example App"));

        let refresh =
            create_session_refresh_confirmation_request(IdentityConfirmationRequestInput {
                account_id: "acct_123".to_string(),
                requester_id: "app_123".to_string(),
                app_name: "Example App".to_string(),
                responder: serde_json::json!({ "email": "person@example.com" }),
                expires_at: "2026-06-25T00:00:00Z".to_string(),
                prompt: None,
                identity_label: Some("person@example.com".to_string()),
                metadata: None,
            })
            .expect("refresh body");
        let prompt = refresh
            .pointer("/artifacts/0/content")
            .and_then(Value::as_str)
            .unwrap_or_default();
        assert!(prompt.contains("still person@example.com"));
        assert!(prompt.contains("resume your session with Example App"));
    }

    #[test]
    fn multi_artifact_builder_sets_artifacts_renderers_and_delivery() {
        let json_artifact = ConfirmationArtifactInput::inline_json(
            "artifact_json",
            &serde_json::json!({ "z": 1, "a": 2 }),
        )
        .expect("json artifact")
        .with_renderer(RendererRequirement::required("json/v1").version("v1"));
        let pdf_artifact = ConfirmationArtifactInput::fetched_uri(
            "artifact_pdf",
            "application/pdf",
            "https://requester.example.com/disclosure.pdf",
            "sha256:abc123",
        )
        .with_renderer(RendererRequirement::required("pdf/v1"));

        let body = create_multi_artifact_confirmation_request(ConfirmationRequestInput {
            account_id: "acct_123".to_string(),
            requester_id: "app_123".to_string(),
            requester_display_name: Some("Example App".to_string()),
            responder: serde_json::json!({ "email": "person@example.com" }),
            artifacts: vec![
                ConfirmationArtifactInput::inline_markdown("statement", "Please review."),
                json_artifact,
                pdf_artifact,
            ],
            expires_at: "2026-06-25T00:00:00Z".to_string(),
            workflow_template_id: String::new(),
            audiences: None,
            disclosure_policy: None,
            evidence_policy: None,
            notification_policy: None,
            completion_delivery: Some(completion_delivery_async(vec![
                DeliveryChannel::pull(),
                DeliveryChannel::webhook("https://requester.example.com/webhooks/confirm"),
            ])),
            metadata: None,
        })
        .expect("multi artifact body");

        assert_eq!(
            body.pointer("/workflow_template_id")
                .and_then(Value::as_str),
            Some(MULTI_ARTIFACT_REVIEW_WORKFLOW)
        );
        assert_eq!(
            body.pointer("/artifacts/1/content").and_then(Value::as_str),
            Some(r#"{"a":2,"z":1}"#)
        );
        assert_eq!(
            body.pointer("/artifacts/1/renderer/id")
                .and_then(Value::as_str),
            Some("json/v1")
        );
        assert_eq!(
            body.pointer("/artifacts/2/uri").and_then(Value::as_str),
            Some("https://requester.example.com/disclosure.pdf")
        );
        assert_eq!(
            body.pointer("/artifacts/2/sha256").and_then(Value::as_str),
            Some("sha256:abc123")
        );
        assert_eq!(
            body.pointer("/completion_delivery/channels/1/type")
                .and_then(Value::as_str),
            Some("webhook")
        );
    }

    #[test]
    fn verify_confirmation_response_token_checks_claims_origin_and_replay() {
        let private_key = test_private_key();
        let public_key = RsaPublicKey::from(&private_key);
        let private_key_pem = private_key
            .to_pkcs8_pem(LineEnding::LF)
            .expect("private pem")
            .to_string();
        let kid = "signing_1";
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());
        header.typ = Some(CONFIRM_RESPONSE_TOKEN_TYPE.to_string());
        let token = encode(
            &header,
            &serde_json::json!({
              "iss": "https://confirm.example.com",
              "aud": "app_123",
              "sub": "person@example.com",
              "request_id": "cr_123",
              "receipt_id": "rcpt_123",
              "workflow_template_id": TIGHT_CONFIRM_WORKFLOW,
              "decision": "confirmed",
              "iat": 1_700_000_000u64,
              "exp": 4_102_444_800u64,
              "jti": "jti_123",
              "artifact_set_hash": "sha256:abc",
              "registered_origin": "https://requester.example.com"
            }),
            &EncodingKey::from_rsa_pem(private_key_pem.as_bytes()).expect("encoding key"),
        )
        .expect("jwt");
        let jwks = Jwks {
            keys: vec![test_jwk(&public_key, kid)],
        };
        let mut replay_cache = MemoryResponseReplayCache::default();
        let verified = verify_confirmation_response_token(
            &token,
            &jwks,
            VerifyConfirmationResponseInput {
                issuer: Some("https://confirm.example.com"),
                audience: Some("app_123"),
                workflow_template_id: Some(TIGHT_CONFIRM_WORKFLOW),
                registered_origin: Some("https://requester.example.com"),
                now: Some(1_700_000_100),
                require_confirmed: true,
            },
            Some(&mut replay_cache),
        )
        .expect("verified token");
        assert_eq!(verified.claims.receipt_id, "rcpt_123");
        assert_eq!(verified.claims.jti.as_deref(), Some("jti_123"));

        let replay = verify_confirmation_response_token(
            &token,
            &jwks,
            VerifyConfirmationResponseInput {
                now: Some(1_700_000_100),
                require_confirmed: true,
                ..Default::default()
            },
            Some(&mut replay_cache),
        );
        assert!(matches!(replay, Err(ConfirmSdkError::ReplayDetected)));

        let wrong_origin = verify_confirmation_response_token(
            &token,
            &jwks,
            VerifyConfirmationResponseInput {
                registered_origin: Some("https://evil.example.com"),
                now: Some(1_700_000_100),
                require_confirmed: true,
                ..Default::default()
            },
            None,
        );
        assert!(matches!(
            wrong_origin,
            Err(ConfirmSdkError::RegisteredOriginMismatch)
        ));
    }

    #[test]
    fn verify_confirmation_receipt_checks_response_token_and_receipt_id() {
        let private_key = test_private_key();
        let public_key = RsaPublicKey::from(&private_key);
        let private_key_pem = private_key
            .to_pkcs8_pem(LineEnding::LF)
            .expect("private pem")
            .to_string();
        let kid = "signing_1";
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());
        header.typ = Some(CONFIRM_RESPONSE_TOKEN_TYPE.to_string());
        let token = encode(
            &header,
            &serde_json::json!({
              "iss": "https://confirm.example.com",
              "aud": "app_123",
              "request_id": "cr_123",
              "receipt_id": "rcpt_123",
              "workflow_template_id": TIGHT_CONFIRM_WORKFLOW,
              "decision": "confirmed",
              "exp": 4_102_444_800u64,
              "jti": "jti_123",
              "registered_origin": "https://requester.example.com"
            }),
            &EncodingKey::from_rsa_pem(private_key_pem.as_bytes()).expect("encoding key"),
        )
        .expect("jwt");
        let jwks = Jwks {
            keys: vec![test_jwk(&public_key, kid)],
        };
        let receipt = ConfirmationReceipt {
            receipt_id: "rcpt_123".to_string(),
            request_id: "cr_123".to_string(),
            status: "confirmed".to_string(),
            artifacts: Vec::new(),
            decision: serde_json::json!({ "result": "confirmed" }),
            evidence_records: Vec::new(),
            satisfied_evidence_branch: None,
            created_at: Some(1_700_000_100),
            attestation: serde_json::json!({
              "signed_payload_hash": "sha256:abc123"
            }),
            response_token: Some(token),
        };
        let mut replay_cache = MemoryResponseReplayCache::default();
        let verified = verify_confirmation_receipt(
            receipt.clone(),
            &jwks,
            VerifyConfirmationResponseInput {
                issuer: Some("https://confirm.example.com"),
                audience: Some("app_123"),
                registered_origin: Some("https://requester.example.com"),
                now: Some(1_700_000_100),
                require_confirmed: true,
                ..Default::default()
            },
            Some(&mut replay_cache),
        )
        .expect("verified receipt");
        assert_eq!(verified.receipt.receipt_id, "rcpt_123");
        assert_eq!(verified.response.claims.receipt_id, "rcpt_123");

        let mut mismatched = receipt;
        mismatched.receipt_id = "rcpt_other".to_string();
        let mismatch = verify_confirmation_receipt(
            mismatched,
            &jwks,
            VerifyConfirmationResponseInput {
                now: Some(1_700_000_100),
                require_confirmed: true,
                ..Default::default()
            },
            None,
        );
        assert!(matches!(mismatch, Err(ConfirmSdkError::ReceiptIdMismatch)));
    }

    #[cfg(feature = "http")]
    #[tokio::test]
    async fn submit_confirmation_request_posts_signed_body_and_headers() {
        #[derive(Clone, Debug, Default)]
        struct Capture {
            body: Arc<Mutex<Option<String>>>,
            origin: Arc<Mutex<Option<String>>>,
            signature: Arc<Mutex<Option<String>>>,
        }

        async fn handler(
            State(capture): State<Capture>,
            headers: HeaderMap,
            body: Bytes,
        ) -> (StatusCode, &'static str) {
            *capture.body.lock().await = Some(String::from_utf8(body.to_vec()).expect("body utf8"));
            *capture.origin.lock().await = headers
                .get("x-confirm-origin")
                .and_then(|value| value.to_str().ok())
                .map(str::to_string);
            *capture.signature.lock().await = headers
                .get("x-confirm-signature")
                .and_then(|value| value.to_str().ok())
                .map(str::to_string);
            (
                StatusCode::OK,
                r#"{"request_id":"cr_123","workflow_id":"wf_123","workflow_url":"https://confirm.example.com/request/wf_123","status":"submitted","expires_at":"2026-06-25T00:00:00Z"}"#,
            )
        }

        let capture = Capture::default();
        let app = Router::new()
            .route("/v1/confirmation-requests", post(handler))
            .with_state(capture.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("test server");
        });

        let private_key = test_private_key();
        let private_key_pem = private_key
            .to_pkcs8_pem(LineEnding::LF)
            .expect("private pem")
            .to_string();
        let signed = sign_confirmation_request(SignConfirmationRequestInput {
            requester_id: "app_123".to_string(),
            key_id: "kid_123".to_string(),
            private_key_pem,
            origin: "https://requester.example.com".to_string(),
            created_at: 1_700_000_000,
            expires_at: 1_700_000_300,
            nonce: "nonce_123".to_string(),
            body: serde_json::json!({ "account_id": "acct_123" }),
        })
        .expect("signed request");
        let client = ConfirmHttpClient::new(format!("http://{}", addr)).expect("http client");
        let response = client
            .submit_confirmation_request(&signed)
            .await
            .expect("submit response");

        assert_eq!(response.request_id, "cr_123");
        assert_eq!(response.workflow_id, "wf_123");
        assert_eq!(
            capture.origin.lock().await.as_deref(),
            Some("https://requester.example.com")
        );
        assert_eq!(
            capture.signature.lock().await.as_deref(),
            Some(signed.envelope.signature.as_str())
        );
        assert_eq!(
            capture.body.lock().await.as_deref(),
            Some(signed.body.as_str())
        );
    }

    #[cfg(feature = "http")]
    #[tokio::test]
    async fn submit_confirmation_request_surfaces_api_errors() {
        async fn handler() -> (StatusCode, &'static str) {
            (StatusCode::BAD_REQUEST, "bad signed request")
        }

        let app = Router::new().route("/v1/confirmation-requests", post(handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("test server");
        });

        let signed = SignedConfirmationRequest {
            body: "{}".to_string(),
            envelope: SignedRequestEnvelope {
                requester_id: "app_123".to_string(),
                key_id: "kid_123".to_string(),
                algorithm: "RS256".to_string(),
                created_at: 1,
                expires_at: 2,
                nonce: "nonce".to_string(),
                origin: "https://requester.example.com".to_string(),
                body_sha256: signed_request_body_sha256(b"{}"),
                signature: "signature".to_string(),
            },
            headers: BTreeMap::new(),
        };
        let client = ConfirmHttpClient::new(format!("http://{}", addr)).expect("http client");
        let err = client
            .submit_confirmation_request(&signed)
            .await
            .expect_err("api error");
        assert!(matches!(
            err,
            ConfirmSdkError::ConfirmApi {
                status: 400,
                body
            } if body == "bad signed request"
        ));
    }
}
