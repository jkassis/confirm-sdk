import { createHash, createPrivateKey, createPublicKey, createSign, createVerify, type JsonWebKey, type KeyObject } from "node:crypto";

export const REQUESTER_SIGNATURE_ALGORITHM = "RS256";
export const CONFIRM_RESPONSE_TOKEN_TYPE = "confirm-response+jwt";
export const TIGHT_CONFIRM_WORKFLOW = "single_responder.tight_confirm.v1";
export const MULTI_ARTIFACT_REVIEW_WORKFLOW = "single_responder.multi_artifact_review.v1";

export class ConfirmSdkError extends Error {
  constructor(
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "ConfirmSdkError";
  }
}

export interface SignedRequestEnvelope {
  requesterId: string;
  keyId: string;
  algorithm: string;
  createdAt: number;
  expiresAt: number;
  nonce: string;
  origin: string;
  bodySha256: string;
  signature: string;
}

export interface SignedConfirmationRequest {
  body: string;
  envelope: SignedRequestEnvelope;
  headers: Record<string, string>;
}

export interface ConfirmationRequestCreateResponse {
  request_id: string;
  workflow_id: string;
  workflow_url: string;
  status: string;
  expires_at: string;
}

export interface ConfirmationReceiptResponse {
  receipt: ConfirmationReceipt;
}

export interface ConfirmationReceiptDisclosureResponse {
  receipt: unknown;
  disclosureRecord: unknown;
}

export interface ConfirmationReceipt {
  receiptId: string;
  requestId: string;
  status: string;
  artifacts?: unknown[];
  decision?: unknown;
  evidenceRecords?: unknown[];
  satisfiedEvidenceBranch?: unknown;
  createdAt?: number;
  attestation?: Record<string, unknown>;
  responseToken?: string;
}

export interface VerifiedConfirmationReceipt {
  receipt: ConfirmationReceipt;
  response: VerifiedConfirmationResponse;
}

export type DisclosureAudience = "requester" | "responder" | "operator";

export class ConfirmHttpClient {
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;

  constructor(baseUrl: string, fetchImpl: typeof fetch = fetch) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    if (this.baseUrl.length === 0) {
      throw new ConfirmSdkError("invalid_url", "invalid URL: empty base URL");
    }
    this.fetchImpl = fetchImpl;
  }

  submitConfirmationRequest(signed: SignedConfirmationRequest, signal?: AbortSignal): Promise<ConfirmationRequestCreateResponse> {
    return submitConfirmationRequest(this.fetchImpl, this.baseUrl, signed, signal);
  }

  getConfirmationReceipt(receiptId: string, signal?: AbortSignal): Promise<ConfirmationReceiptResponse> {
    return getJson(this.fetchImpl, `${this.baseUrl}/v1/confirmation-receipts/${receiptId}`, {}, signal);
  }

  getReceiptDisclosure(receiptId: string, audience: DisclosureAudience, signal?: AbortSignal): Promise<ConfirmationReceiptDisclosureResponse> {
    return getJson(this.fetchImpl, `${this.baseUrl}/v1/confirmation-receipts/${receiptId}/disclosure`, { "x-confirm-audience": audience }, signal);
  }
}

export async function submitConfirmationRequest(
  fetchImpl: typeof fetch,
  baseUrl: string,
  signed: SignedConfirmationRequest,
  signal?: AbortSignal,
): Promise<ConfirmationRequestCreateResponse> {
  const init: RequestInit = {
    method: "POST",
    headers: signed.headers,
    body: signed.body,
  };
  if (signal !== undefined) {
    init.signal = signal;
  }
  const response = await fetchImpl(`${baseUrl.replace(/\/+$/, "")}/v1/confirmation-requests`, init);
  return responseJson(response);
}

async function getJson<T>(fetchImpl: typeof fetch, url: string, headers: Record<string, string>, signal?: AbortSignal): Promise<T> {
  const init: RequestInit = { method: "GET", headers };
  if (signal !== undefined) {
    init.signal = signal;
  }
  return responseJson(await fetchImpl(url, init));
}

async function responseJson<T>(response: Response): Promise<T> {
  const body = await response.text();
  if (!response.ok) {
    throw new ConfirmSdkError("confirm_api", `Confirm API returned ${response.status}: ${body}`);
  }
  return JSON.parse(body) as T;
}

export interface SignConfirmationRequestInput {
  requesterId: string;
  keyId: string;
  privateKeyPem: string;
  origin: string;
  createdAt: number;
  expiresAt: number;
  nonce: string;
  body: unknown;
}

export interface SignConfirmationRequestBodyInput {
  body: string;
  requesterId: string;
  keyId: string;
  privateKeyPem: string;
  origin: string;
  createdAt: number;
  expiresAt: number;
  nonce: string;
}

export function signConfirmationRequest(input: SignConfirmationRequestInput): SignedConfirmationRequest {
  return signConfirmationRequestBody({ ...input, body: canonicalJson(input.body) });
}

export function signConfirmationRequestBody(input: SignConfirmationRequestBodyInput): SignedConfirmationRequest {
  const privateKey = createPrivateKey(input.privateKeyPem);
  const envelope: SignedRequestEnvelope = {
    requesterId: input.requesterId,
    keyId: input.keyId,
    algorithm: REQUESTER_SIGNATURE_ALGORITHM,
    createdAt: input.createdAt,
    expiresAt: input.expiresAt,
    nonce: input.nonce,
    origin: input.origin,
    bodySha256: signedRequestBodySha256(Buffer.from(input.body)),
    signature: "",
  };
  const signer = createSign("RSA-SHA256");
  signer.update(requesterSignaturePayload(envelope));
  signer.end();
  envelope.signature = base64Url(signer.sign(privateKey));
  return {
    body: input.body,
    envelope,
    headers: {
      "content-type": "application/json",
      "x-confirm-requester-id": envelope.requesterId,
      "x-confirm-key-id": envelope.keyId,
      "x-confirm-algorithm": envelope.algorithm,
      "x-confirm-created-at": String(envelope.createdAt),
      "x-confirm-expires-at": String(envelope.expiresAt),
      "x-confirm-nonce": envelope.nonce,
      "x-confirm-origin": envelope.origin,
      "x-confirm-body-sha256": envelope.bodySha256,
      "x-confirm-signature": envelope.signature,
    },
  };
}

export function requesterSignaturePayload(envelope: SignedRequestEnvelope): string {
  return [
    "confirm-request-v1",
    `requester_id:${envelope.requesterId}`,
    `key_id:${envelope.keyId}`,
    `algorithm:${envelope.algorithm}`,
    `created_at:${envelope.createdAt}`,
    `expires_at:${envelope.expiresAt}`,
    `nonce:${envelope.nonce}`,
    `origin:${envelope.origin}`,
    `body_sha256:${envelope.bodySha256}`,
  ].join("\n");
}

export function signedRequestBodySha256(input: Buffer | Uint8Array | string): string {
  return `sha256:${sha256Base64Url(input)}`;
}

export function sha256Base64Url(input: Buffer | Uint8Array | string): string {
  return base64Url(createHash("sha256").update(input).digest());
}

export function base64Url(input: Buffer | Uint8Array | string): string {
  return Buffer.from(input).toString("base64url");
}

export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortJson(value));
}

function sortJson(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortJson);
  }
  if (value !== null && typeof value === "object") {
    const input = value as Record<string, unknown>;
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(input).sort()) {
      sorted[key] = sortJson(input[key]);
    }
    return sorted;
  }
  return value;
}

export interface ConfirmationArtifactInput {
  id: string;
  media_type: string;
  content?: string;
  uri?: string;
  sha256?: string;
  renderer?: Record<string, unknown>;
}

export function inlineTextArtifact(id: string, content: string): ConfirmationArtifactInput {
  return inlineArtifact(id, "text/plain", content);
}

export function inlineMarkdownArtifact(id: string, content: string): ConfirmationArtifactInput {
  return inlineArtifact(id, "text/markdown", content);
}

export function inlineJsonArtifact(id: string, value: unknown): ConfirmationArtifactInput {
  return inlineArtifact(id, "application/json", canonicalJson(value));
}

export function fetchedUriArtifact(id: string, mediaType: string, uri: string, sha256: string): ConfirmationArtifactInput {
  return { id, media_type: mediaType, uri, sha256 };
}

export function withRenderer(artifact: ConfirmationArtifactInput, renderer: RendererRequirement): ConfirmationArtifactInput {
  return { ...artifact, renderer: rendererRequirementValue(renderer) };
}

function inlineArtifact(id: string, mediaType: string, content: string): ConfirmationArtifactInput {
  return { id, media_type: mediaType, content };
}

export interface RendererRequirement {
  id: string;
  required: boolean;
  version?: string;
}

export function requiredRenderer(id: string): RendererRequirement {
  return { id, required: true };
}

export function optionalRenderer(id: string): RendererRequirement {
  return { id, required: false };
}

export function rendererRequirementValue(renderer: RendererRequirement): Record<string, unknown> {
  const out: Record<string, unknown> = { id: renderer.id, required: renderer.required };
  if (renderer.version !== undefined) {
    out.version = renderer.version;
  }
  return out;
}

export interface DeliveryChannel {
  type: "pull" | "webhook" | "redirect";
  url?: string;
}

export function pullDeliveryChannel(): DeliveryChannel {
  return { type: "pull" };
}

export function webhookDeliveryChannel(url: string): DeliveryChannel {
  return { type: "webhook", url };
}

export function redirectDeliveryChannel(url: string): DeliveryChannel {
  return { type: "redirect", url };
}

export function completionDeliveryAsync(channels: DeliveryChannel[]): Record<string, unknown> {
  return { mode: "async", channels };
}

export function completionDeliverySync(channels: DeliveryChannel[]): Record<string, unknown> {
  return { mode: "sync", channels };
}

export interface ConfirmationRequestInput {
  accountId: string;
  requesterId: string;
  requesterDisplayName?: string;
  responder: unknown;
  artifacts: ConfirmationArtifactInput[];
  expiresAt: string;
  workflowTemplateId: string;
  audiences?: unknown;
  disclosurePolicy?: unknown;
  evidencePolicy?: unknown;
  notificationPolicy?: unknown;
  completionDelivery?: unknown;
  metadata?: unknown;
}

export function confirmationRequestBody(input: ConfirmationRequestInput): Record<string, unknown> {
  return {
    account_id: input.accountId,
    requester: {
      id: input.requesterId,
      display_name: input.requesterDisplayName ?? null,
    },
    responder: input.responder,
    artifacts: input.artifacts,
    audiences: input.audiences ?? defaultAudiences(),
    disclosure_policy: input.disclosurePolicy ?? defaultDisclosurePolicy(),
    evidence_policy: input.evidencePolicy ?? defaultEvidencePolicy(),
    notification_policy: input.notificationPolicy ?? defaultNotificationPolicy(),
    completion_delivery: input.completionDelivery ?? defaultCompletionDelivery(),
    workflow_template_id: input.workflowTemplateId,
    expires_at: input.expiresAt,
    metadata: input.metadata ?? {},
  };
}

export function createMultiArtifactConfirmationRequest(input: Omit<ConfirmationRequestInput, "workflowTemplateId"> & { workflowTemplateId?: string }): Record<string, unknown> {
  return confirmationRequestBody({ ...input, workflowTemplateId: MULTI_ARTIFACT_REVIEW_WORKFLOW });
}

export interface IdentityConfirmationRequestInput {
  accountId: string;
  requesterId: string;
  appName: string;
  responder: unknown;
  expiresAt: string;
  prompt?: string;
  identityLabel?: string;
  metadata?: unknown;
}

export function createLoginConfirmationRequest(input: IdentityConfirmationRequestInput): Record<string, unknown> {
  const prompt = input.prompt ?? `You would like to share your identity with ${input.appName}.`;
  return identityConfirmationRequest(input, "login_prompt", prompt);
}

export function createSessionRefreshConfirmationRequest(input: IdentityConfirmationRequestInput): Record<string, unknown> {
  const prompt = input.prompt ?? (input.identityLabel === undefined
    ? `You wish to resume your session with ${input.appName}.`
    : `You are still ${input.identityLabel} and wish to resume your session with ${input.appName}.`);
  return identityConfirmationRequest(input, "session_refresh_prompt", prompt);
}

function identityConfirmationRequest(input: IdentityConfirmationRequestInput, artifactId: string, prompt: string): Record<string, unknown> {
  return confirmationRequestBody({
    accountId: input.accountId,
    requesterId: input.requesterId,
    requesterDisplayName: input.appName,
    responder: input.responder,
    artifacts: [inlineMarkdownArtifact(artifactId, prompt)],
    expiresAt: input.expiresAt,
    workflowTemplateId: TIGHT_CONFIRM_WORKFLOW,
    metadata: input.metadata,
  });
}

function defaultAudiences(): unknown {
  return [{ id: "primary_audience", mode: "restricted", members: [{ type: "requester" }, { type: "responder" }] }];
}

function defaultDisclosurePolicy(): unknown {
  return { rules: [{ audience: "primary_audience", target: "artifacts", access: "full" }] };
}

function defaultEvidencePolicy(): unknown {
  return { any_of: [{ all_of: [{ method: "oauth", provider: "google" }] }] };
}

function defaultNotificationPolicy(): unknown {
  return { mode: "requester_managed", channels: [] };
}

function defaultCompletionDelivery(): unknown {
  return { mode: "async", channels: [{ type: "pull" }] };
}

export interface Jwks {
  keys: Jwk[];
}

export interface Jwk {
  kty: string;
  kid?: string;
  alg?: string;
  use?: string;
  n: string;
  e: string;
}

export interface JwtHeader {
  alg: string;
  typ?: string;
  kid?: string;
}

export interface ConfirmationResponseClaims {
  iss?: string;
  aud: string;
  sub?: string;
  request_id?: string;
  receipt_id: string;
  workflow_template_id: string;
  decision: string;
  confirmed_at?: number;
  iat?: number;
  exp?: number;
  jti?: string;
  artifact_set_hash?: string;
  registered_origin?: string;
}

export interface VerifyConfirmationResponseInput {
  issuer?: string;
  audience?: string;
  workflowTemplateId?: string;
  registeredOrigin?: string;
  now?: number;
  requireConfirmed?: boolean;
}

export interface VerifiedConfirmationResponse {
  header: JwtHeader;
  claims: ConfirmationResponseClaims;
}

export interface ResponseReplayCache {
  checkAndStore(jti: string, receiptId: string): void;
}

export class MemoryResponseReplayCache implements ResponseReplayCache {
  private readonly jtis = new Set<string>();
  private readonly receiptIds = new Set<string>();

  checkAndStore(jti: string, receiptId: string): void {
    if (this.jtis.has(jti) || this.receiptIds.has(receiptId)) {
      throw new ConfirmSdkError("replay_detected", "confirmation response replay detected");
    }
    this.jtis.add(jti);
    this.receiptIds.add(receiptId);
  }
}

export function verifyConfirmationResponseToken(
  token: string,
  jwks: Jwks,
  input: VerifyConfirmationResponseInput = {},
  replayCache?: ResponseReplayCache,
): VerifiedConfirmationResponse {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new ConfirmSdkError("invalid_jwt_shape", "invalid JWT shape");
  }
  const header = decodeBase64UrlJson<JwtHeader>(parts[0]!);
  if (header.typ !== CONFIRM_RESPONSE_TOKEN_TYPE) {
    throw new ConfirmSdkError("unexpected_token_type", `unexpected token type: ${header.typ ?? "missing"}`);
  }
  if (header.alg !== REQUESTER_SIGNATURE_ALGORITHM) {
    throw new ConfirmSdkError("unsupported_token_algorithm", `unsupported token algorithm: ${header.alg}`);
  }
  if (header.kid === undefined) {
    throw new ConfirmSdkError("missing_token_key_id", "missing token key id");
  }
  const jwk = jwks.keys.find((key) => key.kid === header.kid);
  if (jwk === undefined) {
    throw new ConfirmSdkError("missing_jwk", `no JWK found for key ${header.kid}`);
  }
  if (jwk.alg !== undefined && jwk.alg !== header.alg) {
    throw new ConfirmSdkError("jwk_algorithm_mismatch", `JWK algorithm mismatch for key ${header.kid}`);
  }
  const verifier = createVerify("RSA-SHA256");
  verifier.update(`${parts[0]}.${parts[1]}`);
  verifier.end();
  if (!verifier.verify(jwkRsaPublicKey(jwk), Buffer.from(parts[2]!, "base64url"))) {
    throw new ConfirmSdkError("invalid_token_signature", "invalid token signature");
  }
  const claims = decodeBase64UrlJson<ConfirmationResponseClaims>(parts[1]!);
  const now = input.now ?? Math.floor(Date.now() / 1000);
  if (claims.exp !== undefined && claims.exp <= now) {
    throw new ConfirmSdkError("token_expired", "token expired");
  }
  if (input.issuer !== undefined && claims.iss !== input.issuer) {
    throw new ConfirmSdkError("issuer_mismatch", "issuer mismatch");
  }
  if (input.audience !== undefined && claims.aud !== input.audience) {
    throw new ConfirmSdkError("audience_mismatch", "audience mismatch");
  }
  if (input.workflowTemplateId !== undefined && claims.workflow_template_id !== input.workflowTemplateId) {
    throw new ConfirmSdkError("workflow_template_mismatch", "workflow template mismatch");
  }
  if ((input.requireConfirmed ?? false) && claims.decision !== "confirmed") {
    throw new ConfirmSdkError("decision_not_confirmed", "confirmation decision is not confirmed");
  }
  if (claims.receipt_id.trim().length === 0) {
    throw new ConfirmSdkError("missing_receipt_id", "missing receipt id");
  }
  if (input.registeredOrigin !== undefined && claims.registered_origin !== input.registeredOrigin) {
    throw new ConfirmSdkError("registered_origin_mismatch", "registered origin mismatch");
  }
  if (replayCache !== undefined) {
    if (claims.jti === undefined || claims.jti.trim().length === 0) {
      throw new ConfirmSdkError("missing_jti", "missing jti");
    }
    replayCache.checkAndStore(claims.jti, claims.receipt_id);
  }
  return { header, claims };
}

export function verifyConfirmationReceipt(
  receipt: ConfirmationReceipt,
  jwks: Jwks,
  input: VerifyConfirmationResponseInput = {},
  replayCache?: ResponseReplayCache,
): VerifiedConfirmationReceipt {
  const signedPayloadHash = receipt.attestation?.signed_payload_hash;
  if (typeof signedPayloadHash !== "string") {
    throw new ConfirmSdkError("missing_signed_payload_hash", "receipt attestation is missing signed_payload_hash");
  }
  if (!signedPayloadHash.startsWith("sha256:")) {
    throw new ConfirmSdkError("invalid_signed_payload_hash", "receipt attestation signed_payload_hash is not a sha256 hash");
  }
  if (receipt.responseToken === undefined) {
    throw new ConfirmSdkError("missing_response_token", "receipt is missing responseToken");
  }
  const response = verifyConfirmationResponseToken(receipt.responseToken, jwks, input, replayCache);
  if (response.claims.receipt_id !== receipt.receiptId) {
    throw new ConfirmSdkError("receipt_id_mismatch", "receipt id mismatch");
  }
  return { receipt, response };
}

function decodeBase64UrlJson<T>(input: string): T {
  return JSON.parse(Buffer.from(input, "base64url").toString("utf8")) as T;
}

function jwkRsaPublicKey(jwk: Jwk): KeyObject {
  if (jwk.kty !== "RSA") {
    throw new ConfirmSdkError("invalid_public_key", `invalid RSA public key: unsupported kty ${jwk.kty}`);
  }
  return createPublicKey({ key: jwk as JsonWebKey, format: "jwk" });
}
