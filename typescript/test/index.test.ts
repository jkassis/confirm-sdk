import assert from "node:assert/strict";
import { generateKeyPairSync, createSign, createVerify } from "node:crypto";
import test from "node:test";
import {
  base64Url,
  canonicalJson,
  ConfirmHttpClient,
  ConfirmSdkError,
  createLoginConfirmationRequest,
  createMultiArtifactConfirmationRequest,
  createSessionRefreshConfirmationRequest,
  fetchedUriArtifact,
  inlineJsonArtifact,
  inlineMarkdownArtifact,
  MemoryResponseReplayCache,
  MULTI_ARTIFACT_REVIEW_WORKFLOW,
  pullDeliveryChannel,
  requesterSignaturePayload,
  requiredRenderer,
  signedRequestBodySha256,
  signConfirmationRequest,
  TIGHT_CONFIRM_WORKFLOW,
  verifyConfirmationReceipt,
  verifyConfirmationResponseToken,
  webhookDeliveryChannel,
  withRenderer,
  type Jwk,
} from "../src/index.js";

function testKeyPair(): { privateKeyPem: string; publicJwk: Jwk } {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const privateKeyPem = privateKey.export({ format: "pem", type: "pkcs8" }).toString();
  const jwk = publicKey.export({ format: "jwk" });
  return {
    privateKeyPem,
    publicJwk: {
      kty: "RSA",
      kid: "signing_1",
      alg: "RS256",
      use: "sig",
      n: jwk.n!,
      e: jwk.e!,
    },
  };
}

test("stable request body hash matches service fixture", () => {
  assert.equal(signedRequestBodySha256(Buffer.from(`{"ok":true}`)), "sha256:QGLtr3UPuAdOfoPgyQKMlOMkaKi28WFHdDKO8EUVD5M");
});

test("canonical JSON sorts object keys recursively", () => {
  assert.equal(canonicalJson({ z: 1, a: { y: 2, b: 3 }, list: [{ d: 4, c: 5 }] }), `{"a":{"b":3,"y":2},"list":[{"c":5,"d":4}],"z":1}`);
});

test("sign confirmation request emits origin-bound RS256 headers", () => {
  const { privateKeyPem } = testKeyPair();
  const signed = signConfirmationRequest({
    requesterId: "app_123",
    keyId: "kid_123",
    privateKeyPem,
    origin: "https://requester.example.com",
    createdAt: 1_700_000_000,
    expiresAt: 1_700_000_300,
    nonce: "nonce_123",
    body: { requester: { id: "app_123" }, account_id: "acct_123" },
  });
  assert.equal(signed.headers["x-confirm-requester-id"], "app_123");
  assert.equal(signed.headers["x-confirm-origin"], "https://requester.example.com");
  assert.match(requesterSignaturePayload(signed.envelope), /origin:https:\/\/requester\.example\.com/);

  const verifier = createVerify("RSA-SHA256");
  verifier.update(requesterSignaturePayload(signed.envelope));
  verifier.end();
  assert.equal(verifier.verify(privateKeyPem, Buffer.from(signed.envelope.signature, "base64url")), true);
});

test("identity confirmation builders create tight workflows", () => {
  const login = createLoginConfirmationRequest({
    accountId: "acct_123",
    requesterId: "app_123",
    appName: "Example App",
    responder: { email: "person@example.com" },
    expiresAt: "2026-06-25T00:00:00Z",
  });
  assert.equal(login.workflow_template_id, TIGHT_CONFIRM_WORKFLOW);
  assert.match((login.artifacts as Array<{ content: string }>)[0]!.content, /share your identity with Example App/);

  const refresh = createSessionRefreshConfirmationRequest({
    accountId: "acct_123",
    requesterId: "app_123",
    appName: "Example App",
    responder: { email: "person@example.com" },
    expiresAt: "2026-06-25T00:00:00Z",
    identityLabel: "person@example.com",
  });
  const prompt = (refresh.artifacts as Array<{ content: string }>)[0]!.content;
  assert.match(prompt, /still person@example.com/);
  assert.match(prompt, /resume your session with Example App/);
});

test("multi-artifact builder sets artifacts renderers and delivery", () => {
  const jsonArtifact = withRenderer(inlineJsonArtifact("artifact_json", { z: 1, a: 2 }), { ...requiredRenderer("json/v1"), version: "v1" });
  const pdfArtifact = withRenderer(
    fetchedUriArtifact("artifact_pdf", "application/pdf", "https://requester.example.com/disclosure.pdf", "sha256:abc123"),
    requiredRenderer("pdf/v1"),
  );
  const body = createMultiArtifactConfirmationRequest({
    accountId: "acct_123",
    requesterId: "app_123",
    requesterDisplayName: "Example App",
    responder: { email: "person@example.com" },
    artifacts: [inlineMarkdownArtifact("statement", "Please review."), jsonArtifact, pdfArtifact],
    expiresAt: "2026-06-25T00:00:00Z",
    completionDelivery: { mode: "async", channels: [pullDeliveryChannel(), webhookDeliveryChannel("https://requester.example.com/webhooks/confirm")] },
  });
  const artifacts = body.artifacts as Array<{ content?: string; uri?: string; sha256?: string; renderer?: Record<string, unknown> }>;
  assert.equal(body.workflow_template_id, MULTI_ARTIFACT_REVIEW_WORKFLOW);
  assert.equal(artifacts[1]!.content, `{"a":2,"z":1}`);
  assert.equal(artifacts[1]!.renderer?.id, "json/v1");
  assert.equal(artifacts[2]!.uri, "https://requester.example.com/disclosure.pdf");
  assert.equal(artifacts[2]!.sha256, "sha256:abc123");
});

test("verify confirmation response token checks claims origin and replay", () => {
  const { privateKeyPem, publicJwk } = testKeyPair();
  const token = signTestJwt(privateKeyPem, "signing_1", {
    iss: "https://confirm.example.com",
    aud: "app_123",
    sub: "person@example.com",
    request_id: "cr_123",
    receipt_id: "rcpt_123",
    workflow_template_id: TIGHT_CONFIRM_WORKFLOW,
    decision: "confirmed",
    iat: 1_700_000_000,
    exp: 4_102_444_800,
    jti: "jti_123",
    artifact_set_hash: "sha256:abc",
    registered_origin: "https://requester.example.com",
  });
  const cache = new MemoryResponseReplayCache();
  const verified = verifyConfirmationResponseToken(token, { keys: [publicJwk] }, {
    issuer: "https://confirm.example.com",
    audience: "app_123",
    workflowTemplateId: TIGHT_CONFIRM_WORKFLOW,
    registeredOrigin: "https://requester.example.com",
    now: 1_700_000_100,
    requireConfirmed: true,
  }, cache);
  assert.equal(verified.claims.receipt_id, "rcpt_123");
  assert.equal(verified.claims.jti, "jti_123");

  assert.throws(
    () => verifyConfirmationResponseToken(token, { keys: [publicJwk] }, { now: 1_700_000_100, requireConfirmed: true }, cache),
    (error) => error instanceof ConfirmSdkError && error.code === "replay_detected",
  );
  assert.throws(
    () => verifyConfirmationResponseToken(token, { keys: [publicJwk] }, { registeredOrigin: "https://evil.example.com", now: 1_700_000_100, requireConfirmed: true }),
    (error) => error instanceof ConfirmSdkError && error.code === "registered_origin_mismatch",
  );
});

test("verify confirmation receipt checks response token and receipt id", () => {
  const { privateKeyPem, publicJwk } = testKeyPair();
  const token = signTestJwt(privateKeyPem, "signing_1", {
    iss: "https://confirm.example.com",
    aud: "app_123",
    request_id: "cr_123",
    receipt_id: "rcpt_123",
    workflow_template_id: TIGHT_CONFIRM_WORKFLOW,
    decision: "confirmed",
    exp: 4_102_444_800,
    jti: "jti_123",
    registered_origin: "https://requester.example.com",
  });
  const receipt = {
    receiptId: "rcpt_123",
    requestId: "cr_123",
    status: "confirmed",
    attestation: { signed_payload_hash: "sha256:abc123" },
    responseToken: token,
  };
  const verified = verifyConfirmationReceipt(receipt, { keys: [publicJwk] }, {
    issuer: "https://confirm.example.com",
    audience: "app_123",
    registeredOrigin: "https://requester.example.com",
    now: 1_700_000_100,
    requireConfirmed: true,
  }, new MemoryResponseReplayCache());
  assert.equal(verified.receipt.receiptId, "rcpt_123");
  assert.equal(verified.response.claims.receipt_id, "rcpt_123");

  assert.throws(
    () => verifyConfirmationReceipt({ ...receipt, receiptId: "rcpt_other" }, { keys: [publicJwk] }, { now: 1_700_000_100, requireConfirmed: true }),
    (error) => error instanceof ConfirmSdkError && error.code === "receipt_id_mismatch",
  );
});

test("submit confirmation request posts signed body and headers", async () => {
  const requests: Array<{ url: string; init: RequestInit | undefined }> = [];
  const fetchImpl = async (url: string | URL | Request, init?: RequestInit): Promise<Response> => {
    requests.push({ url: String(url), init });
    return new Response(JSON.stringify({
      request_id: "cr_123",
      workflow_id: "wf_123",
      workflow_url: "https://confirm.example.com/request/wf_123",
      status: "submitted",
      expires_at: "2026-06-25T00:00:00Z",
    }), { status: 200 });
  };
  const client = new ConfirmHttpClient("https://confirm.example.com/", fetchImpl as typeof fetch);
  const response = await client.submitConfirmationRequest({
    body: "{}",
    envelope: {
      requesterId: "app_123",
      keyId: "kid_123",
      algorithm: "RS256",
      createdAt: 1,
      expiresAt: 2,
      nonce: "nonce",
      origin: "https://requester.example.com",
      bodySha256: "sha256:abc",
      signature: "signature",
    },
    headers: { "x-confirm-origin": "https://requester.example.com", "x-confirm-signature": "signature" },
  });
  assert.equal(response.request_id, "cr_123");
  assert.equal(requests[0]!.url, "https://confirm.example.com/v1/confirmation-requests");
  assert.equal(requests[0]!.init?.body, "{}");
  assert.deepEqual(requests[0]!.init?.headers, { "x-confirm-origin": "https://requester.example.com", "x-confirm-signature": "signature" });
});

function signTestJwt(privateKeyPem: string, kid: string, claims: Record<string, unknown>): string {
  const header = { alg: "RS256", typ: "confirm-response+jwt", kid };
  const signingInput = `${base64Url(JSON.stringify(header))}.${base64Url(JSON.stringify(claims))}`;
  const signer = createSign("RSA-SHA256");
  signer.update(signingInput);
  signer.end();
  return `${signingInput}.${base64Url(signer.sign(privateKeyPem))}`;
}
