package confirm

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testPrivateKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func privateKeyPEM(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func strptr(value string) *string {
	return &value
}

func u64ptr(value uint64) *uint64 {
	return &value
}

func testJWK(key *rsa.PublicKey, kid string) JWK {
	alg := RequesterSignatureAlgorithm
	use := "sig"
	return JWK{
		KTY: "RSA", KID: &kid, Alg: &alg, KeyUse: &use,
		N: Base64URL(key.N.Bytes()),
		E: Base64URL(bigIntBytes(key.E)),
	}
}

func bigIntBytes(value int) []byte {
	return new(big.Int).SetInt64(int64(value)).Bytes()
}

func TestStableRequestBodyHashMatchesServiceFixture(t *testing.T) {
	if got := SignedRequestBodySHA256([]byte(`{"ok":true}`)); got != "sha256:QGLtr3UPuAdOfoPgyQKMlOMkaKi28WFHdDKO8EUVD5M" {
		t.Fatalf("hash = %s", got)
	}
}

func TestCanonicalJSONSortsObjectKeysRecursively(t *testing.T) {
	got, err := CanonicalJSON(map[string]any{
		"z":    1,
		"a":    map[string]any{"y": 2, "b": 3},
		"list": []any{map[string]any{"d": 4, "c": 5}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != `{"a":{"b":3,"y":2},"list":[{"c":5,"d":4}],"z":1}` {
		t.Fatalf("canonical JSON = %s", got)
	}
}

func TestSignConfirmationRequestEmitsOriginBoundRS256Headers(t *testing.T) {
	privateKey := testPrivateKey(t)
	signed, err := SignConfirmationRequest(SignConfirmationRequestInput{
		RequesterID: "app_123", KeyID: "kid_123", PrivateKeyPEM: privateKeyPEM(t, privateKey),
		Origin: "https://requester.example.com", CreatedAt: 1_700_000_000, ExpiresAt: 1_700_000_300, Nonce: "nonce_123",
		Body: map[string]any{"requester": map[string]any{"id": "app_123"}, "account_id": "acct_123"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := signed.Headers.Get("x-confirm-requester-id"); got != "app_123" {
		t.Fatalf("requester header = %s", got)
	}
	if got := signed.Headers.Get("x-confirm-origin"); got != "https://requester.example.com" {
		t.Fatalf("origin header = %s", got)
	}
	payload := RequesterSignaturePayload(signed.Envelope)
	if !strings.Contains(payload, "origin:https://requester.example.com") {
		t.Fatalf("payload missing origin: %s", payload)
	}
	signature, err := base64.RawURLEncoding.DecodeString(signed.Envelope.Signature)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(payload))
	if err := rsa.VerifyPKCS1v15(&privateKey.PublicKey, crypto.SHA256, digest[:], signature); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityConfirmationBuildersCreateTightWorkflows(t *testing.T) {
	login := CreateLoginConfirmationRequest(IdentityConfirmationRequestInput{
		AccountID: "acct_123", RequesterID: "app_123", AppName: "Example App",
		Responder: map[string]any{"email": "person@example.com"}, ExpiresAt: "2026-06-25T00:00:00Z",
	})
	if login["workflow_template_id"] != TightConfirmWorkflow {
		t.Fatalf("workflow = %v", login["workflow_template_id"])
	}
	artifacts := login["artifacts"].([]ConfirmationArtifactInput)
	if !strings.Contains(*artifacts[0].Content, "share your identity with Example App") {
		t.Fatalf("login prompt = %s", *artifacts[0].Content)
	}
	refresh := CreateSessionRefreshConfirmationRequest(IdentityConfirmationRequestInput{
		AccountID: "acct_123", RequesterID: "app_123", AppName: "Example App",
		Responder: map[string]any{"email": "person@example.com"}, ExpiresAt: "2026-06-25T00:00:00Z",
		IdentityLabel: strptr("person@example.com"),
	})
	prompt := *(refresh["artifacts"].([]ConfirmationArtifactInput)[0].Content)
	if !strings.Contains(prompt, "still person@example.com") || !strings.Contains(prompt, "resume your session with Example App") {
		t.Fatalf("refresh prompt = %s", prompt)
	}
}

func TestMultiArtifactBuilderSetsArtifactsRenderersAndDelivery(t *testing.T) {
	jsonArtifact, err := InlineJSONArtifact("artifact_json", map[string]any{"z": 1, "a": 2})
	if err != nil {
		t.Fatal(err)
	}
	jsonArtifact = jsonArtifact.WithRenderer(RequiredRenderer("json/v1").WithVersion("v1"))
	pdfArtifact := FetchedURIArtifact("artifact_pdf", "application/pdf", "https://requester.example.com/disclosure.pdf", "sha256:abc123").
		WithRenderer(RequiredRenderer("pdf/v1"))

	body := CreateMultiArtifactConfirmationRequest(ConfirmationRequestInput{
		AccountID: "acct_123", RequesterID: "app_123", RequesterDisplayName: strptr("Example App"),
		Responder:          map[string]any{"email": "person@example.com"},
		Artifacts:          []ConfirmationArtifactInput{InlineMarkdownArtifact("statement", "Please review."), jsonArtifact, pdfArtifact},
		ExpiresAt:          "2026-06-25T00:00:00Z",
		CompletionDelivery: CompletionDeliveryAsync([]DeliveryChannel{PullDeliveryChannel(), WebhookDeliveryChannel("https://requester.example.com/webhooks/confirm")}),
	})
	if body["workflow_template_id"] != MultiArtifactReviewWorkflow {
		t.Fatalf("workflow = %v", body["workflow_template_id"])
	}
	artifacts := body["artifacts"].([]ConfirmationArtifactInput)
	if *artifacts[1].Content != `{"a":2,"z":1}` {
		t.Fatalf("json artifact = %s", *artifacts[1].Content)
	}
	if artifacts[1].Renderer["id"] != "json/v1" || *artifacts[2].URI != "https://requester.example.com/disclosure.pdf" || *artifacts[2].SHA256 != "sha256:abc123" {
		t.Fatalf("artifacts = %#v", artifacts)
	}
}

func TestVerifyConfirmationResponseTokenChecksClaimsOriginAndReplay(t *testing.T) {
	privateKey := testPrivateKey(t)
	kid := "signing_1"
	token := signTestJWT(t, privateKey, kid, map[string]any{
		"iss": "https://confirm.example.com", "aud": "app_123", "sub": "person@example.com",
		"request_id": "cr_123", "receipt_id": "rcpt_123", "workflow_template_id": TightConfirmWorkflow,
		"decision": "confirmed", "iat": 1_700_000_000, "exp": 4_102_444_800, "jti": "jti_123",
		"artifact_set_hash": "sha256:abc", "registered_origin": "https://requester.example.com",
	})
	jwks := JWKS{Keys: []JWK{testJWK(&privateKey.PublicKey, kid)}}
	cache := NewMemoryResponseReplayCache()
	verified, err := VerifyConfirmationResponseToken(token, jwks, VerifyConfirmationResponseInput{
		Issuer: strptr("https://confirm.example.com"), Audience: strptr("app_123"), WorkflowTemplateID: strptr(TightConfirmWorkflow),
		RegisteredOrigin: strptr("https://requester.example.com"), Now: u64ptr(1_700_000_100), RequireConfirmed: true,
	}, cache)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Claims.ReceiptID != "rcpt_123" || verified.Claims.JTI == nil || *verified.Claims.JTI != "jti_123" {
		t.Fatalf("claims = %#v", verified.Claims)
	}
	_, err = VerifyConfirmationResponseToken(token, jwks, VerifyConfirmationResponseInput{Now: u64ptr(1_700_000_100), RequireConfirmed: true}, cache)
	if !errors.Is(err, ErrReplayDetected) {
		t.Fatalf("replay err = %v", err)
	}
	_, err = VerifyConfirmationResponseToken(token, jwks, VerifyConfirmationResponseInput{RegisteredOrigin: strptr("https://evil.example.com"), Now: u64ptr(1_700_000_100), RequireConfirmed: true}, nil)
	if !errors.Is(err, ErrRegisteredOriginMismatch) {
		t.Fatalf("wrong origin err = %v", err)
	}
}

func TestVerifyConfirmationReceiptChecksResponseTokenAndReceiptID(t *testing.T) {
	privateKey := testPrivateKey(t)
	kid := "signing_1"
	token := signTestJWT(t, privateKey, kid, map[string]any{
		"iss": "https://confirm.example.com", "aud": "app_123", "request_id": "cr_123", "receipt_id": "rcpt_123",
		"workflow_template_id": TightConfirmWorkflow, "decision": "confirmed", "exp": 4_102_444_800,
		"jti": "jti_123", "registered_origin": "https://requester.example.com",
	})
	jwks := JWKS{Keys: []JWK{testJWK(&privateKey.PublicKey, kid)}}
	receipt := ConfirmationReceipt{
		ReceiptID: "rcpt_123", RequestID: "cr_123", Status: "confirmed",
		Attestation: map[string]any{"signed_payload_hash": "sha256:abc123"}, ResponseToken: &token,
	}
	verified, err := VerifyConfirmationReceipt(receipt, jwks, VerifyConfirmationResponseInput{
		Issuer: strptr("https://confirm.example.com"), Audience: strptr("app_123"), RegisteredOrigin: strptr("https://requester.example.com"),
		Now: u64ptr(1_700_000_100), RequireConfirmed: true,
	}, NewMemoryResponseReplayCache())
	if err != nil {
		t.Fatal(err)
	}
	if verified.Receipt.ReceiptID != "rcpt_123" || verified.Response.Claims.ReceiptID != "rcpt_123" {
		t.Fatalf("verified = %#v", verified)
	}
	receipt.ReceiptID = "rcpt_other"
	_, err = VerifyConfirmationReceipt(receipt, jwks, VerifyConfirmationResponseInput{Now: u64ptr(1_700_000_100), RequireConfirmed: true}, nil)
	if !errors.Is(err, ErrReceiptIDMismatch) {
		t.Fatalf("mismatch err = %v", err)
	}
}

func TestSubmitConfirmationRequestPostsSignedBodyAndHeaders(t *testing.T) {
	var capturedBody, capturedOrigin, capturedSignature string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		capturedBody = string(body)
		capturedOrigin = r.Header.Get("x-confirm-origin")
		capturedSignature = r.Header.Get("x-confirm-signature")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"request_id":"cr_123","workflow_id":"wf_123","workflow_url":"https://confirm.example.com/request/wf_123","status":"submitted","expires_at":"2026-06-25T00:00:00Z"}`))
	}))
	defer server.Close()

	signed := SignedConfirmationRequest{
		Body:     "{}",
		Envelope: SignedRequestEnvelope{Signature: "signature"},
		Headers:  http.Header{"x-confirm-origin": []string{"https://requester.example.com"}, "x-confirm-signature": []string{"signature"}},
	}
	client, err := NewHTTPClient(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.SubmitConfirmationRequest(context.Background(), signed)
	if err != nil {
		t.Fatal(err)
	}
	if response.RequestID != "cr_123" || capturedBody != "{}" || capturedOrigin != "https://requester.example.com" || capturedSignature != "signature" {
		t.Fatalf("response=%#v body=%q origin=%q signature=%q", response, capturedBody, capturedOrigin, capturedSignature)
	}
}

func signTestJWT(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": RequesterSignatureAlgorithm, "typ": ConfirmResponseTokenType, "kid": kid}
	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)
	signingInput := Base64URL(headerJSON) + "." + Base64URL(claimsJSON)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + Base64URL(signature)
}
