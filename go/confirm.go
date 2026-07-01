package confirm

import (
	"bytes"
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
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	RequesterSignatureAlgorithm = "RS256"
	ConfirmResponseTokenType    = "confirm-response+jwt"
	TightConfirmWorkflow        = "single_responder.tight_confirm.v1"
	MultiArtifactReviewWorkflow = "single_responder.multi_artifact_review.v1"
)

var (
	ErrInvalidJWTShape          = errors.New("invalid JWT shape")
	ErrInvalidTokenSignature    = errors.New("invalid token signature")
	ErrTokenExpired             = errors.New("token expired")
	ErrIssuerMismatch           = errors.New("issuer mismatch")
	ErrAudienceMismatch         = errors.New("audience mismatch")
	ErrWorkflowTemplateMismatch = errors.New("workflow template mismatch")
	ErrDecisionNotConfirmed     = errors.New("confirmation decision is not confirmed")
	ErrMissingReceiptID         = errors.New("missing receipt id")
	ErrMissingJTI               = errors.New("missing jti")
	ErrRegisteredOriginMismatch = errors.New("registered origin mismatch")
	ErrReplayDetected           = errors.New("confirmation response replay detected")
	ErrMissingResponseToken     = errors.New("receipt is missing responseToken")
	ErrReceiptIDMismatch        = errors.New("receipt id mismatch")
	ErrMissingSignedPayloadHash = errors.New("receipt attestation is missing signed_payload_hash")
	ErrInvalidSignedPayloadHash = errors.New("receipt attestation signed_payload_hash is not a sha256 hash")
)

type SignedRequestEnvelope struct {
	RequesterID string `json:"requesterId"`
	KeyID       string `json:"keyId"`
	Algorithm   string `json:"algorithm"`
	CreatedAt   uint64 `json:"createdAt"`
	ExpiresAt   uint64 `json:"expiresAt"`
	Nonce       string `json:"nonce"`
	Origin      string `json:"origin"`
	BodySHA256  string `json:"bodySha256"`
	Signature   string `json:"signature"`
}

type SignedConfirmationRequest struct {
	Body     string
	Envelope SignedRequestEnvelope
	Headers  http.Header
}

type ConfirmationRequestCreateResponse struct {
	RequestID   string `json:"request_id"`
	WorkflowID  string `json:"workflow_id"`
	WorkflowURL string `json:"workflow_url"`
	Status      string `json:"status"`
	ExpiresAt   string `json:"expires_at"`
}

type ConfirmationReceiptResponse struct {
	Receipt ConfirmationReceipt `json:"receipt"`
}

type ConfirmationReceiptDisclosureResponse struct {
	Receipt          any `json:"receipt"`
	DisclosureRecord any `json:"disclosureRecord"`
}

type ConfirmationReceipt struct {
	ReceiptID               string         `json:"receiptId"`
	RequestID               string         `json:"requestId"`
	Status                  string         `json:"status"`
	Artifacts               []any          `json:"artifacts,omitempty"`
	Decision                any            `json:"decision,omitempty"`
	EvidenceRecords         []any          `json:"evidenceRecords,omitempty"`
	SatisfiedEvidenceBranch any            `json:"satisfiedEvidenceBranch,omitempty"`
	CreatedAt               *uint64        `json:"createdAt,omitempty"`
	Attestation             map[string]any `json:"attestation,omitempty"`
	ResponseToken           *string        `json:"responseToken,omitempty"`
}

type VerifiedConfirmationReceipt struct {
	Receipt  ConfirmationReceipt
	Response VerifiedConfirmationResponse
}

type HTTPClient struct {
	baseURL string
	client  *http.Client
}

func NewHTTPClient(baseURL string, client *http.Client) (*HTTPClient, error) {
	baseURL = strings.TrimRight(baseURL, "/")
	if baseURL == "" {
		return nil, errors.New("invalid URL: empty base URL")
	}
	if client == nil {
		client = http.DefaultClient
	}
	return &HTTPClient{baseURL: baseURL, client: client}, nil
}

func (c *HTTPClient) SubmitConfirmationRequest(ctx context.Context, signed SignedConfirmationRequest) (ConfirmationRequestCreateResponse, error) {
	return SubmitConfirmationRequest(ctx, c.client, c.baseURL, signed)
}

func (c *HTTPClient) GetConfirmationReceipt(ctx context.Context, receiptID string) (ConfirmationReceiptResponse, error) {
	var out ConfirmationReceiptResponse
	err := getJSON(ctx, c.client, c.baseURL+"/v1/confirmation-receipts/"+receiptID, nil, &out)
	return out, err
}

type DisclosureAudience string

const (
	DisclosureAudienceRequester DisclosureAudience = "requester"
	DisclosureAudienceResponder DisclosureAudience = "responder"
	DisclosureAudienceOperator  DisclosureAudience = "operator"
)

func (c *HTTPClient) GetReceiptDisclosure(ctx context.Context, receiptID string, audience DisclosureAudience) (ConfirmationReceiptDisclosureResponse, error) {
	var out ConfirmationReceiptDisclosureResponse
	headers := http.Header{"x-confirm-audience": []string{string(audience)}}
	err := getJSON(ctx, c.client, c.baseURL+"/v1/confirmation-receipts/"+receiptID+"/disclosure", headers, &out)
	return out, err
}

func SubmitConfirmationRequest(ctx context.Context, client *http.Client, baseURL string, signed SignedConfirmationRequest) (ConfirmationRequestCreateResponse, error) {
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(baseURL, "/")+"/v1/confirmation-requests", strings.NewReader(signed.Body))
	if err != nil {
		return ConfirmationRequestCreateResponse{}, err
	}
	for name, values := range signed.Headers {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return ConfirmationRequestCreateResponse{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ConfirmationRequestCreateResponse{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ConfirmationRequestCreateResponse{}, fmt.Errorf("Confirm API returned %d: %s", resp.StatusCode, string(body))
	}
	var out ConfirmationRequestCreateResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return ConfirmationRequestCreateResponse{}, err
	}
	return out, nil
}

func getJSON(ctx context.Context, client *http.Client, url string, headers http.Header, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	for name, values := range headers {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("Confirm API returned %d: %s", resp.StatusCode, string(body))
	}
	return json.Unmarshal(body, out)
}

type SignConfirmationRequestInput struct {
	RequesterID   string
	KeyID         string
	PrivateKeyPEM string
	Origin        string
	CreatedAt     uint64
	ExpiresAt     uint64
	Nonce         string
	Body          any
}

type SignConfirmationRequestBodyInput struct {
	Body          string
	RequesterID   string
	KeyID         string
	PrivateKeyPEM string
	Origin        string
	CreatedAt     uint64
	ExpiresAt     uint64
	Nonce         string
}

func SignConfirmationRequest(input SignConfirmationRequestInput) (SignedConfirmationRequest, error) {
	body, err := CanonicalJSON(input.Body)
	if err != nil {
		return SignedConfirmationRequest{}, err
	}
	return SignConfirmationRequestBody(SignConfirmationRequestBodyInput{
		Body: body, RequesterID: input.RequesterID, KeyID: input.KeyID, PrivateKeyPEM: input.PrivateKeyPEM,
		Origin: input.Origin, CreatedAt: input.CreatedAt, ExpiresAt: input.ExpiresAt, Nonce: input.Nonce,
	})
}

func SignConfirmationRequestBody(input SignConfirmationRequestBodyInput) (SignedConfirmationRequest, error) {
	privateKey, err := parseRSAPrivateKey(input.PrivateKeyPEM)
	if err != nil {
		return SignedConfirmationRequest{}, err
	}
	envelope := SignedRequestEnvelope{
		RequesterID: input.RequesterID,
		KeyID:       input.KeyID,
		Algorithm:   RequesterSignatureAlgorithm,
		CreatedAt:   input.CreatedAt,
		ExpiresAt:   input.ExpiresAt,
		Nonce:       input.Nonce,
		Origin:      input.Origin,
		BodySHA256:  SignedRequestBodySHA256([]byte(input.Body)),
	}
	digest := sha256.Sum256([]byte(RequesterSignaturePayload(envelope)))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return SignedConfirmationRequest{}, err
	}
	envelope.Signature = Base64URL(signature)
	headers := http.Header{}
	headers.Set("content-type", "application/json")
	headers.Set("x-confirm-requester-id", envelope.RequesterID)
	headers.Set("x-confirm-key-id", envelope.KeyID)
	headers.Set("x-confirm-algorithm", envelope.Algorithm)
	headers.Set("x-confirm-created-at", strconv.FormatUint(envelope.CreatedAt, 10))
	headers.Set("x-confirm-expires-at", strconv.FormatUint(envelope.ExpiresAt, 10))
	headers.Set("x-confirm-nonce", envelope.Nonce)
	headers.Set("x-confirm-origin", envelope.Origin)
	headers.Set("x-confirm-body-sha256", envelope.BodySHA256)
	headers.Set("x-confirm-signature", envelope.Signature)
	return SignedConfirmationRequest{Body: input.Body, Envelope: envelope, Headers: headers}, nil
}

func RequesterSignaturePayload(envelope SignedRequestEnvelope) string {
	return fmt.Sprintf("confirm-request-v1\nrequester_id:%s\nkey_id:%s\nalgorithm:%s\ncreated_at:%d\nexpires_at:%d\nnonce:%s\norigin:%s\nbody_sha256:%s",
		envelope.RequesterID, envelope.KeyID, envelope.Algorithm, envelope.CreatedAt, envelope.ExpiresAt, envelope.Nonce, envelope.Origin, envelope.BodySHA256)
}

func SignedRequestBodySHA256(input []byte) string {
	return "sha256:" + SHA256Base64URL(input)
}

func SHA256Base64URL(input []byte) string {
	sum := sha256.Sum256(input)
	return Base64URL(sum[:])
}

func Base64URL(input []byte) string {
	return base64.RawURLEncoding.EncodeToString(input)
}

func CanonicalJSON(value any) (string, error) {
	var normalized any
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	if err := json.Unmarshal(raw, &normalized); err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := writeCanonicalJSON(&buf, normalized); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func writeCanonicalJSON(buf *bytes.Buffer, value any) error {
	switch v := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			keyJSON, _ := json.Marshal(key)
			buf.Write(keyJSON)
			buf.WriteByte(':')
			if err := writeCanonicalJSON(buf, v[key]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
		return nil
	case []any:
		buf.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonicalJSON(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
		return nil
	default:
		raw, err := json.Marshal(v)
		if err != nil {
			return err
		}
		buf.Write(raw)
		return nil
	}
}

type ConfirmationArtifactInput struct {
	ID        string         `json:"id"`
	MediaType string         `json:"media_type"`
	Content   *string        `json:"content,omitempty"`
	URI       *string        `json:"uri,omitempty"`
	SHA256    *string        `json:"sha256,omitempty"`
	Renderer  map[string]any `json:"renderer,omitempty"`
}

func InlineTextArtifact(id, content string) ConfirmationArtifactInput {
	return inlineArtifact(id, "text/plain", content)
}

func InlineMarkdownArtifact(id, content string) ConfirmationArtifactInput {
	return inlineArtifact(id, "text/markdown", content)
}

func InlineJSONArtifact(id string, value any) (ConfirmationArtifactInput, error) {
	content, err := CanonicalJSON(value)
	if err != nil {
		return ConfirmationArtifactInput{}, err
	}
	return inlineArtifact(id, "application/json", content), nil
}

func FetchedURIArtifact(id, mediaType, uri, sha256 string) ConfirmationArtifactInput {
	return ConfirmationArtifactInput{ID: id, MediaType: mediaType, URI: &uri, SHA256: &sha256}
}

func (a ConfirmationArtifactInput) WithRenderer(renderer RendererRequirement) ConfirmationArtifactInput {
	a.Renderer = renderer.Value()
	return a
}

func inlineArtifact(id, mediaType, content string) ConfirmationArtifactInput {
	return ConfirmationArtifactInput{ID: id, MediaType: mediaType, Content: &content}
}

type RendererRequirement struct {
	ID       string
	Required bool
	Version  *string
}

func RequiredRenderer(id string) RendererRequirement {
	return RendererRequirement{ID: id, Required: true}
}

func OptionalRenderer(id string) RendererRequirement {
	return RendererRequirement{ID: id, Required: false}
}

func (r RendererRequirement) WithVersion(version string) RendererRequirement {
	r.Version = &version
	return r
}

func (r RendererRequirement) Value() map[string]any {
	out := map[string]any{"id": r.ID, "required": r.Required}
	if r.Version != nil {
		out["version"] = *r.Version
	}
	return out
}

type DeliveryChannel struct {
	Type string
	URL  *string
}

func PullDeliveryChannel() DeliveryChannel {
	return DeliveryChannel{Type: "pull"}
}

func WebhookDeliveryChannel(url string) DeliveryChannel {
	return DeliveryChannel{Type: "webhook", URL: &url}
}

func RedirectDeliveryChannel(url string) DeliveryChannel {
	return DeliveryChannel{Type: "redirect", URL: &url}
}

func CompletionDeliveryAsync(channels []DeliveryChannel) map[string]any {
	return completionDelivery("async", channels)
}

func CompletionDeliverySync(channels []DeliveryChannel) map[string]any {
	return completionDelivery("sync", channels)
}

func completionDelivery(mode string, channels []DeliveryChannel) map[string]any {
	items := make([]map[string]any, 0, len(channels))
	for _, channel := range channels {
		item := map[string]any{"type": channel.Type}
		if channel.URL != nil {
			item["url"] = *channel.URL
		}
		items = append(items, item)
	}
	return map[string]any{"mode": mode, "channels": items}
}

type ConfirmationRequestInput struct {
	AccountID            string
	RequesterID          string
	RequesterDisplayName *string
	Responder            any
	Artifacts            []ConfirmationArtifactInput
	ExpiresAt            string
	WorkflowTemplateID   string
	Audiences            any
	DisclosurePolicy     any
	EvidencePolicy       any
	NotificationPolicy   any
	CompletionDelivery   any
	Metadata             any
}

func ConfirmationRequestBody(input ConfirmationRequestInput) map[string]any {
	return map[string]any{
		"account_id":           input.AccountID,
		"requester":            map[string]any{"id": input.RequesterID, "display_name": input.RequesterDisplayName},
		"responder":            input.Responder,
		"artifacts":            input.Artifacts,
		"audiences":            defaultValue(input.Audiences, defaultAudiences()),
		"disclosure_policy":    defaultValue(input.DisclosurePolicy, defaultDisclosurePolicy()),
		"evidence_policy":      defaultValue(input.EvidencePolicy, defaultEvidencePolicy()),
		"notification_policy":  defaultValue(input.NotificationPolicy, defaultNotificationPolicy()),
		"completion_delivery":  defaultValue(input.CompletionDelivery, defaultCompletionDelivery()),
		"workflow_template_id": input.WorkflowTemplateID,
		"expires_at":           input.ExpiresAt,
		"metadata":             defaultValue(input.Metadata, map[string]any{}),
	}
}

func CreateMultiArtifactConfirmationRequest(input ConfirmationRequestInput) map[string]any {
	input.WorkflowTemplateID = MultiArtifactReviewWorkflow
	return ConfirmationRequestBody(input)
}

type IdentityConfirmationRequestInput struct {
	AccountID     string
	RequesterID   string
	AppName       string
	Responder     any
	ExpiresAt     string
	Prompt        *string
	IdentityLabel *string
	Metadata      any
}

func CreateLoginConfirmationRequest(input IdentityConfirmationRequestInput) map[string]any {
	prompt := fmt.Sprintf("You would like to share your identity with %s.", input.AppName)
	if input.Prompt != nil {
		prompt = *input.Prompt
	}
	return identityConfirmationRequest(input, "login_prompt", prompt)
}

func CreateSessionRefreshConfirmationRequest(input IdentityConfirmationRequestInput) map[string]any {
	prompt := fmt.Sprintf("You wish to resume your session with %s.", input.AppName)
	if input.IdentityLabel != nil {
		prompt = fmt.Sprintf("You are still %s and wish to resume your session with %s.", *input.IdentityLabel, input.AppName)
	}
	if input.Prompt != nil {
		prompt = *input.Prompt
	}
	return identityConfirmationRequest(input, "session_refresh_prompt", prompt)
}

func identityConfirmationRequest(input IdentityConfirmationRequestInput, artifactID, prompt string) map[string]any {
	return ConfirmationRequestBody(ConfirmationRequestInput{
		AccountID:            input.AccountID,
		RequesterID:          input.RequesterID,
		RequesterDisplayName: &input.AppName,
		Responder:            input.Responder,
		Artifacts:            []ConfirmationArtifactInput{InlineMarkdownArtifact(artifactID, prompt)},
		ExpiresAt:            input.ExpiresAt,
		WorkflowTemplateID:   TightConfirmWorkflow,
		Metadata:             input.Metadata,
	})
}

func defaultValue(value, fallback any) any {
	if value == nil {
		return fallback
	}
	return value
}

func defaultAudiences() []map[string]any {
	return []map[string]any{{"id": "primary_audience", "mode": "restricted", "members": []map[string]any{{"type": "requester"}, {"type": "responder"}}}}
}

func defaultDisclosurePolicy() map[string]any {
	return map[string]any{"rules": []map[string]any{{"audience": "primary_audience", "target": "artifacts", "access": "full"}}}
}

func defaultEvidencePolicy() map[string]any {
	return map[string]any{"any_of": []map[string]any{{"all_of": []map[string]any{{"method": "oauth", "provider": "google"}}}}}
}

func defaultNotificationPolicy() map[string]any {
	return map[string]any{"mode": "requester_managed", "channels": []any{}}
}

func defaultCompletionDelivery() map[string]any {
	return map[string]any{"mode": "async", "channels": []map[string]any{{"type": "pull"}}}
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	KTY    string  `json:"kty"`
	KID    *string `json:"kid,omitempty"`
	Alg    *string `json:"alg,omitempty"`
	KeyUse *string `json:"use,omitempty"`
	N      string  `json:"n"`
	E      string  `json:"e"`
}

type JWTHeader struct {
	Alg string  `json:"alg"`
	Typ *string `json:"typ,omitempty"`
	KID *string `json:"kid,omitempty"`
}

type ConfirmationResponseClaims struct {
	Iss                *string `json:"iss,omitempty"`
	Aud                string  `json:"aud"`
	Sub                *string `json:"sub,omitempty"`
	RequestID          *string `json:"request_id,omitempty"`
	ReceiptID          string  `json:"receipt_id"`
	WorkflowTemplateID string  `json:"workflow_template_id"`
	Decision           string  `json:"decision"`
	ConfirmedAt        *uint64 `json:"confirmed_at,omitempty"`
	Iat                *uint64 `json:"iat,omitempty"`
	Exp                *uint64 `json:"exp,omitempty"`
	JTI                *string `json:"jti,omitempty"`
	ArtifactSetHash    *string `json:"artifact_set_hash,omitempty"`
	RegisteredOrigin   *string `json:"registered_origin,omitempty"`
}

type VerifyConfirmationResponseInput struct {
	Issuer             *string
	Audience           *string
	WorkflowTemplateID *string
	RegisteredOrigin   *string
	Now                *uint64
	RequireConfirmed   bool
}

type VerifiedConfirmationResponse struct {
	Header JWTHeader
	Claims ConfirmationResponseClaims
}

type ResponseReplayCache interface {
	CheckAndStore(jti, receiptID string) error
}

type MemoryResponseReplayCache struct {
	mu         sync.Mutex
	jtis       map[string]struct{}
	receiptIDs map[string]struct{}
}

func NewMemoryResponseReplayCache() *MemoryResponseReplayCache {
	return &MemoryResponseReplayCache{jtis: map[string]struct{}{}, receiptIDs: map[string]struct{}{}}
}

func (c *MemoryResponseReplayCache) CheckAndStore(jti, receiptID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.jtis == nil {
		c.jtis = map[string]struct{}{}
	}
	if c.receiptIDs == nil {
		c.receiptIDs = map[string]struct{}{}
	}
	if _, ok := c.jtis[jti]; ok {
		return ErrReplayDetected
	}
	if _, ok := c.receiptIDs[receiptID]; ok {
		return ErrReplayDetected
	}
	c.jtis[jti] = struct{}{}
	c.receiptIDs[receiptID] = struct{}{}
	return nil
}

func VerifyConfirmationResponseToken(token string, jwks JWKS, input VerifyConfirmationResponseInput, replayCache ResponseReplayCache) (VerifiedConfirmationResponse, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return VerifiedConfirmationResponse{}, ErrInvalidJWTShape
	}
	var header JWTHeader
	if err := decodeBase64URLJSON(parts[0], &header); err != nil {
		return VerifiedConfirmationResponse{}, err
	}
	if header.Typ == nil || *header.Typ != ConfirmResponseTokenType {
		got := "missing"
		if header.Typ != nil {
			got = *header.Typ
		}
		return VerifiedConfirmationResponse{}, fmt.Errorf("unexpected token type: %s", got)
	}
	if header.Alg != RequesterSignatureAlgorithm {
		return VerifiedConfirmationResponse{}, fmt.Errorf("unsupported token algorithm: %s", header.Alg)
	}
	if header.KID == nil {
		return VerifiedConfirmationResponse{}, errors.New("missing token key id")
	}
	jwk, ok := findJWK(jwks, *header.KID)
	if !ok {
		return VerifiedConfirmationResponse{}, fmt.Errorf("no JWK found for key %s", *header.KID)
	}
	if jwk.Alg != nil && *jwk.Alg != header.Alg {
		return VerifiedConfirmationResponse{}, fmt.Errorf("JWK algorithm mismatch for key %s", *header.KID)
	}
	publicKey, err := jwkRSAPublicKey(jwk)
	if err != nil {
		return VerifiedConfirmationResponse{}, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return VerifiedConfirmationResponse{}, err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest[:], signature); err != nil {
		return VerifiedConfirmationResponse{}, ErrInvalidTokenSignature
	}
	var claims ConfirmationResponseClaims
	if err := decodeBase64URLJSON(parts[1], &claims); err != nil {
		return VerifiedConfirmationResponse{}, err
	}
	now := uint64(time.Now().Unix())
	if input.Now != nil {
		now = *input.Now
	}
	if claims.Exp != nil && *claims.Exp <= now {
		return VerifiedConfirmationResponse{}, ErrTokenExpired
	}
	if input.Issuer != nil && (claims.Iss == nil || *claims.Iss != *input.Issuer) {
		return VerifiedConfirmationResponse{}, ErrIssuerMismatch
	}
	if input.Audience != nil && claims.Aud != *input.Audience {
		return VerifiedConfirmationResponse{}, ErrAudienceMismatch
	}
	if input.WorkflowTemplateID != nil && claims.WorkflowTemplateID != *input.WorkflowTemplateID {
		return VerifiedConfirmationResponse{}, ErrWorkflowTemplateMismatch
	}
	if input.RequireConfirmed && claims.Decision != "confirmed" {
		return VerifiedConfirmationResponse{}, ErrDecisionNotConfirmed
	}
	if strings.TrimSpace(claims.ReceiptID) == "" {
		return VerifiedConfirmationResponse{}, ErrMissingReceiptID
	}
	if input.RegisteredOrigin != nil && (claims.RegisteredOrigin == nil || *claims.RegisteredOrigin != *input.RegisteredOrigin) {
		return VerifiedConfirmationResponse{}, ErrRegisteredOriginMismatch
	}
	if replayCache != nil {
		if claims.JTI == nil || strings.TrimSpace(*claims.JTI) == "" {
			return VerifiedConfirmationResponse{}, ErrMissingJTI
		}
		if err := replayCache.CheckAndStore(*claims.JTI, claims.ReceiptID); err != nil {
			return VerifiedConfirmationResponse{}, err
		}
	}
	return VerifiedConfirmationResponse{Header: header, Claims: claims}, nil
}

func VerifyConfirmationReceipt(receipt ConfirmationReceipt, jwks JWKS, input VerifyConfirmationResponseInput, replayCache ResponseReplayCache) (VerifiedConfirmationReceipt, error) {
	hash, _ := receipt.Attestation["signed_payload_hash"].(string)
	if hash == "" {
		return VerifiedConfirmationReceipt{}, ErrMissingSignedPayloadHash
	}
	if !strings.HasPrefix(hash, "sha256:") {
		return VerifiedConfirmationReceipt{}, ErrInvalidSignedPayloadHash
	}
	if receipt.ResponseToken == nil {
		return VerifiedConfirmationReceipt{}, ErrMissingResponseToken
	}
	response, err := VerifyConfirmationResponseToken(*receipt.ResponseToken, jwks, input, replayCache)
	if err != nil {
		return VerifiedConfirmationReceipt{}, err
	}
	if response.Claims.ReceiptID != receipt.ReceiptID {
		return VerifiedConfirmationReceipt{}, ErrReceiptIDMismatch
	}
	return VerifiedConfirmationReceipt{Receipt: receipt, Response: response}, nil
}

func parseRSAPrivateKey(privateKeyPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, errors.New("invalid RSA private key: missing PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("invalid RSA private key: not RSA")
		}
		return rsaKey, nil
	}
	if rsaKey, pkcs1Err := x509.ParsePKCS1PrivateKey(block.Bytes); pkcs1Err == nil {
		return rsaKey, nil
	}
	return nil, fmt.Errorf("invalid RSA private key: %w", err)
}

func findJWK(jwks JWKS, kid string) (JWK, bool) {
	for _, key := range jwks.Keys {
		if key.KID != nil && *key.KID == kid {
			return key, true
		}
	}
	return JWK{}, false
}

func jwkRSAPublicKey(jwk JWK) (*rsa.PublicKey, error) {
	if jwk.KTY != "RSA" {
		return nil, fmt.Errorf("invalid RSA public key: unsupported kty %s", jwk.KTY)
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, err
	}
	e := new(big.Int).SetBytes(eBytes).Int64()
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(e)}, nil
}

func decodeBase64URLJSON(input string, out any) error {
	raw, err := base64.RawURLEncoding.DecodeString(input)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}
