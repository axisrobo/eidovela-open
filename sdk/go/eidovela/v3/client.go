// Package v3 is the lowerCamelCase client for the EIDOVELA v3.0 wire surface.
//
// It mirrors the core registry-consumer daemon: enrollment, PoP token issuance,
// introspection (optionally token-bound context), registry read views, evidence,
// federation trust, brokered issuance, credentials and authentication state.
//
// The frozen `.../sdk/go/eidovela` package targets the v2 snake_case line and is
// unchanged; consumers on the current (v3.0) daemon should use this package.
package v3

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client is an HTTP client for the EIDOVELA v3.0 API.
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

// NewClient returns a client for baseURL (trailing slash trimmed).
func NewClient(baseURL string) *Client {
	return &Client{BaseURL: strings.TrimSuffix(baseURL, "/"), HTTPClient: http.DefaultClient}
}

// JWK is an Ed25519 public key as submitted and published (RFC 7517/7638).
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Kid string `json:"kid,omitempty"`
	Alg string `json:"alg,omitempty"`
	Use string `json:"use,omitempty"`
}

// JWKFromPublic renders an Ed25519 public key as an OKP JWK.
func JWKFromPublic(pub ed25519.PublicKey, kid string) JWK {
	return JWK{Kty: "OKP", Crv: "Ed25519", X: b64(pub), Kid: kid, Alg: "EdDSA", Use: "sig"}
}

// Challenge is an issued enrollment challenge.
type Challenge struct {
	EnrollmentID string    `json:"enrollmentId"`
	AgentID      string    `json:"agentId"`
	Nonce        string    `json:"nonce"`
	ExpiresAt    time.Time `json:"expiresAt"`
}

// Instance is the Agent Instance projection returned by completion and reads.
type Instance struct {
	InstanceID     string    `json:"instanceId"`
	AgentID        string    `json:"agentId"`
	WorkloadID     string    `json:"workloadId"`
	ArtifactDigest string    `json:"artifactDigest,omitempty"`
	AttestationRef string    `json:"attestationRef,omitempty"`
	LeaseExpiresAt time.Time `json:"leaseExpiresAt,omitempty"`
	Status         string    `json:"status"`
}

// WorkloadAttestation carries optional platform evidence for attested
// enrollment. Method is one of spiffe_svid, k8s_projected_sa or mtls.
type WorkloadAttestation struct {
	Method         string `json:"method"`
	CertificatePEM string `json:"certificatePem,omitempty"`
	Token          string `json:"token,omitempty"`
}

// TokenResponse is a PoP-bound short-lived identity token.
type TokenResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// RegistryAgent is the registry agent view (v3.0 camelCase).
type RegistryAgent struct {
	Namespace        string `json:"namespace"`
	AgentRef         string `json:"agentRef"`
	AgentID          string `json:"agentId"`
	AgentClass       string `json:"agentClass"`
	AgentState       string `json:"agentState"`
	IdentityState    string `json:"identityState"`
	AgentEpoch       int64  `json:"agentEpoch"`
	IdentityEpoch    int64  `json:"identityEpoch"`
	AuthorityRootRef string `json:"authorityRootRef,omitempty"`
	SponsorRef       string `json:"sponsorRef,omitempty"`
	Tokenable        bool   `json:"tokenable"`
}

// RegistryInstance is the registry instance view (v3.0 camelCase).
type RegistryInstance struct {
	InstanceID             string `json:"instanceId"`
	Namespace              string `json:"namespace"`
	AgentID                string `json:"agentId"`
	WorkloadRegistrationID string `json:"workloadRegistrationId"`
	WorkloadID             string `json:"workloadId"`
	ArtifactDigest         string `json:"artifactDigest"`
	AttestationRef         string `json:"attestationRef"`
	LeaseExpiresAt         string `json:"leaseExpiresAt,omitempty"`
	State                  string `json:"state"`
	Generation             int64  `json:"generation"`
	Tokenable              bool   `json:"tokenable"`
}

// EvidenceEvent is a sanitized security event. It never carries tokens, proofs
// or private key material.
type EvidenceEvent struct {
	EventID        string    `json:"eventId"`
	EventType      string    `json:"eventType"`
	AgentID        string    `json:"agentId,omitempty"`
	InstanceID     string    `json:"instanceId,omitempty"`
	LifecycleEpoch uint64    `json:"lifecycleEpoch,omitempty"`
	Outcome        string    `json:"outcome"`
	Reason         string    `json:"reason,omitempty"`
	CorrelationID  string    `json:"correlationId,omitempty"`
	CreatedAt      time.Time `json:"createdAt"`
}

// OutboxStats is a tenant-scoped outbox health summary.
type OutboxStats struct {
	Published    int `json:"published"`
	Pending      int `json:"pending"`
	Leased       int `json:"leased"`
	DeadLettered int `json:"deadLettered"`
}

// OutboxEvent is one outbox row (DLQ review projection).
type OutboxEvent struct {
	EventID        string    `json:"eventId"`
	Topic          string    `json:"topic"`
	AgentID        string    `json:"agentId,omitempty"`
	Epoch          uint64    `json:"epoch,omitempty"`
	State          string    `json:"state"`
	Attempts       uint32    `json:"attempts"`
	LeaseUntil     time.Time `json:"leaseUntil,omitempty"`
	CreatedAt      time.Time `json:"createdAt"`
	DeadLetteredAt time.Time `json:"deadLetteredAt,omitempty"`
}

// FederationTrust mirrors the core trust record. Field tags match the daemon
// exactly, including the mixed-cased legacy keys it still emits.
type FederationTrust struct {
	Issuer           string            `json:"issuer"`
	JWKSURI          string            `json:"jwks_uri,omitempty"`
	AllowedAudiences []string          `json:"allowed_audiences"`
	ClaimMappings    map[string]string `json:"claimMappings"`
	Status           string            `json:"status"`
	CreatedAt        time.Time         `json:"createdAt,omitempty"`
}

// FederationTrustStatus merges a trust with per-issuer introspection counters.
type FederationTrustStatus struct {
	Issuer  string `json:"issuer"`
	Status  string `json:"status"`
	Success int64  `json:"success"`
	Deny    int64  `json:"deny"`
}

// Credential is an Agent authentication credential record. Private material is
// never present.
type Credential struct {
	KID                  string `json:"kid"`
	AgentID              string `json:"agentId"`
	KeyThumbprint        string `json:"keyThumbprint"`
	Status               string `json:"status"`
	CredentialGeneration int64  `json:"credentialGeneration,omitempty"`
}

// AuthenticationRecord is an EIDOVELA authentication state override.
type AuthenticationRecord struct {
	AgentID              string    `json:"agentId"`
	AuthenticationState  string    `json:"authenticationState"`
	CredentialGeneration int64     `json:"credentialGeneration"`
	Reason               string    `json:"reason,omitempty"`
	UpdatedAt            time.Time `json:"updatedAt"`
}

// AttestationResult is a sanitized attestation result.
type AttestationResult struct {
	AttestationRef   string    `json:"attestationRef"`
	AgentID          string    `json:"agentId"`
	EnrollmentID     string    `json:"enrollmentId"`
	Method           string    `json:"method"`
	VerifierIdentity string    `json:"verifierIdentity"`
	EvidenceDigest   string    `json:"evidenceDigest"`
	AttributesDigest string    `json:"attributesDigest"`
	CreatedAt        time.Time `json:"createdAt"`
}

// CreateChallenge requests an enrollment challenge for an Agent and Workload
// Registration owned by the NOMIVELA registry.
func (c *Client) CreateChallenge(ctx context.Context, agentID, workloadRegistrationID string) (Challenge, error) {
	var challenge Challenge
	err := c.post(ctx, "/v1/enrollments", map[string]string{
		"agentId": agentID, "workloadRegistrationId": workloadRegistrationID,
	}, &challenge)
	return challenge, err
}

// CompleteEnrollment binds a proof key to the workload (no attestation).
func (c *Client) CompleteEnrollment(ctx context.Context, challenge Challenge, privateKey ed25519.PrivateKey, runtime, workloadID, artifactDigest string, workloadAttributes map[string]string) (Instance, error) {
	return c.CompleteEnrollmentWithAttestation(ctx, challenge, privateKey, runtime, workloadID, artifactDigest, workloadAttributes, nil)
}

// CompleteEnrollmentWithAttestation completes enrollment with optional
// transport-verified workload evidence.
func (c *Client) CompleteEnrollmentWithAttestation(ctx context.Context, challenge Challenge, privateKey ed25519.PrivateKey, runtime, workloadID, artifactDigest string, workloadAttributes map[string]string, attestation *WorkloadAttestation) (Instance, error) {
	pub := privateKey.Public().(ed25519.PublicKey)
	proof, err := enrollmentProof(challenge, privateKey)
	if err != nil {
		return Instance{}, err
	}
	body := map[string]any{
		"enrollmentId":       challenge.EnrollmentID,
		"proofJwt":           proof,
		"publicKey":          JWKFromPublic(pub, ""),
		"runtime":            runtime,
		"workloadId":         workloadID,
		"artifactDigest":     artifactDigest,
		"workloadAttributes": workloadAttributes,
	}
	if attestation != nil {
		body["attestation"] = attestation
	}
	var instance Instance
	err = c.post(ctx, "/v1/enrollments/complete", body, &instance)
	return instance, err
}

// Token requests a PoP-bound identity token for the agent and instance.
func (c *Client) Token(ctx context.Context, agentID, instanceID, audience string, privateKey ed25519.PrivateKey) (TokenResponse, error) {
	proof, err := tokenProof(agentID, instanceID, privateKey)
	if err != nil {
		return TokenResponse{}, err
	}
	var token TokenResponse
	err = c.post(ctx, "/oauth2/token", map[string]any{
		"agentId":    agentID,
		"instanceId": instanceID,
		"audience":   audience,
		"publicKey":  JWKFromPublic(privateKey.Public().(ed25519.PublicKey), ""),
		"proofJwt":   proof,
	}, &token)
	return token, err
}

// Exchange requests an RFC 8693 attenuation token; the core denies audience
// widening.
func (c *Client) Exchange(ctx context.Context, subjectToken, parentAudience, requestedAudience string, privateKey ed25519.PrivateKey) (TokenResponse, error) {
	var token TokenResponse
	err := c.post(ctx, "/v1/token/exchange", map[string]any{
		"subjectToken":      subjectToken,
		"parentAudience":    parentAudience,
		"requestedAudience": requestedAudience,
		"publicKey":         JWKFromPublic(privateKey.Public().(ed25519.PublicKey), ""),
	}, &token)
	return token, err
}

// Introspect asks the authority whether token is active for audience. A
// submitted public key alone is not proof of possession; prefer
// IntrospectContext for a proof-bound check.
func (c *Client) Introspect(ctx context.Context, token, audience string, privateKey ed25519.PrivateKey) (bool, error) {
	var response struct {
		Active bool `json:"active"`
	}
	err := c.post(ctx, "/v1/introspect", map[string]any{
		"token":     token,
		"audience":  audience,
		"publicKey": JWKFromPublic(privateKey.Public().(ed25519.PublicKey), ""),
	}, &response)
	return response.Active, err
}

// BrokerIssue imports a verified external assertion as a short-lived local
// PoP-bound token.
func (c *Client) BrokerIssue(ctx context.Context, assertion, audience string, privateKey ed25519.PrivateKey) (TokenResponse, error) {
	var token TokenResponse
	err := c.post(ctx, "/v1/broker/issue", map[string]any{
		"token":     assertion,
		"audience":  audience,
		"publicKey": JWKFromPublic(privateKey.Public().(ed25519.PublicKey), ""),
	}, &token)
	return token, err
}

// VerifiedContext fetches the verified agent context for an agent id, optionally
// binding an instance projection.
func (c *Client) VerifiedContext(ctx context.Context, agentID, instanceID string) (map[string]any, error) {
	q := url.Values{}
	q.Set("agentId", agentID)
	if instanceID != "" {
		q.Set("instanceId", instanceID)
	}
	var context map[string]any
	if err := c.get(ctx, "/v1/verified-agent-context?"+q.Encode(), &context); err != nil {
		return nil, err
	}
	return context, nil
}

// ListRegistryAgents lists the registry agent views.
func (c *Client) ListRegistryAgents(ctx context.Context) ([]RegistryAgent, error) {
	var envelope struct {
		Agents []RegistryAgent `json:"agents"`
	}
	err := c.get(ctx, "/v1/registry/agents", &envelope)
	return envelope.Agents, err
}

// GetRegistryAgent reads one registry agent view by id.
func (c *Client) GetRegistryAgent(ctx context.Context, agentID string) (RegistryAgent, error) {
	var agent RegistryAgent
	err := c.get(ctx, "/v1/registry/agents/"+url.PathEscape(agentID), &agent)
	return agent, err
}

// ListRegistryInstances lists the instances of an Agent.
func (c *Client) ListRegistryInstances(ctx context.Context, agentID string) ([]RegistryInstance, error) {
	var envelope struct {
		Instances []RegistryInstance `json:"instances"`
	}
	err := c.get(ctx, "/v1/registry/agents/"+url.PathEscape(agentID)+"/instances", &envelope)
	return envelope.Instances, err
}

// EvidenceEvents lists sanitized evidence, optionally since an RFC3339 time.
func (c *Client) EvidenceEvents(ctx context.Context, since string) ([]EvidenceEvent, error) {
	path := "/v1/evidence"
	if since != "" {
		path += "?since=" + url.QueryEscape(since)
	}
	var envelope struct {
		Evidence []EvidenceEvent `json:"evidence"`
	}
	err := c.get(ctx, path, &envelope)
	return envelope.Evidence, err
}

// OutboxStatus reads the outbox health summary.
func (c *Client) OutboxStatus(ctx context.Context) (OutboxStats, error) {
	var stats OutboxStats
	err := c.get(ctx, "/v1/ops/outbox", &stats)
	return stats, err
}

// OutboxEvents lists outbox rows.
func (c *Client) OutboxEvents(ctx context.Context) ([]OutboxEvent, error) {
	var envelope struct {
		Events []OutboxEvent `json:"events"`
	}
	err := c.get(ctx, "/v1/ops/outbox/events", &envelope)
	return envelope.Events, err
}

// RedriveOutboxEvent requeues a dead-lettered outbox entry.
func (c *Client) RedriveOutboxEvent(ctx context.Context, eventID string) error {
	return c.post(ctx, "/v1/ops/outbox/events/"+url.PathEscape(eventID)+"/redrive", nil, &struct{}{})
}

// KeyStatus is the read-only signing-key custody status. The core ops keys
// endpoint is a legacy surface and still emits snake_case fields.
type KeyStatus struct {
	ActiveKID string   `json:"active_kid"`
	Kids      []string `json:"kids"`
	Overlap   bool     `json:"overlap"`
}

// KeyStatus reads the active signing kid and the keys valid now (grace overlap).
func (c *Client) KeyStatus(ctx context.Context) (KeyStatus, error) {
	var status KeyStatus
	err := c.get(ctx, "/v1/ops/keys", &status)
	return status, err
}

// RotateSigningKey rotates the active signing key with an overlapping grace
// window (operator-initiated).
func (c *Client) RotateSigningKey(ctx context.Context) (KeyStatus, error) {
	var status KeyStatus
	err := c.post(ctx, "/v1/ops/keys/rotate", nil, &status)
	return status, err
}

// CreateFederationTrust creates or replaces a peer trust anchor.
func (c *Client) CreateFederationTrust(ctx context.Context, trust FederationTrust) (FederationTrust, error) {
	var saved FederationTrust
	err := c.post(ctx, "/v1/federation/trusts", trust, &saved)
	return saved, err
}

// FederationTrusts lists configured trusts.
func (c *Client) FederationTrusts(ctx context.Context) ([]FederationTrust, error) {
	var envelope struct {
		Trusts []FederationTrust `json:"trusts"`
	}
	err := c.get(ctx, "/v1/federation/trusts", &envelope)
	return envelope.Trusts, err
}

// SetFederationTrustStatus enables or disables a trust by issuer.
func (c *Client) SetFederationTrustStatus(ctx context.Context, issuer string, enable bool) (FederationTrust, error) {
	op := "disable"
	if enable {
		op = "enable"
	}
	var trust FederationTrust
	err := c.post(ctx, "/v1/federation/trusts/"+op, map[string]string{"issuer": issuer}, &trust)
	return trust, err
}

// FederationTrustStatuses reads trust health with per-issuer counters.
func (c *Client) FederationTrustStatuses(ctx context.Context) ([]FederationTrustStatus, error) {
	var envelope struct {
		Trusts []FederationTrustStatus `json:"trusts"`
	}
	err := c.get(ctx, "/v1/federation/trusts/status", &envelope)
	return envelope.Trusts, err
}

// ListCredentials lists an Agent's credentials.
func (c *Client) ListCredentials(ctx context.Context, agentID string) ([]Credential, error) {
	var envelope struct {
		Credentials []Credential `json:"credentials"`
	}
	err := c.get(ctx, "/v1/credentials?agentId="+url.QueryEscape(agentID), &envelope)
	return envelope.Credentials, err
}

// RevokeCredential revokes one credential generation.
func (c *Client) RevokeCredential(ctx context.Context, agentID, kid, reason string) error {
	body := map[string]string{"agentId": agentID, "kid": kid}
	if reason != "" {
		body["reason"] = reason
	}
	return c.post(ctx, "/v1/credential-revocations", body, &struct{}{})
}

// SetAuthenticationState applies an authentication override by Operation:
// "quarantine", "disable" or "reinstate".
func (c *Client) SetAuthenticationState(ctx context.Context, agentID, op, reason string) (AuthenticationRecord, error) {
	var record AuthenticationRecord
	var body any
	if reason != "" {
		body = map[string]string{"reason": reason}
	}
	err := c.post(ctx, "/v1/authentication-state/"+url.PathEscape(agentID)+"/"+op, body, &record)
	return record, err
}

// GetAttestation resolves a sanitized attestation result by reference.
func (c *Client) GetAttestation(ctx context.Context, ref string) (AttestationResult, error) {
	var result AttestationResult
	err := c.get(ctx, "/v1/attestations/"+url.PathEscape(ref), &result)
	return result, err
}

func enrollmentProof(challenge Challenge, privateKey ed25519.PrivateKey) (string, error) {
	claims := map[string]any{
		"iss": challenge.AgentID, "sub": challenge.AgentID,
		"aud": "eidovela:enroll", "jti": challenge.EnrollmentID, "nonce": challenge.Nonce,
		"exp": time.Now().Add(time.Minute).Unix(),
	}
	return sign(privateKey, claims)
}

func tokenProof(agentID, instanceID string, privateKey ed25519.PrivateKey) (string, error) {
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	return sign(privateKey, map[string]any{
		"iss": agentID, "sub": instanceID, "aud": "eidovela:token",
		"jti": b64(jti), "exp": time.Now().Add(time.Minute).Unix(),
	})
}

func sign(privateKey ed25519.PrivateKey, claims map[string]any) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := b64(header) + "." + b64(payload)
	return input + "." + b64(ed25519.Sign(privateKey, []byte(input))), nil
}

func (c *Client) post(ctx context.Context, path string, request, response any) error {
	body, err := json.Marshal(request)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req, response)
}

func (c *Client) get(ctx context.Context, path string, response any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return err
	}
	return c.do(req, response)
}

func (c *Client) do(req *http.Request, response any) error {
	client := c.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		var failure struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(res.Body).Decode(&failure)
		if failure.Error == "" {
			failure.Error = res.Status
		}
		return fmt.Errorf("eidovela: %s", failure.Error)
	}
	if response == nil {
		return nil
	}
	return json.NewDecoder(res.Body).Decode(response)
}

func b64(data []byte) string { return base64.RawURLEncoding.EncodeToString(data) }
