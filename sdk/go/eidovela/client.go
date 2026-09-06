// Package eidovela provides an HTTP client and token verifier for EIDOVELA.
package eidovela

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var (
	ErrInactive         = errors.New("eidovela: token is inactive")
	ErrPoPMismatch      = errors.New("eidovela: proof key does not match token cnf")
	ErrAudienceMismatch = errors.New("eidovela: token audience mismatch")
	ErrUnknownKey       = errors.New("eidovela: token signing key not found in JWKS")
	ErrInvalidToken     = errors.New("eidovela: invalid token")
)

type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

func NewClient(baseURL string) *Client {
	return &Client{BaseURL: strings.TrimSuffix(baseURL, "/"), HTTPClient: http.DefaultClient}
}

type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Kid string `json:"kid,omitempty"`
	Alg string `json:"alg,omitempty"`
	Use string `json:"use,omitempty"`
}

type RegisterAgentRequest struct {
	Class            string `json:"class"`
	BlueprintID      string `json:"blueprint_id,omitempty"`
	BlueprintVersion string `json:"blueprint_version,omitempty"`
	BindingType      string `json:"binding_type"`
	AuthorityRootRef string `json:"authority_root_ref"`
	SponsorRef       string `json:"sponsor_ref,omitempty"`
}

type Agent struct {
	AgentID string `json:"agent_id"`
	State   string `json:"lifecycle_state"`
	Epoch   uint64 `json:"lifecycle_epoch"`
}

type WorkloadRegistrationRequest struct {
	Platform            string            `json:"platform"`
	Selector            map[string]string `json:"selector"`
	TrustDomain         string            `json:"trust_domain"`
	AllowedProofMethods []string          `json:"allowed_proof_methods"`
}

type WorkloadRegistration struct {
	RegistrationID string `json:"registration_id"`
}

type Challenge struct {
	ID        string    `json:"enrollment_id"`
	AgentID   string    `json:"agent_id"`
	Nonce     string    `json:"nonce"`
	ExpiresAt time.Time `json:"expires_at"`
}

type Instance struct {
	InstanceID     string    `json:"instance_id"`
	AgentID        string    `json:"agent_id"`
	WorkloadID     string    `json:"workload_id"`
	Status         string    `json:"status"`
	LeaseExpiresAt time.Time `json:"lease_expires_at,omitempty"`
}

type TokenResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// FederationTrust is the wire representation of a peer trust anchor. Tenant is
// server-scoped; a caller-supplied TenantID is discarded.
type FederationTrust struct {
	TenantID         string            `json:"tenant_id,omitempty"`
	Issuer           string            `json:"issuer"`
	JWKSURI          string            `json:"jwks_uri,omitempty"`
	AllowedAudiences []string          `json:"allowed_audiences"`
	ClaimMappings    map[string]string `json:"claim_mappings"`
	Status           string            `json:"status"`
	CreatedAt        time.Time         `json:"created_at,omitempty"`
}

type federationTrustList struct {
	Trusts []FederationTrust `json:"trusts"`
}

type federationTrustStatusRequest struct {
	Issuer string `json:"issuer"`
}

func (c *Client) RegisterAgent(ctx context.Context, req RegisterAgentRequest) (Agent, error) {
	var agent Agent
	err := c.post(ctx, "/v1/agents", req, &agent)
	return agent, err
}

func (c *Client) RegisterWorkload(ctx context.Context, req WorkloadRegistrationRequest) (WorkloadRegistration, error) {
	var workload WorkloadRegistration
	err := c.post(ctx, "/v1/workload-registrations", req, &workload)
	return workload, err
}

func (c *Client) CreateChallenge(ctx context.Context, agentID, workloadRegistrationID string) (Challenge, error) {
	var challenge Challenge
	err := c.post(ctx, "/v1/enrollments", map[string]string{
		"agent_id": agentID, "workload_registration_id": workloadRegistrationID,
	}, &challenge)
	return challenge, err
}

// CompleteEnrollment binds a proof key to a workload only when its verified
// workloadAttributes satisfy every selector in the workload registration.
func (c *Client) CompleteEnrollment(ctx context.Context, challenge Challenge, privateKey ed25519.PrivateKey, runtime, workloadID, artifactDigest string, workloadAttributes map[string]string) (Instance, error) {
	return c.CompleteEnrollmentWithAttestation(ctx, challenge, privateKey, runtime, workloadID, artifactDigest, workloadAttributes, nil)
}

// WorkloadAttestation carries optional platform evidence for attested
// enrollment. Method is one of spiffe_svid, k8s_projected_sa or mtls;
// CertificatePEM is the PEM leaf for spiffe_svid/mtls and Token is the raw
// projected service-account JWT for k8s_projected_sa.
type WorkloadAttestation struct {
	Method         string `json:"method"`
	CertificatePEM string `json:"certificate_pem,omitempty"`
	Token          string `json:"token,omitempty"`
}

// CompleteEnrollmentWithAttestation is CompleteEnrollment with optional
// transport-verified workload evidence. When attestation is supplied, the core
// derives trusted selector attributes from the evidence instead of trusting
// caller-supplied workloadAttributes.
func (c *Client) CompleteEnrollmentWithAttestation(ctx context.Context, challenge Challenge, privateKey ed25519.PrivateKey, runtime, workloadID, artifactDigest string, workloadAttributes map[string]string, attestation *WorkloadAttestation) (Instance, error) {
	pub := privateKey.Public().(ed25519.PublicKey)
	proof, err := enrollmentProof(challenge, privateKey)
	if err != nil {
		return Instance{}, err
	}
	body := map[string]any{
		"enrollment_id":       challenge.ID,
		"proof_jwt":           proof,
		"public_key":          JWKFromPublic(pub, ""),
		"runtime":             runtime,
		"workload_id":         workloadID,
		"artifact_digest":     artifactDigest,
		"workload_attributes": workloadAttributes,
	}
	if attestation != nil {
		body["attestation"] = attestation
	}
	var instance Instance
	err = c.post(ctx, "/v1/enrollments/complete", body, &instance)
	return instance, err
}

func (c *Client) Activate(ctx context.Context, agentID string) (Agent, error) {
	var agent Agent
	err := c.post(ctx, "/v1/agents/"+agentID+"/activate", nil, &agent)
	return agent, err
}

// LeaseInstance binds an instance to an expiry and moves it to active. While the
// lease is set, the instance is tokenable only before the expiry; instances
// without a lease keep the legacy unlimited semantics. The server caps lease
// duration.
func (c *Client) LeaseInstance(ctx context.Context, instanceID string, expiresAt time.Time) (Instance, error) {
	var instance Instance
	err := c.post(ctx, "/v1/instances/"+instanceID+"/lease", map[string]any{"lease_expires_at": expiresAt}, &instance)
	return instance, err
}

// TerminateInstance moves an instance to the terminal terminated state. A
// terminated instance cannot request tokens and cannot be leased again.
func (c *Client) TerminateInstance(ctx context.Context, instanceID string) (Instance, error) {
	var instance Instance
	err := c.post(ctx, "/v1/instances/"+instanceID+"/terminate", nil, &instance)
	return instance, err
}

func (c *Client) Suspend(ctx context.Context, agentID string) (Agent, error) {
	var agent Agent
	err := c.post(ctx, "/v1/agents/"+agentID+"/suspend", nil, &agent)
	return agent, err
}

// Revoke transitions an agent to the terminal revoked state. A revoked agent
// cannot obtain tokens and its previously issued tokens fail authoritative
// introspection immediately (revocation SLO).
func (c *Client) Revoke(ctx context.Context, agentID string) (Agent, error) {
	var agent Agent
	err := c.post(ctx, "/v1/agents/"+agentID+"/revoke", nil, &agent)
	return agent, err
}

func (c *Client) Token(ctx context.Context, agentID, instanceID, audience string, privateKey ed25519.PrivateKey) (TokenResponse, error) {
	proof, err := tokenProof(agentID, instanceID, privateKey)
	if err != nil {
		return TokenResponse{}, err
	}
	var token TokenResponse
	err = c.post(ctx, "/oauth2/token", map[string]any{
		"agent_id":    agentID,
		"instance_id": instanceID,
		"audience":    audience,
		"public_key":  JWKFromPublic(privateKey.Public().(ed25519.PublicKey), ""),
		"proof_jwt":   proof,
	}, &token)
	return token, err
}

func tokenProof(agentID, instanceID string, privateKey ed25519.PrivateKey) (string, error) {
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	return sign(privateKey, map[string]any{"iss": agentID, "sub": instanceID, "aud": "eidovela:token", "jti": b64(jti), "exp": time.Now().Add(time.Minute).Unix()})
}

// Exchange requests an RFC 8693 attenuation token. The core only permits the
// child to retain the parent audience and expiry; audience widening is denied.
func (c *Client) Exchange(ctx context.Context, subjectToken, parentAudience, requestedAudience string, privateKey ed25519.PrivateKey) (TokenResponse, error) {
	var token TokenResponse
	err := c.post(ctx, "/v1/token/exchange", map[string]any{
		"subject_token": subjectToken, "parent_audience": parentAudience,
		"requested_audience": requestedAudience,
		"public_key":         JWKFromPublic(privateKey.Public().(ed25519.PublicKey), ""),
	}, &token)
	return token, err
}

// Introspect asks the authoritative authority whether token is active for
// audience. The audience is required: tokens issued for one audience are
// inactive when introspected for another.
func (c *Client) Introspect(ctx context.Context, token, audience string, privateKey ed25519.PrivateKey) (bool, error) {
	var response struct {
		Active bool `json:"active"`
	}
	err := c.post(ctx, "/v1/introspect", map[string]any{
		"token": token, "audience": audience,
		"public_key": JWKFromPublic(privateKey.Public().(ed25519.PublicKey), ""),
	}, &response)
	return response.Active, err
}

// CreateFederationTrust creates or replaces a trust anchor for a peer issuer.
// The server revalidates the full configuration on every write.
func (c *Client) CreateFederationTrust(ctx context.Context, trust FederationTrust) (FederationTrust, error) {
	var saved FederationTrust
	err := c.post(ctx, "/v1/federation/trusts", trust, &saved)
	return saved, err
}

func (c *Client) ListFederationTrusts(ctx context.Context) ([]FederationTrust, error) {
	var list federationTrustList
	err := c.get(ctx, "/v1/federation/trusts", &list)
	return list.Trusts, err
}

func (c *Client) GetFederationTrust(ctx context.Context, issuer string) (FederationTrust, error) {
	var trust FederationTrust
	err := c.get(ctx, "/v1/federation/trusts?issuer="+url.QueryEscape(issuer), &trust)
	return trust, err
}

func (c *Client) EnableFederationTrust(ctx context.Context, issuer string) (FederationTrust, error) {
	var trust FederationTrust
	err := c.post(ctx, "/v1/federation/trusts/enable", federationTrustStatusRequest{Issuer: issuer}, &trust)
	return trust, err
}

func (c *Client) DisableFederationTrust(ctx context.Context, issuer string) (FederationTrust, error) {
	var trust FederationTrust
	err := c.post(ctx, "/v1/federation/trusts/disable", federationTrustStatusRequest{Issuer: issuer}, &trust)
	return trust, err
}

func GeneratePoPKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// AgentSummary is the read-projection shape of an agent.
type AgentSummary struct {
	AgentID        string    `json:"agent_id"`
	AgentClass     string    `json:"agent_class"`
	AuthorityRoot  string    `json:"authority_root_ref"`
	LifecycleState string    `json:"lifecycle_state"`
	Epoch          uint64    `json:"lifecycle_epoch"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type EvidenceRecord struct {
	ID             string    `json:"event_id"`
	Type           string    `json:"event_type"`
	AgentID        string    `json:"agent_id,omitempty"`
	InstanceID     string    `json:"instance_id,omitempty"`
	LifecycleEpoch uint64    `json:"lifecycle_epoch,omitempty"`
	Outcome        string    `json:"outcome"`
	PayloadHash    string    `json:"payload_hash,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

type OutboxStatus struct {
	Published    int `json:"published"`
	Pending      int `json:"pending"`
	Leased       int `json:"leased"`
	DeadLettered int `json:"dead_lettered"`
}

// FederationTrustStatus is a trust merged with per-issuer introspection
// outcome telemetry (process-local counters).
type FederationTrustStatus struct {
	Issuer  string `json:"issuer"`
	Status  string `json:"status"`
	Success int64  `json:"success"`
	Deny    int64  `json:"deny"`
}

func (c *Client) ListAgents(ctx context.Context, state string, limit, offset int) ([]AgentSummary, error) {
	var envelope struct {
		Agents []AgentSummary `json:"agents"`
	}
	path := "/v1/agents?" + pageQuery(state != "", "state="+url.QueryEscape(state), limit, offset)
	err := c.get(ctx, path, &envelope)
	return envelope.Agents, err
}

func (c *Client) ListAgentInstances(ctx context.Context, agentID string, limit, offset int) ([]Instance, error) {
	var envelope struct {
		Instances []Instance `json:"instances"`
	}
	err := c.get(ctx, "/v1/agents/"+agentID+"/instances?"+pageQuery(false, "", limit, offset), &envelope)
	return envelope.Instances, err
}

func (c *Client) ListEvidence(ctx context.Context, eventType string, limit, offset int) ([]EvidenceRecord, error) {
	return c.ListEvidenceSince(ctx, eventType, nil, limit, offset)
}

func (c *Client) ListEvidenceSince(ctx context.Context, eventType string, since *time.Time, limit, offset int) ([]EvidenceRecord, error) {
	var envelope struct {
		Evidence []EvidenceRecord `json:"evidence"`
	}
	params := []string{}
	if eventType != "" {
		params = append(params, "event_type="+url.QueryEscape(eventType))
	}
	if since != nil {
		params = append(params, "since="+url.QueryEscape(since.UTC().Format(time.RFC3339)))
	}
	params = append(params, pageQuery(false, "", limit, offset))
	path := "/v1/evidence?" + strings.Join(params, "&")
	err := c.get(ctx, path, &envelope)
	return envelope.Evidence, err
}

// AgentDetail reads a single tenant agent.
func (c *Client) AgentDetail(ctx context.Context, agentID string) (AgentSummary, error) {
	var agent AgentSummary
	err := c.get(ctx, "/v1/agents/"+agentID, &agent)
	return agent, err
}

func (c *Client) OutboxStatus(ctx context.Context) (OutboxStatus, error) {
	var status OutboxStatus
	err := c.get(ctx, "/v1/ops/outbox", &status)
	return status, err
}

func (c *Client) FederationTrustStatuses(ctx context.Context) ([]FederationTrustStatus, error) {
	var envelope struct {
		Trusts []FederationTrustStatus `json:"trusts"`
	}
	err := c.get(ctx, "/v1/federation/trusts/status", &envelope)
	return envelope.Trusts, err
}

// pageQuery composes limit/offset query params; filter, when non-empty, is
// already URL-escaped by the caller.
func pageQuery(hasFilter bool, filter string, limit, offset int) string {
	params := []string{}
	if hasFilter {
		params = append(params, filter)
	}
	if limit > 0 {
		params = append(params, fmt.Sprintf("limit=%d", limit))
	}
	if offset > 0 {
		params = append(params, fmt.Sprintf("offset=%d", offset))
	}
	return strings.Join(params, "&")
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
	return json.NewDecoder(res.Body).Decode(response)
}

func (c *Client) get(ctx context.Context, path string, response any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return err
	}
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
	return json.NewDecoder(res.Body).Decode(response)
}

func enrollmentProof(challenge Challenge, privateKey ed25519.PrivateKey) (string, error) {
	claims := map[string]any{
		"iss": challenge.AgentID, "sub": challenge.AgentID,
		"aud": "eidovela:enroll", "jti": challenge.ID, "nonce": challenge.Nonce,
		"exp": time.Now().Add(time.Minute).Unix(),
	}
	return sign(privateKey, claims)
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

func JWKFromPublic(pub ed25519.PublicKey, kid string) JWK {
	return JWK{Kty: "OKP", Crv: "Ed25519", X: b64(pub), Kid: kid, Alg: "EdDSA", Use: "sig"}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
