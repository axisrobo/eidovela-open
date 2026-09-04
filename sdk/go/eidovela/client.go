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
	InstanceID string `json:"instance_id"`
	AgentID    string `json:"agent_id"`
	WorkloadID string `json:"workload_id"`
	Status     string `json:"status"`
}

type TokenResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
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
	pub := privateKey.Public().(ed25519.PublicKey)
	proof, err := enrollmentProof(challenge, privateKey)
	if err != nil {
		return Instance{}, err
	}
	var instance Instance
	err = c.post(ctx, "/v1/enrollments/complete", map[string]any{
		"enrollment_id":       challenge.ID,
		"proof_jwt":           proof,
		"public_key":          JWKFromPublic(pub, ""),
		"runtime":             runtime,
		"workload_id":         workloadID,
		"artifact_digest":     artifactDigest,
		"workload_attributes": workloadAttributes,
	}, &instance)
	return instance, err
}

func (c *Client) Activate(ctx context.Context, agentID string) (Agent, error) {
	var agent Agent
	err := c.post(ctx, "/v1/agents/"+agentID+"/activate", nil, &agent)
	return agent, err
}

func (c *Client) Suspend(ctx context.Context, agentID string) (Agent, error) {
	var agent Agent
	err := c.post(ctx, "/v1/agents/"+agentID+"/suspend", nil, &agent)
	return agent, err
}

func (c *Client) Token(ctx context.Context, agentID, instanceID, audience string, privateKey ed25519.PrivateKey) (TokenResponse, error) {
	var token TokenResponse
	err := c.post(ctx, "/oauth2/token", map[string]any{
		"agent_id":    agentID,
		"instance_id": instanceID,
		"audience":    audience,
		"public_key":  JWKFromPublic(privateKey.Public().(ed25519.PublicKey), ""),
	}, &token)
	return token, err
}

func (c *Client) Introspect(ctx context.Context, token string, privateKey ed25519.PrivateKey) (bool, error) {
	var response struct {
		Active bool `json:"active"`
	}
	err := c.post(ctx, "/v1/introspect", map[string]any{
		"token": token, "public_key": JWKFromPublic(privateKey.Public().(ed25519.PublicKey), ""),
	}, &response)
	return response.Active, err
}

func GeneratePoPKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
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
