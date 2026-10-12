package eidovela

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// TokenContext is the candidate FP-1 proof-bound context, not a portable grant.
type TokenContext struct {
	SchemaVersion string    `json:"schemaVersion"`
	Namespace     string    `json:"namespace"`
	AgentID       string    `json:"agentId"`
	AgentRef      string    `json:"agentRef"`
	AgentClass    string    `json:"agentClass"`
	RegistryClass string    `json:"registryClass"`
	IdentityType  string    `json:"identityType"`
	SubjectRef    string    `json:"subjectRef,omitempty"`
	AgentEpoch    int64     `json:"agentEpoch"`
	IdentityEpoch int64     `json:"identityEpoch"`
	InstanceID    string    `json:"instanceId"`
	Issuer        string    `json:"issuer"`
	Audience      string    `json:"audience"`
	ExpiresAt     time.Time `json:"expiresAt"`
	TokenHash     string    `json:"tokenHash"`
	PresenterJKT  string    `json:"presenterJkt"`
}

// SignDPoP creates a fresh Ed25519 proof for one target and exact token. To
// present through a gateway, call separately for resource and introspection.
func SignDPoP(key ed25519.PrivateKey, method, target, token string, issuedAt time.Time) (string, error) {
	if len(key) != ed25519.PrivateKeySize || method == "" || token == "" || issuedAt.IsZero() {
		return "", ErrInvalidToken
	}
	uri, err := url.Parse(target)
	if err != nil || uri.Host == "" || uri.User != nil || uri.Opaque != "" ||
		(uri.Scheme != "https" && uri.Scheme != "http") {
		return "", ErrInvalidToken
	}
	uri.RawQuery, uri.Fragment, uri.RawFragment, uri.ForceQuery = "", "", "", false
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	header, err := json.Marshal(map[string]any{"typ": "dpop+jwt", "alg": "EdDSA", "jwk": JWKFromPublic(key.Public().(ed25519.PublicKey), "")})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(token))
	claims, err := json.Marshal(map[string]any{"htm": method, "htu": uri.String(), "ath": b64(sum[:]), "iat": issuedAt.Unix(), "jti": b64(jti)})
	if err != nil {
		return "", err
	}
	input := b64(header) + "." + b64(claims)
	return input + "." + b64(ed25519.Sign(key, []byte(input))), nil
}

// IntrospectContext relays an unchanged client proof and checks the result's
// token/key binding. Caller must additionally enforce configured issuer and
// namespace policy and validate/consume the separate resource proof.
func (c *Client) IntrospectContext(ctx context.Context, token, audience, proof string, presenter ed25519.PublicKey) (TokenContext, error) {
	if token == "" || audience == "" || proof == "" || len(presenter) != ed25519.PublicKeySize {
		return TokenContext{}, ErrInvalidToken
	}
	endpoint, err := url.Parse(c.BaseURL + "/v1/introspect")
	if err != nil || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Opaque != "" {
		return TokenContext{}, ErrInvalidToken
	}
	loopback := net.ParseIP(endpoint.Hostname())
	if endpoint.Scheme != "https" && !(endpoint.Scheme == "http" && loopback != nil && loopback.IsLoopback()) {
		return TokenContext{}, fmt.Errorf("eidovela: context requires TLS (loopback HTTP only for tests)")
	}
	body, err := json.Marshal(map[string]any{"token": token, "audience": audience, "dpopProof": proof, "includeContext": true})
	if err != nil {
		return TokenContext{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return TokenContext{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	base := c.HTTPClient
	if base == nil {
		base = http.DefaultClient
	}
	client := *base
	if client.Timeout <= 0 || client.Timeout > 10*time.Second {
		client.Timeout = 10 * time.Second
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, err := client.Do(req)
	if err != nil {
		return TokenContext{}, fmt.Errorf("eidovela: context transport failed")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return TokenContext{}, fmt.Errorf("eidovela: context HTTP %d", res.StatusCode)
	}
	const maxResponse = 64 * 1024
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxResponse+1))
	if err != nil || len(raw) > maxResponse {
		return TokenContext{}, ErrInvalidToken
	}
	var response struct {
		Active  *bool         `json:"active"`
		Context *TokenContext `json:"context"`
	}
	if err := json.Unmarshal(raw, &response); err != nil || response.Active == nil {
		return TokenContext{}, ErrInvalidToken
	}
	if !*response.Active {
		return TokenContext{}, ErrInactive
	}
	if response.Context == nil {
		return TokenContext{}, ErrInvalidToken
	}
	result := *response.Context
	sum := sha256.Sum256([]byte(token))
	if result.SchemaVersion != "eidovela.token-context.v1" || result.TokenHash != b64(sum[:]) ||
		result.PresenterJKT != Thumbprint(presenter) || result.Audience != audience ||
		result.Namespace == "" || result.Issuer == "" || result.AgentID == "" || result.AgentRef == "" || result.RegistryClass == "" ||
		result.InstanceID == "" || result.AgentEpoch <= 0 || result.IdentityEpoch <= 0 || !time.Now().Before(result.ExpiresAt) {
		return TokenContext{}, ErrInvalidToken
	}
	if result.AgentClass != "service" && result.AgentClass != "twin" && result.AgentClass != "ephemeral" {
		return TokenContext{}, ErrInvalidToken
	}
	switch result.IdentityType {
	case "interactive", "digitalEmployee":
		if strings.TrimSpace(result.SubjectRef) == "" {
			return TokenContext{}, ErrInvalidToken
		}
	case "autonomous":
		if result.SubjectRef != "" {
			return TokenContext{}, ErrInvalidToken
		}
	default:
		return TokenContext{}, ErrInvalidToken
	}
	return result, nil
}
