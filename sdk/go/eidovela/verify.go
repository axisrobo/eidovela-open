package eidovela

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

type Principal struct {
	TenantID         string
	AgentID          string
	AgentClass       string
	InstanceID       string
	WorkloadID       string
	AuthorityRootRef string
	Epoch            uint64
	Issuer           string
	Audience         string
	ExpiresAt        time.Time
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

// Verify fetches the issuer JWKS and verifies signature, audience, expiry and cnf binding.
// Callers requiring current lifecycle state must additionally use authoritative introspection.
func Verify(httpClient *http.Client, token, audience string, proofKey ed25519.PublicKey) (Principal, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Principal{}, ErrInvalidToken
	}
	decode := func(segment string, target any) error {
		raw, err := base64.RawURLEncoding.DecodeString(segment)
		if err != nil {
			return ErrInvalidToken
		}
		if err := json.Unmarshal(raw, target); err != nil {
			return ErrInvalidToken
		}
		return nil
	}
	var header struct{ Alg, Kid string }
	var claims map[string]any
	if err := decode(parts[0], &header); err != nil {
		return Principal{}, err
	}
	if err := decode(parts[1], &claims); err != nil {
		return Principal{}, err
	}
	if header.Alg != "EdDSA" {
		return Principal{}, ErrInvalidToken
	}
	issuer, ok := claims["iss"].(string)
	if !ok || issuer == "" {
		return Principal{}, ErrInvalidToken
	}
	client := httpClient
	if client == nil {
		client = http.DefaultClient
	}
	jwksURL := strings.Split(issuer, "/t/")[0] + "/jwks.json"
	response, err := client.Get(jwksURL)
	if err != nil {
		return Principal{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return Principal{}, ErrUnknownKey
	}
	var keys JWKS
	if err := json.NewDecoder(response.Body).Decode(&keys); err != nil {
		return Principal{}, err
	}
	var public ed25519.PublicKey
	for _, key := range keys.Keys {
		if key.Kid != header.Kid || key.Kty != "OKP" || key.Crv != "Ed25519" {
			continue
		}
		raw, err := base64.RawURLEncoding.DecodeString(key.X)
		if err == nil && len(raw) == ed25519.PublicKeySize {
			public = ed25519.PublicKey(raw)
			break
		}
	}
	if public == nil {
		return Principal{}, ErrUnknownKey
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(public, []byte(parts[0]+"."+parts[1]), signature) {
		return Principal{}, ErrInvalidToken
	}
	if !audienceContains(claims["aud"], audience) {
		return Principal{}, ErrAudienceMismatch
	}
	exp, ok := number(claims["exp"])
	if !ok || time.Now().Unix() >= exp {
		return Principal{}, ErrInactive
	}
	cnf, _ := claims["cnf"].(map[string]any)
	if jkt, _ := cnf["jkt"].(string); jkt == "" || jkt != Thumbprint(proofKey) {
		return Principal{}, ErrPoPMismatch
	}
	agentID, ok := claims["sub"].(string)
	if !ok {
		return Principal{}, ErrInvalidToken
	}
	epoch, ok := number(claims["lifecycle_epoch"])
	if !ok {
		return Principal{}, ErrInvalidToken
	}
	principal := Principal{AgentID: agentID, Epoch: uint64(epoch), Issuer: issuer, Audience: audience, ExpiresAt: time.Unix(exp, 0)}
	principal.TenantID = strings.TrimPrefix(issuer, strings.TrimSuffix(strings.Split(issuer, "/t/")[0], "/")+"/t/")
	principal.AgentClass, _ = claims["agent_class"].(string)
	principal.InstanceID, _ = claims["instance_id"].(string)
	principal.WorkloadID, _ = claims["workload_id"].(string)
	principal.AuthorityRootRef, _ = claims["authority_root_ref"].(string)
	return principal, nil
}

func Thumbprint(pub ed25519.PublicKey) string {
	canonical := `{"crv":"Ed25519","kty":"OKP","x":"` + b64(pub) + `"}`
	// Token issuers use the RFC 7638 SHA-256 JWK thumbprint.
	// Delegated to the standard hash primitive to avoid any secret material.
	return sha256B64([]byte(canonical))
}

func sha256B64(value []byte) string {
	sum := sha256.Sum256(value)
	return b64(sum[:])
}

func audienceContains(value any, audience string) bool {
	switch v := value.(type) {
	case string:
		return v == audience
	case []any:
		for _, item := range v {
			if item == audience {
				return true
			}
		}
	}
	return false
}

func number(value any) (int64, bool) {
	switch v := value.(type) {
	case float64:
		return int64(v), true
	case json.Number:
		n, err := v.Int64()
		return n, err == nil
	}
	return 0, false
}
