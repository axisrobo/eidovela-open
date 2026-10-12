package v3

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

var (
	// ErrInactive means the token is expired or otherwise not active.
	ErrInactive = errors.New("eidovela: token is inactive")
	// ErrPoPMismatch means the proof key does not match the token cnf binding.
	ErrPoPMismatch = errors.New("eidovela: proof key does not match token cnf")
	// ErrAudienceMismatch means the token audience does not match.
	ErrAudienceMismatch = errors.New("eidovela: token audience mismatch")
	// ErrUnknownKey means the signing key was not found in the issuer JWKS.
	ErrUnknownKey = errors.New("eidovela: token signing key not found in JWKS")
	// ErrInvalidToken means the token is malformed or fails verification.
	ErrInvalidToken = errors.New("eidovela: invalid token")
)

// Principal is the locally verified token identity. It mirrors the core v3.0
// claims: normalized agentClass, both registry epochs, the registry namespace,
// and the presenter key thumbprint.
type Principal struct {
	TenantID         string
	Namespace        string
	AgentID          string
	AgentClass       string
	InstanceID       string
	WorkloadID       string
	AuthorityRootRef string
	AgentEpoch       int64
	IdentityEpoch    int64
	JKT              string
	JTI              string
	Issuer           string
	Audience         string
	ExpiresAt        time.Time
}

type jwks struct {
	Keys []JWK `json:"keys"`
}

// Verify fetches the issuer JWKS and verifies signature, audience, expiry, the
// token cnf binding against proofKey, and the dual-epoch claims. Callers
// requiring current lifecycle state must additionally use authoritative
// introspection.
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
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
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
	var keys jwks
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
	jkt, _ := cnf["jkt"].(string)
	if jkt == "" || jkt != Thumbprint(proofKey) {
		return Principal{}, ErrPoPMismatch
	}
	agentID, ok := claims["sub"].(string)
	if !ok {
		return Principal{}, ErrInvalidToken
	}
	principal := Principal{AgentID: agentID, JKT: jkt, Issuer: issuer, Audience: audience, ExpiresAt: time.Unix(exp, 0)}
	principal.TenantID = tenantFromIssuer(issuer)
	principal.Namespace, _ = claims["registry"].(string)
	principal.AgentClass, _ = claims["agentClass"].(string)
	principal.InstanceID, _ = claims["instanceId"].(string)
	principal.WorkloadID, _ = claims["workloadId"].(string)
	principal.AuthorityRootRef, _ = claims["authorityRootRef"].(string)
	principal.JTI, _ = claims["jti"].(string)
	principal.AgentEpoch, _ = number(claims["agentEpoch"])
	principal.IdentityEpoch, _ = number(claims["identityEpoch"])
	if principal.AgentEpoch == 0 && principal.IdentityEpoch == 0 {
		// Legacy single-epoch token: fall back to lifecycleEpoch, but a v3
		// consumer should treat missing dual epochs as non-authoritative.
		if legacy, ok := number(claims["lifecycleEpoch"]); ok {
			principal.AgentEpoch = legacy
		}
	}
	return principal, nil
}

func tenantFromIssuer(issuer string) string {
	parts := strings.SplitN(issuer, "/t/", 2)
	if len(parts) != 2 {
		return ""
	}
	base := strings.TrimSuffix(parts[0], "/")
	return strings.TrimPrefix(issuer, base+"/t/")
}

// Thumbprint returns the RFC 7638 SHA-256 thumbprint of an Ed25519 key, byte-
// identical to the token cnf.jkt the issuer binds.
func Thumbprint(pub ed25519.PublicKey) string {
	canonical := `{"crv":"Ed25519","kty":"OKP","x":"` + b64(pub) + `"}`
	sum := sha256.Sum256([]byte(canonical))
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
