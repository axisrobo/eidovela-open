package v3

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestThumbprintMatchesRFC7638CanonicalForm(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	canonical := `{"crv":"Ed25519","kty":"OKP","x":"` + b64(pub) + `"}`
	sum := sha256.Sum256([]byte(canonical))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if got := Thumbprint(pub); got != want {
		t.Fatalf("Thumbprint = %q, want %q", got, want)
	}
}

// signCamelCase signs a v3 token with camelCase claims and the dual epochs.
func signCamelCase(t *testing.T, priv ed25519.PrivateKey, kid, issuer string, claims map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": kid})
	payload, _ := json.Marshal(claims)
	input := b64(header) + "." + b64(payload)
	return input + "." + b64(ed25519.Sign(priv, []byte(input)))
}

func TestVerifyParsesCamelCaseDualEpochClaims(t *testing.T) {
	presenterPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuerPub, issuerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{
			map[string]any{"kty": "OKP", "crv": "Ed25519", "x": b64(issuerPub), "kid": "k1", "alg": "EdDSA", "use": "sig"},
		}})
	}))
	defer jwks.Close()
	issuer := jwks.URL + "/t/local"

	token := signCamelCase(t, issuerPriv, "k1", issuer, map[string]any{
		"iss": issuer, "sub": "agent-1", "aud": "aegivela", "exp": time.Now().Add(time.Minute).Unix(),
		"agentClass": "service", "instanceId": "inst-1", "workloadId": "wl", "authorityRootRef": "org:acme",
		"agentEpoch": 3, "identityEpoch": 7, "registry": "https://registry.example.test",
		"jti": "tkn_1", "cnf": map[string]any{"jkt": Thumbprint(presenterPub)},
	})
	principal, err := Verify(jwks.Client(), token, "aegivela", presenterPub)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if principal.AgentID != "agent-1" || principal.AgentClass != "service" || principal.InstanceID != "inst-1" ||
		principal.AgentEpoch != 3 || principal.IdentityEpoch != 7 || principal.Namespace != "https://registry.example.test" ||
		principal.TenantID != "local" {
		t.Fatalf("principal = %+v", principal)
	}

	// A different presenter key must fail the cnf binding.
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(jwks.Client(), token, "aegivela", otherPub); !errors.Is(err, ErrPoPMismatch) {
		t.Fatalf("err = %v, want ErrPoPMismatch", err)
	}
}
