package eidovela

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSignDPoPSeparateTargets(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1800000000, 0)
	token := "exact-token"
	var previousJTI string
	for _, target := range []struct{ method, uri string }{
		{"GET", "https://resource.example.test/items/1?query=unsigned#fragment"},
		{"POST", "https://id.example.test/v1/introspect"},
	} {
		raw, err := SignDPoP(key, target.method, target.uri, token, now)
		if err != nil {
			t.Fatal(err)
		}
		parts := strings.Split(raw, ".")
		if len(parts) != 3 {
			t.Fatal("invalid proof encoding")
		}
		var header struct {
			Typ string `json:"typ"`
			Alg string `json:"alg"`
			JWK JWK    `json:"jwk"`
		}
		var claims struct {
			HTM string `json:"htm"`
			HTU string `json:"htu"`
			ATH string `json:"ath"`
			IAT int64  `json:"iat"`
			JTI string `json:"jti"`
		}
		hb, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil {
			t.Fatal(err)
		}
		cb, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(hb, &header); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(cb, &claims); err != nil {
			t.Fatal(err)
		}
		sig, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			t.Fatal(err)
		}
		if !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
			t.Fatal("invalid signature")
		}
		sum := sha256.Sum256([]byte(token))
		wantURI := strings.Split(strings.Split(target.uri, "?")[0], "#")[0]
		if header.Typ != "dpop+jwt" || header.Alg != "EdDSA" || header.JWK.X != b64(pub) ||
			claims.HTM != target.method || claims.HTU != wantURI || claims.ATH != b64(sum[:]) || claims.IAT != now.Unix() ||
			claims.JTI == "" || claims.JTI == previousJTI {
			t.Fatalf("invalid DPoP header/claims: %+v %+v", header, claims)
		}
		previousJTI = claims.JTI
	}
}

func TestSignDPoPInvalidInput(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"/relative", "https://user@host/path", "file:///path", "https://host/%zz"} {
		if _, err := SignDPoP(key, "POST", target, "token", time.Now()); err == nil {
			t.Fatalf("accepted %q", target)
		}
	}
	if _, err := SignDPoP(nil, "POST", "https://id.example.test/v1/introspect", "token", time.Now()); err == nil {
		t.Fatal("accepted missing key")
	}
}

func TestIntrospectContextResponseBinding(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("token"))
	for _, tc := range []struct {
		name   string
		change func(*TokenContext)
		active bool
		omit   bool
		want   error
	}{
		{"valid", nil, true, false, nil},
		{"wrong token", func(c *TokenContext) { c.TokenHash = "wrong" }, true, false, ErrInvalidToken},
		{"wrong key", func(c *TokenContext) { c.PresenterJKT = "wrong" }, true, false, ErrInvalidToken},
		{"wrong audience", func(c *TokenContext) { c.Audience = "other" }, true, false, ErrInvalidToken},
		{"missing identity", func(c *TokenContext) { c.IdentityType = "" }, true, false, ErrInvalidToken},
		{"missing subject", func(c *TokenContext) { c.SubjectRef = " " }, true, false, ErrInvalidToken},
		{"autonomous with subject", func(c *TokenContext) { c.IdentityType = "autonomous" }, true, false, ErrInvalidToken},
		{"missing epoch", func(c *TokenContext) { c.IdentityEpoch = 0 }, true, false, ErrInvalidToken},
		{"expired", func(c *TokenContext) { c.ExpiresAt = time.Now().Add(-time.Second) }, true, false, ErrInvalidToken},
		{"wrong version", func(c *TokenContext) { c.SchemaVersion = "future" }, true, false, ErrInvalidToken},
		{"active only", nil, true, true, ErrInvalidToken},
		{"inactive", nil, false, true, ErrInactive},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := TokenContext{
				SchemaVersion: "eidovela.token-context.v1", Namespace: "https://registry.example.test", AgentID: "agent-id", AgentRef: "agent_demo",
				AgentClass: "service", RegistryClass: "organizational", IdentityType: "interactive", SubjectRef: "user:alice",
				AgentEpoch: 2, IdentityEpoch: 5, InstanceID: "instance-id", Issuer: "https://id.example.test/t/local", Audience: "limenora",
				ExpiresAt: time.Now().Add(time.Minute), TokenHash: b64(sum[:]), PresenterJKT: Thumbprint(pub),
			}
			if tc.change != nil {
				tc.change(&response)
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var payload map[string]any
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Error(err)
				}
				if r.Method != "POST" || r.URL.Path != "/v1/introspect" || payload["includeContext"] != true || payload["dpopProof"] != "unchanged-proof" || payload["publicKey"] != nil {
					t.Errorf("unexpected request: %s %s %+v", r.Method, r.URL.Path, payload)
				}
				out := map[string]any{"active": tc.active}
				if !tc.omit {
					out["context"] = response
				}
				_ = json.NewEncoder(w).Encode(out)
			}))
			defer srv.Close()
			got, err := NewClient(srv.URL).IntrospectContext(context.Background(), "token", "limenora", "unchanged-proof", pub)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if tc.want == nil && got.AgentID != response.AgentID {
				t.Fatalf("context = %+v", got)
			}
		})
	}
}

func TestIntrospectContextTransportBounds(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"redirect", "oversized", "malformed", "credential error"} {
		t.Run(mode, func(t *testing.T) {
			redirected := false
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/introspect" {
					redirected = true
				}
				switch mode {
				case "redirect":
					http.Redirect(w, r, "/other", http.StatusTemporaryRedirect)
				case "oversized":
					_, _ = w.Write([]byte(strings.Repeat(" ", 64*1024+1)))
				case "malformed":
					_, _ = w.Write([]byte(`{"context":{}}`))
				case "credential error":
					w.WriteHeader(http.StatusUnauthorized)
					_, _ = w.Write([]byte("SECRET-PROOF"))
				}
			}))
			defer srv.Close()
			_, err := NewClient(srv.URL).IntrospectContext(context.Background(), "SECRET-TOKEN", "limenora", "SECRET-PROOF", pub)
			if err == nil || strings.Contains(err.Error(), "SECRET") || redirected {
				t.Fatalf("unsafe transport result: err=%v redirected=%v", err, redirected)
			}
		})
	}
	if _, err := NewClient("http://remote.example.test").IntrospectContext(context.Background(), "token", "limenora", "proof", pub); err == nil {
		t.Fatal("accepted remote plaintext context endpoint")
	}
}
