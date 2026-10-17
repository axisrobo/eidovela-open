package v3

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// captureServer records the last request body and path, and returns a caller
// supplied JSON body.
func captureServer(t *testing.T, body string, got *map[string]any, path *string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*path = r.URL.Path
		if r.ContentLength != 0 {
			if err := json.NewDecoder(r.Body).Decode(got); err != nil {
				t.Errorf("decode request: %v", err)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if body != "" {
			_, _ = w.Write([]byte(body))
		}
	}))
}

func TestClientSendsCamelCaseEnrollmentAndToken(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var envelope map[string]any
	var path string
	srv := captureServer(t, `{"enrollmentId":"e1","agentId":"a1","nonce":"n1"}`, &envelope, &path)
	defer srv.Close()
	if _, err := NewClient(srv.URL).CreateChallenge(context.Background(), "a1", "w1"); err != nil {
		t.Fatal(err)
	}
	if path != "/v1/enrollments" || envelope["agentId"] != "a1" || envelope["workloadRegistrationId"] != "w1" {
		t.Fatalf("challenge request = %s %+v", path, envelope)
	}

	srv2 := captureServer(t, `{"token":"t","expiresAt":"2030-01-01T00:00:00Z"}`, &envelope, &path)
	defer srv2.Close()
	if _, err := NewClient(srv2.URL).Token(context.Background(), "a1", "i1", "aud", priv); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"agentId", "instanceId", "audience", "publicKey", "proofJwt"} {
		if _, ok := envelope[key]; !ok {
			t.Fatalf("token request missing %q: %+v", key, envelope)
		}
	}
	if _, ok := envelope["agent_id"]; ok {
		t.Fatalf("token request leaked snake_case: %+v", envelope)
	}
}

func TestClientSendsCamelCaseExchangeAndFederation(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var envelope map[string]any
	var path string
	srv := captureServer(t, `{"token":"t","expiresAt":"2030-01-01T00:00:00Z"}`, &envelope, &path)
	defer srv.Close()
	if _, err := NewClient(srv.URL).Exchange(context.Background(), "subj", "pa", "ra", priv); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"subjectToken", "parentAudience", "requestedAudience", "publicKey"} {
		if _, ok := envelope[key]; !ok {
			t.Fatalf("exchange request missing %q: %+v", key, envelope)
		}
	}

	srv2 := captureServer(t, `{"issuer":"https://peer.example.test","status":"active"}`, &envelope, &path)
	defer srv2.Close()
	trust := FederationTrust{Issuer: "https://peer.example.test", JWKSURI: "https://peer.example.test/jwks.json",
		AllowedAudiences: []string{"aegivela"}, ClaimMappings: map[string]string{"agentId": "sub"}, Status: "active"}
	if _, err := NewClient(srv2.URL).CreateFederationTrust(context.Background(), trust); err != nil {
		t.Fatal(err)
	}
	if _, ok := envelope["claimMappings"]; !ok {
		t.Fatalf("trust request missing camelCase claimMappings: %+v", envelope)
	}
	if _, ok := envelope["claim_mappings"]; ok {
		t.Fatalf("trust request leaked snake_case: %+v", envelope)
	}
}

func TestClientReadsRegistryAndOpsSurfaces(t *testing.T) {
	var path string
	var got map[string]any
	srv := captureServer(t, `{"namespace":"ns","agentId":"a1","agentClass":"service","agentState":"active","identityState":"active"}`, &got, &path)
	defer srv.Close()
	client := NewClient(srv.URL)
	if _, err := client.GetRegistryAgent(context.Background(), "a1"); err != nil {
		t.Fatal(err)
	}
	if path != "/v1/registry/agents/a1" {
		t.Fatalf("get registry agent path = %s", path)
	}

	srv2 := captureServer(t, `{"active_kid":"k2","kids":["k1","k2"],"overlap":true}`, &got, &path)
	defer srv2.Close()
	client2 := NewClient(srv2.URL)
	status, err := client2.KeyStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if path != "/v1/ops/keys" || status.ActiveKID != "k2" || !status.Overlap {
		t.Fatalf("key status = %+v path=%s", status, path)
	}

	srv3 := captureServer(t, `{"active_kid":"k3","kids":["k2","k3"],"overlap":true}`, &got, &path)
	defer srv3.Close()
	if _, err := NewClient(srv3.URL).RotateSigningKey(context.Background()); err != nil {
		t.Fatal(err)
	}
	if path != "/v1/ops/keys/rotate" {
		t.Fatalf("rotate path = %s", path)
	}
}
