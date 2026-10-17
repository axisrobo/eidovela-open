package presentation_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"flag"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/axisvela/eidovela-open/conformance/runner"
	"github.com/axisvela/eidovela-open/sdk/go/eidovela"
)

//go:embed fixtures.json
var fixtureJSON []byte

var daemonPath = flag.String("presentation-daemon", os.Getenv("EIDOVELA_PRESENTATION_DAEMON"), "fresh core daemon for FP-1 provider fixtures")

func TestPresentationProviderAgainstDaemon(t *testing.T) {
	binary := *daemonPath
	if binary == "" {
		t.Skip("set EIDOVELA_PRESENTATION_DAEMON to a freshly built core daemon")
	}
	baseURL, registry, stop, err := runner.StartDaemon(binary)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	var fixtures []struct {
		ID     string `json:"id"`
		Mode   string `json:"mode"`
		Status int    `json:"status"`
		Active bool   `json:"active"`
	}
	if err := json.Unmarshal(fixtureJSON, &fixtures); err != nil {
		t.Fatal(err)
	}
	for _, fixture := range fixtures {
		t.Run(fixture.ID, func(t *testing.T) {
			pub, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			agent := registry.SeedAgent("organizational", "organization", "org:fixture")
			registry.SetIdentityAttributes("interactive", "user:fixture")
			workload := registry.AddWorkload(runner.Workload{
				Platform: "kubernetes", Selector: map[string]string{"namespace": "prod"},
				TrustDomain: "example.test", AllowedProofMethods: []string{"private_key_jwt"},
			})
			var challenge struct {
				ID    string `json:"enrollmentId"`
				Nonce string `json:"nonce"`
			}
			post(t, baseURL, "/v1/enrollments", map[string]any{"agentId": agent, "workloadRegistrationId": workload}, &challenge, http.StatusOK)
			var instance struct {
				ID string `json:"instanceId"`
			}
			post(t, baseURL, "/v1/enrollments/complete", map[string]any{
				"enrollmentId": challenge.ID,
				"proofJwt":     assertion(t, key, map[string]any{"iss": agent, "sub": agent, "aud": "eidovela:enroll", "jti": challenge.ID, "nonce": challenge.Nonce, "exp": time.Now().Add(time.Minute).Unix()}),
				"publicKey":    eidovela.JWKFromPublic(pub, ""), "workloadId": "workload-fixture", "artifactDigest": "sha256:fixture",
				"workloadAttributes": map[string]string{"namespace": "prod"},
			}, &instance, http.StatusOK)
			jti := make([]byte, 16)
			if _, err := rand.Read(jti); err != nil {
				t.Fatal(err)
			}
			var issued struct {
				Token string `json:"token"`
			}
			post(t, baseURL, "/oauth2/token", map[string]any{
				"agentId": agent, "instanceId": instance.ID, "audience": "limenora", "publicKey": eidovela.JWKFromPublic(pub, ""),
				"proofJwt": assertion(t, key, map[string]any{"iss": agent, "sub": instance.ID, "aud": "eidovela:token", "jti": base64.RawURLEncoding.EncodeToString(jti), "exp": time.Now().Add(time.Minute).Unix()}),
			}, &issued, http.StatusOK)
			if issued.Token == "" {
				t.Fatal("missing issued token")
			}
			method, target, hashToken, now := "POST", "https://eidovela.example.test/v1/introspect", issued.Token, time.Now()
			proofKey := key
			switch fixture.Mode {
			case "resource-target":
				method, target = "GET", "https://resource.example.test/items/1"
			case "token-hash":
				hashToken = "different-token"
			case "stale":
				now = now.Add(-2 * time.Minute)
			case "wrong-key":
				_, proofKey, err = ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
			case "missing-type":
				registry.SetIdentityAttributes("", "user:fixture")
			case "missing-subject":
				registry.SetIdentityAttributes("interactive", "")
			case "stale-epoch":
				registry.SuspendIdentity()
			}
			proof, err := eidovela.SignDPoP(proofKey, method, target, hashToken, now)
			if err != nil {
				t.Fatal(err)
			}
			payload := map[string]any{"token": issued.Token, "audience": "limenora", "includeContext": true, "dpopProof": proof}
			if fixture.Mode == "key-only" {
				delete(payload, "dpopProof")
				payload["publicKey"] = eidovela.JWKFromPublic(pub, "")
			}
			if fixture.Mode == "replay" {
				got, err := eidovela.NewClient(baseURL).IntrospectContext(context.Background(), issued.Token, "limenora", proof, pub)
				if err != nil || got.AgentID != agent {
					t.Fatalf("first introspection failed: %v", err)
				}
			}
			var result struct {
				Active  bool                   `json:"active"`
				Context *eidovela.TokenContext `json:"context"`
			}
			post(t, baseURL, "/v1/introspect", payload, &result, fixture.Status)
			if result.Active != fixture.Active || (!fixture.Active && result.Context != nil) {
				t.Fatalf("unexpected result: %+v", result)
			}
			if fixture.Active {
				if result.Context == nil || result.Context.AgentID != agent || result.Context.Namespace != registry.Namespace() || result.Context.SubjectRef != "user:fixture" || result.Context.RegistryClass != "organizational" {
					t.Fatalf("incomplete context: %+v", result.Context)
				}
				fresh, err := eidovela.SignDPoP(key, method, target, issued.Token, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				if _, err := eidovela.NewClient(baseURL).IntrospectContext(context.Background(), issued.Token, "limenora", fresh, pub); err != nil {
					t.Fatalf("SDK/provider interop: %v", err)
				}
			}
		})
	}
}

func post(t *testing.T, base, path string, payload, output any, want int) {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	res, err := client.Post(base+path, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != want {
		t.Fatalf("%s status=%d, want %d", path, res.StatusCode, want)
	}
	if path == "/v1/introspect" && res.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("missing no-store")
	}
	if err := json.NewDecoder(res.Body).Decode(output); err != nil {
		t.Fatal(err)
	}
}

func assertion(t *testing.T, key ed25519.PrivateKey, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{"typ": "JWT", "alg": "EdDSA"})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	return strings.Join([]string{input, base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(input)))}, ".")
}
