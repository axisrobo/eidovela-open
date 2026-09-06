package eidovela

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIntrospectSendsAudience(t *testing.T) {
	var received map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/introspect" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&received)
		_ = json.NewEncoder(w).Encode(map[string]bool{"active": true})
	}))
	defer server.Close()
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	client := NewClient(server.URL)
	active, err := client.Introspect(context.Background(), "some-token", "eidovela:console", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if !active {
		t.Fatal("expected active response")
	}
	if received["audience"] != "eidovela:console" || received["token"] != "some-token" {
		t.Fatalf("introspect request missing audience/token: %v", received)
	}
}

func TestFederationTrustAdmin(t *testing.T) {
	saved := FederationTrust{
		Issuer: "https://peer.example.test", JWKSURI: "https://peer.example.test/jwks.json",
		AllowedAudiences: []string{"eidovela:console"}, ClaimMappings: map[string]string{"agent_id": "sub"},
		Status: "active", TenantID: "local",
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/federation/trusts":
			_ = json.NewEncoder(w).Encode(saved)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/federation/trusts/enable":
			saved.Status = "active"
			_ = json.NewEncoder(w).Encode(saved)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/federation/trusts/disable":
			saved.Status = "disabled"
			_ = json.NewEncoder(w).Encode(saved)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/federation/trusts" && r.URL.Query().Get("issuer") != "":
			_ = json.NewEncoder(w).Encode(saved)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/federation/trusts":
			_ = json.NewEncoder(w).Encode(federationTrustList{Trusts: []FederationTrust{saved}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := NewClient(server.URL)
	ctx := context.Background()

	created, err := client.CreateFederationTrust(ctx, saved)
	if err != nil || created.Issuer != saved.Issuer {
		t.Fatalf("create: %+v, %v", created, err)
	}
	listed, err := client.ListFederationTrusts(ctx)
	if err != nil || len(listed) != 1 || listed[0].Issuer != saved.Issuer {
		t.Fatalf("list: %+v, %v", listed, err)
	}
	single, err := client.GetFederationTrust(ctx, saved.Issuer)
	if err != nil || single.Status != "active" {
		t.Fatalf("get: %+v, %v", single, err)
	}
	disabled, err := client.DisableFederationTrust(ctx, saved.Issuer)
	if err != nil || disabled.Status != "disabled" {
		t.Fatalf("disable: %+v, %v", disabled, err)
	}
	enabled, err := client.EnableFederationTrust(ctx, saved.Issuer)
	if err != nil || enabled.Status != "active" {
		t.Fatalf("enable: %+v, %v", enabled, err)
	}
	if !strings.Contains(single.Issuer, "peer.example.test") {
		t.Fatal("unexpected issuer encoding")
	}
}
