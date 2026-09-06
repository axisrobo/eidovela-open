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
	"time"
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

func TestOpsReadMethodsQueryAndRoundtrip(t *testing.T) {
	var rawQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/agents":
			rawQuery = r.URL.RawQuery
			_ = json.NewEncoder(w).Encode(map[string]any{"agents": []AgentSummary{{AgentID: "agt_1", AgentClass: "service", LifecycleState: "active"}}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/ops/outbox":
			_ = json.NewEncoder(w).Encode(OutboxStatus{Pending: 3, Published: 1})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/federation/trusts/status":
			_ = json.NewEncoder(w).Encode(map[string]any{"trusts": []FederationTrustStatus{{Issuer: "https://peer.example.test", Status: "active", Success: 1}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := NewClient(server.URL)
	ctx := context.Background()

	agents, err := client.ListAgents(ctx, "", 0, 0)
	if err != nil || len(agents) != 1 {
		t.Fatalf("list agents: %v", err)
	}
	if rawQuery != "" {
		t.Fatalf("empty filter must produce no query string, got %q", rawQuery)
	}
	outbox, err := client.OutboxStatus(ctx)
	if err != nil || outbox.Pending != 3 || outbox.Published != 1 {
		t.Fatalf("outbox: %+v, %v", outbox, err)
	}
	statuses, err := client.FederationTrustStatuses(ctx)
	if err != nil || len(statuses) != 1 || statuses[0].Success != 1 {
		t.Fatalf("federation statuses: %+v, %v", statuses, err)
	}
}

func TestAgentDetailAndEvidenceSince(t *testing.T) {
	var sinceQuery, detailPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/agents/agt_1":
			detailPath = r.URL.Path
			_ = json.NewEncoder(w).Encode(AgentSummary{AgentID: "agt_1", AgentClass: "service", LifecycleState: "active"})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/evidence":
			sinceQuery = r.URL.Query().Get("since")
			_ = json.NewEncoder(w).Encode(map[string]any{"evidence": []EvidenceRecord{{Type: "identity.token.issued"}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := NewClient(server.URL)
	ctx := context.Background()
	agent, err := client.AgentDetail(ctx, "agt_1")
	if err != nil || agent.AgentID != "agt_1" {
		t.Fatalf("agent detail: %+v, %v", agent, err)
	}
	if detailPath != "/v1/agents/agt_1" {
		t.Fatalf("unexpected detail path %q", detailPath)
	}
	since := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	events, err := client.ListEvidenceSince(ctx, "", &since, 0, 0)
	if err != nil || len(events) != 1 {
		t.Fatalf("evidence since: %+v, %v", events, err)
	}
	if sinceQuery != "2026-09-06T12:00:00Z" {
		t.Fatalf("since must be UTC RFC3339, got %q", sinceQuery)
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
