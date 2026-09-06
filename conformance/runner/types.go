// Package runner executes EIDOVELA conformance fixtures against a live
// eidovelad over HTTP. Each fixture is an ordered scenario of steps; the
// runner generates real PoP keys and, for spiffe/mtls enrollments, self-signed
// leaf certificates or, for kubernetes, a projected-token-shaped JWT that the
// daemon's attestation layer checks. Fixtures assert allow/deny per step.
package runner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Fixture mirrors fixture.schema.json.
type Fixture struct {
	ID          string   `json:"id"`
	Description string   `json:"description,omitempty"`
	ThreatRef   string   `json:"threat_ref"`
	Expectation string   `json:"expectation"` // allow | deny
	DenyReason  string   `json:"deny_reason,omitempty"`
	Scenario    Scenario `json:"scenario"`
}

// Scenario is the ordered per-fixture script.
type Scenario struct {
	AgentClass       string `json:"agent_class"`
	BindingType      string `json:"binding_type"`
	AuthorityRootRef string `json:"authority_root_ref"`
	Steps            []Step `json:"steps"`
}

// Step is one HTTP operation the runner performs.
type Step struct {
	Op                   string            `json:"op"`
	Workload             *Workload         `json:"workload,omitempty"`
	WorkloadAttributes   map[string]string `json:"workload_attributes,omitempty"`
	Attestation          *Attest           `json:"attestation,omitempty"`
	Audience             string            `json:"audience,omitempty"`
	RequestedAudience    string            `json:"requested_audience,omitempty"`
	PresentKey           string            `json:"present_key,omitempty"` // main | attacker
	Federation           *FederationSpec   `json:"federation,omitempty"`
	FederationIssuer     string            `json:"federation_issuer,omitempty"`
	PeerAgent            string            `json:"peer_agent,omitempty"`
	Expired              bool              `json:"expired,omitempty"`
	Reason               string            `json:"reason,omitempty"`
	BlueprintVersion     string            `json:"blueprint_version,omitempty"`
	BlueprintPublisher   string            `json:"blueprint_publisher,omitempty"`
	BlueprintClass       string            `json:"blueprint_class,omitempty"`
	ExpectBlueprintStatus string           `json:"expect_blueprint_status,omitempty"`
	Expect               string            `json:"expect,omitempty"` // ok (default) | deny
	DenyReason           string            `json:"deny_reason,omitempty"`
	Extra                interface{}       `json:"-"`
}

// FederationSpec configures a peer trust anchor on the daemon. JWKSURI is
// injected by the runner from its local peer issuer; a fixture-supplied value is
// ignored so every scenario exercises a real, reachable JWKS.
type FederationSpec struct {
	Issuer           string            `json:"issuer,omitempty"`
	JWKSURI          string            `json:"jwks_uri,omitempty"`
	AllowedAudiences []string          `json:"allowed_audiences"`
	ClaimMappings    map[string]string `json:"claim_mappings"`
	Status           string            `json:"status,omitempty"`
}

// Workload describes a workload registration to create on the daemon.
type Workload struct {
	Platform            string            `json:"platform"`
	Selector            map[string]string `json:"selector"`
	TrustDomain         string            `json:"trust_domain"`
	AllowedProofMethods []string          `json:"allowed_proof_methods"`
}

// Attest describes evidence the runner must synthesize.
type Attest struct {
	Method            string   `json:"method"` // private_key_jwt | spiffe_svid | k8s_projected_sa | mtls
	SPIFFEID          string   `json:"spiffe_id,omitempty"`
	SubjectCN         string   `json:"subject_cn,omitempty"`
	DNSNames          []string `json:"dns_names,omitempty"`
	KubernetesIssuer  string   `json:"kubernetes_issuer,omitempty"`
	KubernetesSubject string   `json:"kubernetes_subject,omitempty"`
}

// LoadFixtures reads every *.json fixture under dir (schema file excluded).
func LoadFixtures(dir string) ([]Fixture, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var fixtures []Fixture
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		if entry.Name() == "fixture.schema.json" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		var fixture Fixture
		if err := json.Unmarshal(raw, &fixture); err != nil {
			return nil, fmt.Errorf("%s: %w", entry.Name(), err)
		}
		fixtures = append(fixtures, fixture)
	}
	sort.Slice(fixtures, func(a, b int) bool { return fixtures[a].ID < fixtures[b].ID })
	return fixtures, nil
}
