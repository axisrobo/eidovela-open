package runner

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// FakeRegistry is an in-process stand-in for the NOMIVELA Agent Registry. It
// serves the read endpoints the EIDOVELA NOMIVELA SDK calls, plus the instance
// commit the daemon performs on verified enrollment, so the conformance suite
// can drive a real consumer-mode daemon without a NOMIVELA deployment.
//
// It is a test double, not a registry authority: it implements only the subset
// of the contract EIDOVELA consumes and keeps no evidence or lifecycle audit.
type FakeRegistry struct {
	mu sync.Mutex

	namespace string

	agentRef          string
	agentClass        string
	agentState        string
	agentEpoch        int64
	sponsorRef        string
	agentID           string
	identityState     string
	identityEpoch     int64
	authorityRootRef  string
	authorityRootType string

	workloads     map[string]fakeWorkload
	workloadOrder []string
	instances     map[string]fakeInstance
	instanceOrder []string
	sequence      int

	listener net.Listener
	server   *http.Server
	baseURL  string
}

type fakeWorkload struct {
	id          string
	platform    string
	selector    map[string]string
	trustDomain string
	methods     []string
	status      string
	epoch       int64
}

type fakeInstance struct {
	id             string
	agentID        string
	registrationID string
	workloadID     string
	artifactDigest string
	attestationRef string
	leaseExpiresAt time.Time
	state          string
	generation     int64
}

// StartFakeRegistry starts a fake registry on a loopback port.
func StartFakeRegistry(namespace string) (*FakeRegistry, error) {
	if namespace == "" {
		namespace = "https://registry.example.test/ns/local"
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	r := &FakeRegistry{
		namespace: namespace,
		workloads: map[string]fakeWorkload{},
		instances: map[string]fakeInstance{},
		listener:  listener,
	}
	r.baseURL = "http://" + listener.Addr().String()
	r.server = &http.Server{Handler: r}
	go func() { _ = r.server.Serve(listener) }()
	return r, nil
}

// BaseURL is the NOMIVELA base URL the daemon should consume.
func (r *FakeRegistry) BaseURL() string { return r.baseURL }

// Namespace is the provisioned authority namespace.
func (r *FakeRegistry) Namespace() string { return r.namespace }

// Stop shuts the fake registry down.
func (r *FakeRegistry) Stop() {
	if r.server != nil {
		_ = r.server.Close()
	}
}

// SeedAgent models a NOMIVELA-registered Agent and its bound Agent Identity.
// Both lifecycle states are active, as a deployable Agent must be.
func (r *FakeRegistry) SeedAgent(class, bindingType, authorityRootRef string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sequence++
	r.agentRef = "agent_ref_" + strconv.Itoa(r.sequence)
	r.agentClass = class
	r.agentState = "active"
	r.agentEpoch = 1
	r.agentID = fmt.Sprintf("%08d-0000-0000-0000-000000000000", r.sequence)
	r.identityState = "active"
	r.identityEpoch = 1
	r.authorityRootRef = authorityRootRef
	r.authorityRootType = bindingType
	return r.agentID
}

// AddWorkload registers an approved workload and returns its registration ID.
func (r *FakeRegistry) AddWorkload(w Workload) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sequence++
	id := fmt.Sprintf("wr-%08d", r.sequence)
	status := "active"
	r.workloads[id] = fakeWorkload{
		id: id, platform: w.Platform, selector: w.Selector,
		trustDomain: w.TrustDomain, methods: w.AllowedProofMethods,
		status: status, epoch: 1,
	}
	r.workloadOrder = append(r.workloadOrder, id)
	return id
}

// SuspendAgent models a NOMIVELA Agent suspension that bumps the Agent epoch.
func (r *FakeRegistry) SuspendAgent() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.agentState = "suspended"
	r.agentEpoch++
}

// RevokeAgent models an Agent retirement plus identity revocation.
func (r *FakeRegistry) RevokeAgent() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.agentState = "retired"
	r.agentEpoch++
	r.identityState = "revoked"
	r.identityEpoch++
}

// SuspendIdentity models a NOMIVELA identity suspension.
func (r *FakeRegistry) SuspendIdentity() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.identityState = "suspended"
	r.identityEpoch++
}

// TerminateInstance models an instance terminal state.
func (r *FakeRegistry) TerminateInstance(instanceID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	inst, ok := r.instances[instanceID]
	if !ok {
		return
	}
	inst.state = "terminated"
	inst.generation++
	r.instances[instanceID] = inst
}

// LeaseInstance sets an instance lease. A terminated or expired instance cannot
// be leased again, matching registry semantics.
func (r *FakeRegistry) LeaseInstance(instanceID string, expiresAt time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	inst, ok := r.instances[instanceID]
	if !ok {
		return fmt.Errorf("fake registry: unknown instance %s", instanceID)
	}
	if inst.state == "terminated" || inst.state == "expired" {
		return fmt.Errorf("fake registry: instance %s is %s", instanceID, inst.state)
	}
	inst.leaseExpiresAt = expiresAt
	r.instances[instanceID] = inst
	return nil
}

// InstanceCount reports how many instances the registry has recorded.
func (r *FakeRegistry) InstanceCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.instances)
}

// ServeHTTP implements the NOMIVELA read + instance-commit subset.
func (r *FakeRegistry) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	path := strings.TrimSuffix(req.URL.Path, "/")
	switch {
	case req.Method == http.MethodGet && path == "/v1/namespaces":
		writeItems(w, []map[string]any{{
			"namespace": r.namespace, "authorityRootRef": r.authorityRootRef,
			"status": "active", "namespaceEpoch": 1,
		}})
	case req.Method == http.MethodGet && path == "/v1/agents":
		r.mu.Lock()
		items := []map[string]any{{
			"agentRef": r.agentRef, "name": r.agentRef, "purpose": "conformance",
			"sponsorRef": r.sponsorRef, "ownerRef": r.authorityRootRef, "riskClass": "low",
			"agentClass": r.agentClass, "state": r.agentState, "agentEpoch": r.agentEpoch,
		}}
		r.mu.Unlock()
		writeItems(w, items)
	case req.Method == http.MethodGet && path == "/v1/agent-identities":
		r.mu.Lock()
		items := []map[string]any{{
			"namespace": r.namespace, "agentId": r.agentID, "agentRef": r.agentRef,
			"state": r.identityState, "identityEpoch": r.identityEpoch,
			"authorityRootRef": r.authorityRootRef, "authorityRootType": r.authorityRootType,
		}}
		r.mu.Unlock()
		writeItems(w, items)
	case req.Method == http.MethodGet && path == "/v1/workload-registrations":
		r.mu.Lock()
		items := make([]map[string]any, 0, len(r.workloadOrder))
		for _, id := range r.workloadOrder {
			w := r.workloads[id]
			items = append(items, map[string]any{
				"workloadRegistrationId": w.id, "namespace": r.namespace, "platform": w.platform,
				"selector": w.selector, "trustDomain": w.trustDomain,
				"allowedProofMethods": w.methods, "status": w.status, "workloadEpoch": w.epoch,
			})
		}
		r.mu.Unlock()
		writeItems(w, items)
	case req.Method == http.MethodGet && path == "/v1/registry-context":
		r.registryContext(w, req)
	case req.Method == http.MethodGet && strings.HasPrefix(path, "/v1/agent-identities/") && strings.HasSuffix(path, "/instances"):
		agentID := strings.TrimSuffix(strings.TrimPrefix(path, "/v1/agent-identities/"), "/instances")
		r.mu.Lock()
		items := make([]map[string]any, 0, len(r.instanceOrder))
		for _, id := range r.instanceOrder {
			inst := r.instances[id]
			if inst.agentID != agentID {
				continue
			}
			items = append(items, r.instanceJSON(inst))
		}
		r.mu.Unlock()
		writeItems(w, items)
	case req.Method == http.MethodPost && strings.HasPrefix(path, "/v1/agent-identities/") && strings.HasSuffix(path, "/instances"):
		agentID := strings.TrimSuffix(strings.TrimPrefix(path, "/v1/agent-identities/"), "/instances")
		r.commitInstance(w, req, agentID)
	default:
		writeJSONBody(w, http.StatusNotFound, map[string]any{"error": map[string]any{"code": "not_found", "message": "fake registry: " + path}})
	}
}

// registryContext serves the atomic Registry Context EIDOVELA uses for issuance
// and online verification: the Agent, Agent Identity, and the selected
// Workload Registration and Agent Instance from one consistent view.
func (r *FakeRegistry) registryContext(w http.ResponseWriter, req *http.Request) {
	query := req.URL.Query()
	agentID := query.Get("agentId")
	instanceID := query.Get("instanceId")
	workloadRegistrationID := query.Get("workloadRegistrationId")

	r.mu.Lock()
	defer r.mu.Unlock()
	if agentID != r.agentID {
		writeJSONBody(w, http.StatusNotFound, map[string]any{"error": map[string]any{"code": "not_found", "message": "unknown agent"}})
		return
	}
	body := map[string]any{
		"namespace": r.namespaceJSON(),
		"agent":     r.agentJSON(),
		"identity":  r.identityJSON(),
	}
	if instanceID != "" {
		inst, ok := r.instances[instanceID]
		if !ok {
			writeJSONBody(w, http.StatusNotFound, map[string]any{"error": map[string]any{"code": "not_found", "message": "unknown instance"}})
			return
		}
		body["instance"] = r.instanceJSON(inst)
		workloadRegistrationID = inst.registrationID
	}
	if workloadRegistrationID != "" {
		workload, ok := r.workloads[workloadRegistrationID]
		if !ok {
			writeJSONBody(w, http.StatusNotFound, map[string]any{"error": map[string]any{"code": "not_found", "message": "unknown workload registration"}})
			return
		}
		body["workloadRegistration"] = map[string]any{
			"workloadRegistrationId": workload.id, "namespace": r.namespace, "platform": workload.platform,
			"selector": workload.selector, "trustDomain": workload.trustDomain,
			"allowedProofMethods": workload.methods, "status": workload.status, "workloadEpoch": workload.epoch,
		}
	}
	writeJSONBody(w, http.StatusOK, body)
}

func (r *FakeRegistry) namespaceJSON() map[string]any {
	return map[string]any{
		"namespace": r.namespace, "authorityRootRef": r.authorityRootRef,
		"status": "active", "namespaceEpoch": 1,
	}
}

func (r *FakeRegistry) agentJSON() map[string]any {
	return map[string]any{
		"agentRef": r.agentRef, "name": r.agentRef, "purpose": "conformance",
		"sponsorRef": r.sponsorRef, "ownerRef": r.authorityRootRef, "riskClass": "low",
		"agentClass": r.agentClass, "state": r.agentState, "agentEpoch": r.agentEpoch,
	}
}

func (r *FakeRegistry) identityJSON() map[string]any {
	return map[string]any{
		"namespace": r.namespace, "agentId": r.agentID, "agentRef": r.agentRef,
		"state": r.identityState, "identityEpoch": r.identityEpoch,
		"authorityRootRef": r.authorityRootRef, "authorityRootType": r.authorityRootType,
	}
}

func (r *FakeRegistry) commitInstance(w http.ResponseWriter, req *http.Request, agentID string) {
	var body struct {
		Namespace              string `json:"namespace"`
		WorkloadRegistrationID string `json:"workloadRegistrationId"`
		WorkloadID             string `json:"workloadId"`
		ArtifactDigest         string `json:"artifactDigest"`
		AttestationRef         string `json:"attestationRef"`
		LeaseExpiresAt         string `json:"leaseExpiresAt"`
	}
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		writeJSONBody(w, http.StatusBadRequest, map[string]any{"error": map[string]any{"code": "invalid_request", "message": err.Error()}})
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if agentID != r.agentID {
		writeJSONBody(w, http.StatusNotFound, map[string]any{"error": map[string]any{"code": "not_found", "message": "unknown agent"}})
		return
	}
	if _, ok := r.workloads[body.WorkloadRegistrationID]; !ok {
		writeJSONBody(w, http.StatusNotFound, map[string]any{"error": map[string]any{"code": "not_found", "message": "unknown workload registration"}})
		return
	}
	r.sequence++
	lease, _ := time.Parse(time.RFC3339, body.LeaseExpiresAt)
	inst := fakeInstance{
		id: fmt.Sprintf("inst-%08d", r.sequence), agentID: agentID,
		registrationID: body.WorkloadRegistrationID, workloadID: body.WorkloadID,
		artifactDigest: body.ArtifactDigest, attestationRef: body.AttestationRef,
		leaseExpiresAt: lease, state: "active", generation: 1,
	}
	r.instances[inst.id] = inst
	r.instanceOrder = append(r.instanceOrder, inst.id)
	writeJSONBody(w, http.StatusCreated, r.instanceJSON(inst))
}

func (r *FakeRegistry) instanceJSON(inst fakeInstance) map[string]any {
	out := map[string]any{
		"instanceId": inst.id, "namespace": r.namespace, "agentId": inst.agentID,
		"workloadRegistrationId": inst.registrationID, "workloadId": inst.workloadID,
		"artifactDigest": inst.artifactDigest, "attestationRef": inst.attestationRef,
		"state": inst.state, "generation": inst.generation,
	}
	if !inst.leaseExpiresAt.IsZero() {
		out["leaseExpiresAt"] = inst.leaseExpiresAt.UTC().Format(time.RFC3339)
	}
	return out
}

func writeItems(w http.ResponseWriter, items []map[string]any) {
	writeJSONBody(w, http.StatusOK, map[string]any{"items": items})
}

func writeJSONBody(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
