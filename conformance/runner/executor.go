package runner

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Executor drives a live daemon.
type Executor struct {
	BaseURL string
	Client  *http.Client
	// EnrollAudience mirrors the core enrollment audience.
	EnrollAudience string
	// TokenAudience mirrors the core token-proof audience.
	TokenAudience string
	// peer is the in-memory federated issuer started on first use. It serves a
	// loopback JWKS that the daemon fetches when introspecting peer tokens.
	peer *PeerIssuer
}

// peerIssuer lazily starts the in-process federated peer used by federation
// fixtures. Starting on demand keeps non-federation scenarios side-effect free.
func (e *Executor) peerIssuer() (*PeerIssuer, error) {
	if e.peer == nil {
		peer, err := newPeerIssuer()
		if err != nil {
			return nil, err
		}
		e.peer = peer
	}
	return e.peer, nil
}

// Result captures the verdict for one fixture.
type Result struct {
	FixtureID string
	Pass      bool
	Err       error
}

// NewExecutor creates an executor bound to a daemon URL.
func NewExecutor(baseURL string) *Executor {
	return &Executor{
		BaseURL:        strings.TrimSuffix(baseURL, "/"),
		Client:         &http.Client{Timeout: 15 * time.Second},
		EnrollAudience: "eidovela:enroll",
		TokenAudience:  "eidovela:token",
	}
}

// scenarioState carries one fixture's live state.
type scenarioState struct {
	ex           *Executor
	ctx          context.Context
	agentID      string
	regID        string
	challengeID  string
	nonce        string
	instanceID   string
	mainPub      ed25519.PublicKey
	mainPriv     ed25519.PrivateKey
	attackerPub  ed25519.PublicKey
	attackerPriv ed25519.PrivateKey
	issuedToken  string
}

// RunFixture executes a single fixture and returns its verdict. Each step
// asserts its own expected outcome (step.Expect); execStep returns nil only
// when the step met that expectation, so any error here marks the fixture as
// failed.
func (e *Executor) RunFixture(ctx context.Context, fixture Fixture) Result {
	s, err := e.begin(ctx, fixture)
	if err != nil {
		return Result{FixtureID: fixture.ID, Pass: false, Err: err}
	}
	for i, step := range fixture.Scenario.Steps {
		if err := s.execStep(step); err != nil {
			return Result{FixtureID: fixture.ID, Pass: false, Err: fmt.Errorf("step %d (%s): %w", i, step.Op, err)}
		}
	}
	return Result{FixtureID: fixture.ID, Pass: true, Err: nil}
}

func (e *Executor) begin(ctx context.Context, fixture Fixture) (*scenarioState, error) {
	mainPub, mainPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	attackerPub, attackerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	s := &scenarioState{
		ex: e, ctx: ctx,
		mainPub: mainPub, mainPriv: mainPriv,
		attackerPub: attackerPub, attackerPriv: attackerPriv,
	}
	// Register the agent.
	var agent struct {
		AgentID string `json:"agent_id"`
	}
	payload := map[string]any{
		"class": fixture.Scenario.AgentClass, "binding_type": fixture.Scenario.BindingType,
		"authority_root_ref": fixture.Scenario.AuthorityRootRef,
	}
	if err := s.post("/v1/agents", payload, &agent); err != nil {
		return nil, fmt.Errorf("register agent: %w", err)
	}
	s.agentID = agent.AgentID
	return s, nil
}

func (s *scenarioState) execStep(step Step) error {
	wantDeny := step.Expect == "deny"
	switch step.Op {
	case "register_workload":
		return s.outcome(wantDeny, s.registerWorkload(step))
	case "complete_enrollment":
		return s.outcome(wantDeny, s.completeEnrollment(step))
	case "activate":
		return s.outcome(wantDeny, s.post(fmt.Sprintf("/v1/agents/%s/activate", s.agentID), nil, &struct{}{}))
	case "suspend":
		return s.outcome(wantDeny, s.post(fmt.Sprintf("/v1/agents/%s/suspend", s.agentID), nil, &struct{}{}))
	case "revoke":
		return s.outcome(wantDeny, s.post(fmt.Sprintf("/v1/agents/%s/revoke", s.agentID), nil, &struct{}{}))
	case "issue_token":
		return s.outcome(wantDeny, s.issueToken(step))
	case "introspect":
		active, err := s.introspect(step)
		if err != nil {
			return err
		}
		if wantDeny {
			if active {
				return fmt.Errorf("introspect expected inactive but reported active")
			}
			return nil
		}
		if !active {
			return fmt.Errorf("introspect expected active but reported inactive")
		}
		return nil
	case "exchange":
		return s.outcome(wantDeny, s.exchange(step))
	case "register_federation_trust":
		return s.outcome(wantDeny, s.registerFederationTrust(step))
	case "disable_federation_trust":
		return s.outcome(wantDeny, s.disableFederationTrust(step))
	case "issue_peer_token":
		return s.outcome(wantDeny, s.issuePeerToken(step))
	default:
		return fmt.Errorf("unknown op %q", step.Op)
	}
}

// outcome reports nil when the step met its expected outcome: an operation that
// was expected to be denied must have produced an error, and an operation
// expected to succeed must not have.
func (s *scenarioState) outcome(wantDeny bool, err error) error {
	if wantDeny {
		if err == nil {
			return fmt.Errorf("expected deny but operation succeeded")
		}
		return nil
	}
	return err
}

func (s *scenarioState) registerWorkload(step Step) error {
	if step.Workload == nil {
		return fmt.Errorf("register_workload requires workload")
	}
	var workload struct {
		RegistrationID string `json:"registration_id"`
	}
	payload := map[string]any{
		"platform": step.Workload.Platform, "selector": step.Workload.Selector,
		"trust_domain": step.Workload.TrustDomain, "allowed_proof_methods": step.Workload.AllowedProofMethods,
	}
	if err := s.post("/v1/workload-registrations", payload, &workload); err != nil {
		return err
	}
	s.regID = workload.RegistrationID
	// Create the enrollment challenge.
	var challenge struct {
		ID      string `json:"enrollment_id"`
		AgentID string `json:"agent_id"`
		Nonce   string `json:"nonce"`
	}
	if err := s.post("/v1/enrollments", map[string]string{"agent_id": s.agentID, "workload_registration_id": s.regID}, &challenge); err != nil {
		return err
	}
	s.challengeID = challenge.ID
	s.nonce = challenge.Nonce
	return nil
}

func (s *scenarioState) completeEnrollment(step Step) error {
	if s.regID == "" || s.challengeID == "" {
		return fmt.Errorf("complete_enrollment requires register_workload first")
	}
	pub, priv := s.mainPub, s.mainPriv
	proof, err := s.enrollmentProof(s.challengeID, s.nonce, priv)
	if err != nil {
		return err
	}
	attributes := step.WorkloadAttributes
	if attributes == nil {
		attributes = map[string]string{}
	}
	body := map[string]any{
		"enrollment_id": s.challengeID, "proof_jwt": proof,
		"public_key": jwk(pub), "runtime": "praxovela", "workload_id": "wl_conformance",
		"workload_attributes": attributes,
	}
	attestation, err := s.buildAttestation(step.Attestation, pub, priv)
	if err != nil {
		return err
	}
	if attestation != nil {
		body["attestation"] = attestation
	}
	var instance struct {
		InstanceID string `json:"instance_id"`
	}
	if err := s.post("/v1/enrollments/complete", body, &instance); err != nil {
		return err
	}
	s.instanceID = instance.InstanceID
	return nil
}

func (s *scenarioState) issueToken(step Step) error {
	if s.instanceID == "" {
		return fmt.Errorf("issue_token requires completed enrollment")
	}
	audience := step.Audience
	if audience == "" {
		audience = "aegivela"
	}
	priv := s.mainPriv
	if step.PresentKey == "attacker" {
		priv = s.attackerPriv
	}
	proof, err := s.tokenProof(s.agentID, s.instanceID, priv)
	if err != nil {
		return err
	}
	var token struct {
		Token string `json:"token"`
	}
	body := map[string]any{
		"agent_id": s.agentID, "instance_id": s.instanceID, "audience": audience,
		"public_key": jwk(s.mainPub), "proof_jwt": proof,
	}
	if err := s.post("/oauth2/token", body, &token); err != nil {
		return err
	}
	s.issuedToken = token.Token
	return nil
}

func (s *scenarioState) introspect(step Step) (bool, error) {
	if s.issuedToken == "" {
		return false, fmt.Errorf("introspect requires an issued token")
	}
	audience := step.Audience
	if audience == "" {
		audience = "aegivela"
	}
	key := s.mainPub
	if step.PresentKey == "attacker" {
		key = s.attackerPub
	}
	var response struct {
		Active bool `json:"active"`
	}
	if err := s.post("/v1/introspect", map[string]any{"token": s.issuedToken, "audience": audience, "public_key": jwk(key)}, &response); err != nil {
		return false, err
	}
	return response.Active, nil
}

func (s *scenarioState) exchange(step Step) error {
	if s.issuedToken == "" {
		return fmt.Errorf("exchange requires an issued token")
	}
	parentAudience := step.Audience
	if parentAudience == "" {
		parentAudience = "aegivela"
	}
	requested := step.RequestedAudience
	if requested == "" {
		requested = parentAudience
	}
	var exchanged struct {
		Token string `json:"token"`
	}
	body := map[string]any{
		"subject_token": s.issuedToken, "parent_audience": parentAudience,
		"requested_audience": requested, "public_key": jwk(s.mainPub),
	}
	if err := s.post("/v1/token/exchange", body, &exchanged); err != nil {
		return err
	}
	s.issuedToken = exchanged.Token
	return nil
}

func (s *scenarioState) registerFederationTrust(step Step) error {
	if step.Federation == nil {
		return fmt.Errorf("register_federation_trust requires a federation config")
	}
	peer, err := s.ex.peerIssuer()
	if err != nil {
		return err
	}
	config := step.Federation
	if config.Issuer == "" {
		config.Issuer = "https://peer.example.test"
	}
	if config.Status == "" {
		config.Status = "active"
	}
	var trust struct {
		Status string `json:"status"`
	}
	body := map[string]any{
		"issuer": config.Issuer, "jwks_uri": peer.JWKSURL(),
		"claim_mappings": config.ClaimMappings, "allowed_audiences": config.AllowedAudiences,
		"status": config.Status,
	}
	return s.post("/v1/federation/trusts", body, &trust)
}

func (s *scenarioState) disableFederationTrust(step Step) error {
	issuer := step.FederationIssuer
	if issuer == "" {
		issuer = "https://peer.example.test"
	}
	return s.post("/v1/federation/trusts/disable", map[string]string{"issuer": issuer}, &struct{}{})
}

// issuePeerToken signs a token with the in-process peer's key and makes it the
// scenario's introspect subject. The token is bound to the scenario's main PoP
// key so the following introspect step can prove possession.
func (s *scenarioState) issuePeerToken(step Step) error {
	peer, err := s.ex.peerIssuer()
	if err != nil {
		return err
	}
	issuer := step.FederationIssuer
	if issuer == "" {
		issuer = "https://peer.example.test"
	}
	audience := step.Audience
	if audience == "" {
		audience = "aegivela"
	}
	agent := step.PeerAgent
	if agent == "" {
		agent = "agt_peer"
	}
	now := time.Now()
	exp := now.Add(time.Hour)
	if step.Expired {
		exp = now.Add(-time.Minute)
	}
	token, err := peer.Sign("peer-1", map[string]any{
		"iss": issuer, "sub": agent, "aud": audience,
		"iat": now.Add(-10 * time.Minute).Unix(), "exp": exp.Unix(),
		"jti": "peer_jti", "cnf": map[string]any{"jkt": thumbprint(s.mainPub)},
	})
	if err != nil {
		return err
	}
	s.issuedToken = token
	return nil
}

func (s *scenarioState) buildAttestation(att *Attest, pub ed25519.PublicKey, priv ed25519.PrivateKey) (map[string]any, error) {
	if att == nil {
		return nil, nil
	}
	switch att.Method {
	case "private_key_jwt":
		return nil, nil
	case "mtls":
		pemCert, err := selfSignedPEM(att.SubjectCN, att.DNSNames, true, time.Now())
		if err != nil {
			return nil, err
		}
		return map[string]any{"method": "mtls", "certificate_pem": pemCert}, nil
	case "spiffe_svid":
		pemCert, err := selfSignedPEM(att.SubjectCN, att.DNSNames, false, time.Now())
		if err != nil {
			return nil, err
		}
		// Rewrite with the SPIFFE URI SAN when provided.
		if att.SPIFFEID != "" {
			pemCert, err = selfSignedPEMWithURI(att.SPIFFEID, time.Now())
			if err != nil {
				return nil, err
			}
		}
		return map[string]any{"method": "spiffe_svid", "certificate_pem": pemCert}, nil
	case "k8s_projected_sa":
		token, err := s.k8sToken(att, priv)
		if err != nil {
			return nil, err
		}
		return map[string]any{"method": "k8s_projected_sa", "token": token}, nil
	default:
		return nil, fmt.Errorf("unsupported attestation method %q", att.Method)
	}
}

func (s *scenarioState) k8sToken(att *Attest, priv ed25519.PrivateKey) (string, error) {
	issuer := att.KubernetesIssuer
	if issuer == "" {
		issuer = "https://kubernetes.example.test"
	}
	subject := att.KubernetesSubject
	if subject == "" {
		subject = "system:serviceaccount:default:agent"
	}
	claims := map[string]any{
		"iss": issuer, "aud": "eidovela", "sub": subject,
		"exp": time.Now().Add(10 * time.Minute).Unix(),
	}
	return sign(priv, claims)
}

func (s *scenarioState) post(path string, payload any, target any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(s.ctx, http.MethodPost, s.ex.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := s.ex.Client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		var failure struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(res.Body).Decode(&failure)
		if failure.Error == "" {
			failure.Error = res.Status
		}
		return fmt.Errorf("%s", failure.Error)
	}
	if target != nil {
		return json.NewDecoder(res.Body).Decode(target)
	}
	return nil
}

func (s *scenarioState) enrollmentProof(challengeID, nonce string, priv ed25519.PrivateKey) (string, error) {
	claims := map[string]any{
		"iss": s.agentID, "sub": s.agentID, "aud": s.ex.EnrollAudience,
		"jti": challengeID, "nonce": nonce, "exp": time.Now().Add(time.Minute).Unix(),
	}
	return sign(priv, claims)
}

func (s *scenarioState) tokenProof(agentID, instanceID string, priv ed25519.PrivateKey) (string, error) {
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	claims := map[string]any{
		"iss": agentID, "sub": instanceID, "aud": s.ex.TokenAudience,
		"jti": base64.RawURLEncoding.EncodeToString(jti), "exp": time.Now().Add(time.Minute).Unix(),
	}
	return sign(priv, claims)
}

func jwk(pub ed25519.PublicKey) map[string]string {
	return map[string]string{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pub)}
}

func sign(priv ed25519.PrivateKey, claims map[string]any) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	input := b64(header) + "." + b64(payload)
	return input + "." + b64(ed25519.Sign(priv, []byte(input))), nil
}

func selfSignedPEM(cn string, dns []string, clientAuth bool, now time.Time) (string, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
	}
	if clientAuth {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	tmpl.DNSNames = append(tmpl.DNSNames, dns...)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), nil
}

func selfSignedPEMWithURI(spiffeID string, now time.Time) (string, error) {
	parsed, err := parseSPIFFE(spiffeID)
	if err != nil {
		return "", err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: parsed.Host},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		URIs:         []*url.URL{parsed},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), nil
}
