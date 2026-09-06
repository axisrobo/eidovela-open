package runner

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
)

// PeerIssuer is a minimal in-memory EIDOVELA-compatible peer: it serves a JWKS
// for its signing keys over loopback http and signs federated tokens. The
// conformance daemon verifies those tokens by fetching this JWKS during
// introspection, exactly like a real peer deployment would.
type PeerIssuer struct {
	server *httptest.Server
	mu     sync.RWMutex
	keys   map[string]ed25519.PrivateKey
}

func newPeerIssuer() (*PeerIssuer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	peer := &PeerIssuer{keys: map[string]ed25519.PrivateKey{"peer-1": priv}}
	peer.server = httptest.NewServer(http.HandlerFunc(peer.serveJWKS))
	return peer, nil
}

func (p *PeerIssuer) Close() {
	if p.server != nil {
		p.server.Close()
	}
}

func (p *PeerIssuer) JWKSURL() string { return p.server.URL + "/jwks.json" }

func (p *PeerIssuer) serveJWKS(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/jwks.json" {
		http.NotFound(w, r)
		return
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	var keys []map[string]any
	for kid, priv := range p.keys {
		keys = append(keys, map[string]any{
			"kty": "OKP", "crv": "Ed25519", "x": b64(priv.Public().(ed25519.PublicKey)), "kid": kid, "alg": "EdDSA", "use": "sig",
		})
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
}

// Sign issues an EdDSA token under the peer key for kid. Only the public key is
// ever exposed on the wire; the private key never leaves the process.
func (p *PeerIssuer) Sign(kid string, claims map[string]any) (string, error) {
	p.mu.RLock()
	priv, ok := p.keys[kid]
	p.mu.RUnlock()
	if !ok {
		return "", fmt.Errorf("runner: unknown peer key %q", kid)
	}
	return signWithKid(priv, kid, claims)
}

func signWithKid(priv ed25519.PrivateKey, kid string, claims map[string]any) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": kid})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := b64(header) + "." + b64(payload)
	return input + "." + b64(ed25519.Sign(priv, []byte(input))), nil
}

func thumbprint(pub ed25519.PublicKey) string {
	canonical := fmt.Sprintf(`{"crv":"Ed25519","kty":"OKP","x":"%s"}`, b64(pub))
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
