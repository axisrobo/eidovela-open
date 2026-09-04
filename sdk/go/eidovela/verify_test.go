package eidovela

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestThumbprintMatchesRFC7638CanonicalForm(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	canonical := `{"crv":"Ed25519","kty":"OKP","x":"` + base64.RawURLEncoding.EncodeToString(pub) + `"}`
	sum := sha256.Sum256([]byte(canonical))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if got := Thumbprint(pub); got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestJWKFromPublic(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	jwk := JWKFromPublic(pub, "kid-1")
	if jwk.Kty != "OKP" || jwk.Crv != "Ed25519" || jwk.Kid != "kid-1" {
		t.Fatalf("bad JWK: %+v", jwk)
	}
}
