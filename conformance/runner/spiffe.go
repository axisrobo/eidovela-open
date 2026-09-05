package runner

import (
	"fmt"
	"net/url"
	"strings"
)

// parseSPIFFE validates that raw is a well-formed spiffe://<trust>/<path> URI
// and returns it as a *url.URL for use as a URI SAN.
func parseSPIFFE(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if parsed.Scheme != "spiffe" || parsed.Host == "" || parsed.User != nil || parsed.Port() != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("runner: malformed SPIFFE ID %q", raw)
	}
	if !strings.HasPrefix(parsed.Path, "/") || parsed.Path == "/" {
		return nil, fmt.Errorf("runner: SPIFFE ID %q must carry a non-empty path", raw)
	}
	return parsed, nil
}
