package runner

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// defaultDaemonNames maps runtime.GOOS to the committed/built daemon binary
// name expected under the fixtures directory's sibling bin/ folder.
func daemonBinaryName() string {
	if runtime.GOOS == "windows" {
		return "eidovelad.exe"
	}
	return "eidovelad"
}

// FindDaemonBinary returns the path of a platform-appropriate eidovelad under
// the repository's conformance/bin directory. The first candidate to exist is
// returned; if none exists an error is returned (callers may build it).
func FindDaemonBinary(fixturesDir string) (string, error) {
	// Layout: <repo>/conformance/fixtures and <repo>/conformance/bin.
	binDir := filepath.Join(filepath.Dir(fixturesDir), "bin")
	name := daemonBinaryName()
	for _, candidate := range []string{
		filepath.Join(binDir, name),
		filepath.Join(filepath.Dir(fixturesDir), "..", "bin", name),
	} {
		if _, err := os.Stat(candidate); err == nil {
			abs, err := filepath.Abs(candidate)
			if err != nil {
				return "", err
			}
			return abs, nil
		}
	}
	return "", fmt.Errorf("runner: no %s daemon under %s; build it first", name, binDir)
}

// StartDaemon launches a daemon binary in registry-consumer mode on a free
// loopback port, backed by an in-process fake NOMIVELA registry, and returns a
// stop func, the daemon base URL and the fake registry. It waits until /healthz
// responds.
//
// Registry caching is disabled so a fixture that changes registry state (for
// example suspending an Agent) is observed immediately by the next request.
func StartDaemon(binaryPath string) (baseURL string, registry *FakeRegistry, stop func(), err error) {
	if binaryPath == "" {
		binaryPath, err = FindDaemonBinary("fixtures")
		if err != nil {
			return "", nil, nil, err
		}
	}
	port := freePort()
	if port == 0 {
		return "", nil, nil, errors.New("runner: no free port available")
	}
	registry, err = StartFakeRegistry("")
	if err != nil {
		return "", nil, nil, err
	}
	baseURL = fmt.Sprintf("http://127.0.0.1:%d", port)
	cmd := exec.Command(binaryPath)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("EIDOVELA_LISTEN_ADDR=127.0.0.1:%d", port),
		"EIDOVELA_ISSUER=https://eidovela.example.test",
		"EIDOVELA_NOMIVELA_URL="+registry.BaseURL(),
		"EIDOVELA_NOMIVELA_NAMESPACE="+registry.Namespace(),
		"EIDOVELA_NOMIVELA_CACHE_TTL=0s",
	)
	if err := cmd.Start(); err != nil {
		registry.Stop()
		return "", nil, nil, err
	}
	stop = func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
		registry.Stop()
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if healthy(baseURL) {
			return baseURL, registry, stop, nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	stop()
	return "", nil, nil, fmt.Errorf("runner: daemon did not become healthy at %s", baseURL)
}

func healthy(baseURL string) bool {
	client := &http.Client{Timeout: time.Second}
	resp, err := client.Get(strings.TrimSuffix(baseURL, "/") + "/healthz")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

// freePort asks the OS for an ephemeral port and returns it (race-prone but
// sufficient for tests); 0 on failure.
func freePort() int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}
