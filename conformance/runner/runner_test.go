package runner_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/axisrobo/eidovela-open/conformance/runner"
)

// TestFixturesAgainstDaemon runs the executable conformance fixtures against a
// live daemon. When EIDOVELA_CONFORMANCE_URL is set it targets that daemon;
// otherwise it starts the platform daemon committed under conformance/bin (or
// built by the local CI script) automatically.
func TestFixturesAgainstDaemon(t *testing.T) {
	dir := os.Getenv("EIDOVELA_CONFORMANCE_FIXTURES")
	if dir == "" {
		cwd, err := os.Getwd()
		if err != nil {
			t.Fatal(err)
		}
		dir = filepath.Join(cwd, "..", "fixtures")
	}
	fixtures, err := runner.LoadFixtures(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(fixtures) == 0 {
		t.Fatalf("no fixtures found under %s", dir)
	}

	baseURL := os.Getenv("EIDOVELA_CONFORMANCE_URL")
	var stop func()
	if baseURL == "" {
		binaryPath, findErr := runner.FindDaemonBinary(dir)
		if findErr != nil {
			t.Skipf("no local daemon binary and EIDOVELA_CONFORMANCE_URL unset: %v", findErr)
		}
		baseURL, stop, err = runner.StartDaemon(binaryPath)
		if err != nil {
			t.Fatalf("start daemon: %v", err)
		}
		defer stop()
	}

	ex := runner.NewExecutor(baseURL)
	for _, fixture := range fixtures {
		fixture := fixture
		t.Run(fixture.ID, func(t *testing.T) {
			result := ex.RunFixture(context.Background(), fixture)
			if !result.Pass {
				reason := "scenario failed"
				if result.Err != nil {
					reason = result.Err.Error()
				}
				t.Fatalf("%s: %s", fixture.ID, reason)
			}
		})
	}
}
