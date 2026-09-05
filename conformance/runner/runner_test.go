package runner_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/axisrobo/eidovela-open/conformance/runner"
)

// TestFixturesAgainstDaemon runs the executable conformance fixtures against a
// live daemon. Set EIDOVELA_CONFORMANCE_URL to the base URL of a running
// eidovelad (e.g. http://127.0.0.1:8099). The test is skipped when unset so
// unit builds never require a daemon.
func TestFixturesAgainstDaemon(t *testing.T) {
	baseURL := os.Getenv("EIDOVELA_CONFORMANCE_URL")
	if baseURL == "" {
		t.Skip("EIDOVELA_CONFORMANCE_URL is not set; point it at a running eidovelad")
	}
	dir := os.Getenv("EIDOVELA_CONFORMANCE_FIXTURES")
	if dir == "" {
		dir = filepath.Join("..", "fixtures")
	}
	fixtures, err := runner.LoadFixtures(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(fixtures) == 0 {
		t.Fatalf("no fixtures found under %s", dir)
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
