// Command eidovela-conformance runs the EIDOVELA conformance fixtures against a
// live eidovelad. Point it at a daemon with -server (default
// http://localhost:8080). The daemon may run in-memory or against PostgreSQL;
// fixtures create their own agents and workloads per scenario.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/axisrobo/eidovela-open/conformance/runner"
)

func main() {
	server := flag.String("server", "http://localhost:8080", "EIDOVELA server URL")
	fixturesDir := flag.String("fixtures", "", "fixtures directory (default: conformance/fixtures)")
	only := flag.String("run", "", "run only fixtures whose id contains this substring")
	flag.Parse()
	if *fixturesDir == "" {
		cwd, err := os.Getwd()
		if err != nil {
			log.Fatal(err)
		}
		*fixturesDir = filepath.Join(cwd, "conformance", "fixtures")
	}
	fixtures, err := runner.LoadFixtures(*fixturesDir)
	if err != nil {
		log.Fatal(err)
	}
	if len(fixtures) == 0 {
		log.Fatalf("no fixtures found under %s", *fixturesDir)
	}
	ex := runner.NewExecutor(*server)
	ctx := context.Background()
	passed, failed := 0, 0
	for _, fixture := range fixtures {
		if *only != "" && !strings.Contains(fixture.ID, *only) {
			continue
		}
		result := ex.RunFixture(ctx, fixture)
		if result.Pass {
			passed++
			fmt.Printf("PASS  %s\n", fixture.ID)
		} else {
			failed++
			reason := "scenario failed"
			if result.Err != nil {
				reason = result.Err.Error()
			}
			fmt.Printf("FAIL  %s  %s\n", fixture.ID, reason)
		}
	}
	fmt.Printf("\n%d passed, %d failed\n", passed, failed)
	if failed > 0 {
		os.Exit(1)
	}
}
