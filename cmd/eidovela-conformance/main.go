// Command eidovela-conformance runs the EIDOVELA conformance fixtures against a
// locally started consumer-mode eidovelad backed by an in-process fake NOMIVELA
// registry. The runner manages both, so no external daemon or registry is
// needed.
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
	daemonPath := flag.String("daemon", "", "eidovelad binary (default: conformance/bin, built by CI)")
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
	binaryPath := *daemonPath
	if binaryPath == "" {
		var err error
		binaryPath, err = runner.FindDaemonBinary(*fixturesDir)
		if err != nil {
			log.Fatal(err)
		}
	}
	fixtures, err := runner.LoadFixtures(*fixturesDir)
	if err != nil {
		log.Fatal(err)
	}
	if len(fixtures) == 0 {
		log.Fatalf("no fixtures found under %s", *fixturesDir)
	}
	baseURL, registry, stop, err := runner.StartDaemon(binaryPath)
	if err != nil {
		log.Fatal(err)
	}
	defer stop()
	ex := runner.NewExecutor(baseURL, registry)
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
