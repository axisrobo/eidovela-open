package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/axisrobo/eidovela-open/sdk/go/eidovela"
)

func main() {
	server := flag.String("server", "http://localhost:8080", "EIDOVELA server URL")
	flag.Parse()
	args := flag.Args()
	if len(args) < 1 {
		usage()
	}
	client := eidovela.NewClient(*server)
	ctx := context.Background()
	var result any
	var err error
	switch args[0] {
	case "register-service":
		if len(args) != 2 {
			usage()
		}
		result, err = client.RegisterAgent(ctx, eidovela.RegisterAgentRequest{Class: "service", BindingType: "organization_root", AuthorityRootRef: args[1]})
	case "register-twin":
		if len(args) != 2 {
			usage()
		}
		result, err = client.RegisterAgent(ctx, eidovela.RegisterAgentRequest{Class: "twin", BindingType: "human_master", AuthorityRootRef: args[1]})
	case "activate":
		if len(args) != 2 {
			usage()
		}
		result, err = client.Activate(ctx, args[1])
	case "suspend":
		if len(args) != 2 {
			usage()
		}
		result, err = client.Suspend(ctx, args[1])
	case "revoke":
		if len(args) != 2 {
			usage()
		}
		result, err = client.Revoke(ctx, args[1])
	case "federation-trust":
		result, err = federationTrust(ctx, client, args[1:])
	default:
		usage()
	}
	if err != nil {
		log.Fatal(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		log.Fatal(err)
	}
}

// federationTrust administers peer trust anchors. The interactive
// proof-of-possession flows (enroll/token/exchange/introspect) need a caller
// private key and stay in the SDK and local-loop example.
func federationTrust(ctx context.Context, client *eidovela.Client, args []string) (any, error) {
	if len(args) < 1 {
		usage()
	}
	switch args[0] {
	case "list":
		return client.ListFederationTrusts(ctx)
	case "get":
		if len(args) != 2 {
			usage()
		}
		return client.GetFederationTrust(ctx, args[1])
	case "enable":
		if len(args) != 2 {
			usage()
		}
		return client.EnableFederationTrust(ctx, args[1])
	case "disable":
		if len(args) != 2 {
			usage()
		}
		return client.DisableFederationTrust(ctx, args[1])
	case "create":
		return createFederationTrust(ctx, client, args[1:])
	default:
		usage()
		return nil, nil
	}
}

func createFederationTrust(ctx context.Context, client *eidovela.Client, args []string) (any, error) {
	fs := flag.NewFlagSet("federation-trust create", flag.ExitOnError)
	jwksURI := fs.String("jwks-uri", "", "peer https JWKS URI (loopback http allowed for development)")
	audiences := fs.String("audiences", "", "comma-separated allowed local audiences")
	agentClaim := fs.String("agent-claim", "sub", "peer claim name that carries the agent id")
	status := fs.String("status", "active", "trust status: active | disabled")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() != 1 || *jwksURI == "" || *audiences == "" {
		usage()
	}
	allowed := splitCSV(*audiences)
	trust := eidovela.FederationTrust{
		Issuer: fs.Arg(0), JWKSURI: *jwksURI,
		AllowedAudiences: allowed, ClaimMappings: map[string]string{"agent_id": *agentClaim},
		Status: *status,
	}
	return client.CreateFederationTrust(ctx, trust)
}

func splitCSV(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: eidovela [-server URL] register-service <organization-root>")
	fmt.Fprintln(os.Stderr, "       eidovela [-server URL] register-twin <human-master>")
	fmt.Fprintln(os.Stderr, "       eidovela [-server URL] activate|suspend|revoke <agent-id>")
	fmt.Fprintln(os.Stderr, "       eidovela [-server URL] federation-trust list")
	fmt.Fprintln(os.Stderr, "       eidovela [-server URL] federation-trust get|enable|disable <issuer>")
	fmt.Fprintln(os.Stderr, "       eidovela [-server URL] federation-trust create <issuer> -jwks-uri URL -audiences a,b [-agent-claim sub] [-status active|disabled]")
	fmt.Fprintln(os.Stderr, "PoP-bound agent flows (enroll/token/exchange/introspect) are SDK/local-loop examples.")
	os.Exit(2)
}
