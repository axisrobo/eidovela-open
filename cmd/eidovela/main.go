package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/axisrobo/eidovela-open/sdk/go/eidovela"
)

func main() {
	server := flag.String("server", "http://localhost:8080", "EIDOVELA server URL")
	flag.Parse()
	if flag.NArg() < 1 {
		usage()
	}
	client := eidovela.NewClient(*server)
	ctx := context.Background()
	var result any
	var err error
	switch flag.Arg(0) {
	case "register-service":
		if flag.NArg() != 2 {
			usage()
		}
		result, err = client.RegisterAgent(ctx, eidovela.RegisterAgentRequest{Class: "service", BindingType: "organization_root", AuthorityRootRef: flag.Arg(1)})
	case "register-twin":
		if flag.NArg() != 2 {
			usage()
		}
		result, err = client.RegisterAgent(ctx, eidovela.RegisterAgentRequest{Class: "twin", BindingType: "human_master", AuthorityRootRef: flag.Arg(1)})
	case "suspend":
		if flag.NArg() != 2 {
			usage()
		}
		result, err = client.Suspend(ctx, flag.Arg(1))
	case "revoke":
		if flag.NArg() != 2 {
			usage()
		}
		result, err = client.Revoke(ctx, flag.Arg(1))
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

func usage() {
	fmt.Fprintln(os.Stderr, "usage: eidovela [-server URL] register-service <organization-root>")
	fmt.Fprintln(os.Stderr, "       eidovela [-server URL] register-twin <human-master>")
	fmt.Fprintln(os.Stderr, "       eidovela [-server URL] suspend <agent-id>")
	os.Exit(2)
}
