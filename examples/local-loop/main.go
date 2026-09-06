// local-loop demonstrates the v1 identity flow against eidovelad.
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/axisrobo/eidovela-open/sdk/go/eidovela"
)

func main() {
	ctx := context.Background()
	client := eidovela.NewClient("http://localhost:8080")
	_, privateKey, err := eidovela.GeneratePoPKey()
	if err != nil {
		log.Fatal(err)
	}

	agent, err := client.RegisterAgent(ctx, eidovela.RegisterAgentRequest{
		Class: "service", BindingType: "organization_root", AuthorityRootRef: "org:example",
	})
	if err != nil {
		log.Fatal(err)
	}
	workload, err := client.RegisterWorkload(ctx, eidovela.WorkloadRegistrationRequest{
		Platform: "kubernetes", Selector: map[string]string{"namespace": "default", "serviceaccount": "demo"},
		TrustDomain: "local", AllowedProofMethods: []string{"private_key_jwt"},
	})
	if err != nil {
		log.Fatal(err)
	}
	challenge, err := client.CreateChallenge(ctx, agent.AgentID, workload.RegistrationID)
	if err != nil {
		log.Fatal(err)
	}
	instance, err := client.CompleteEnrollment(ctx, challenge, privateKey, "praxovela", "demo-workload", "sha256:demo", map[string]string{"namespace": "default", "serviceaccount": "demo"})
	if err != nil {
		log.Fatal(err)
	}
	if _, err := client.Activate(ctx, agent.AgentID); err != nil {
		log.Fatal(err)
	}
	token, err := client.Token(ctx, agent.AgentID, instance.InstanceID, "aegivela", privateKey)
	if err != nil {
		log.Fatal(err)
	}
	active, err := client.Introspect(ctx, token.Token, "aegivela", privateKey)
	if err != nil {
		log.Fatal(err)
	}
	agents, err := client.ListAgents(ctx, "active", 0, 0)
	if err != nil {
		log.Fatal(err)
	}
	outbox, err := client.OutboxStatus(ctx)
	if err != nil {
		log.Fatal(err)
	}
	detail, err := client.AgentDetail(ctx, agent.AgentID)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("agent=%s instance=%s token_active=%t active_agents=%d outbox_pending=%d state=%s root=%s\n", agent.AgentID, instance.InstanceID, active, len(agents), outbox.Pending, detail.LifecycleState, detail.AuthorityRoot)
}
