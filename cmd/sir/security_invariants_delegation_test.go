package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"testing"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/hooks"
	"github.com/somoore/sir/pkg/policy"
	"github.com/somoore/sir/pkg/session"
)

func runInvariantDelegationAfterRiskyState(t *testing.T, fixture securityInvariantFixture) {
	t.Helper()
	forceLocalPolicyFallbackForCLI(t)

	cases := []struct {
		name   string
		mutate func(*session.State)
	}{
		{
			name: "tainted mcp server",
			mutate: func(state *session.State) {
				state.AddTaintedMCPServer("jira")
			},
		},
		{
			name: "elevated posture",
			mutate: func(state *session.State) {
				state.RaisePosture(policy.PostureStateElevated)
			},
		},
		{
			name: "pending injection alert",
			mutate: func(state *session.State) {
				state.SetPendingInjectionAlert("pending injection alert")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newTestEnv(t)
			l := env.writeDefaultLease()

			state := session.NewState(env.projectRoot)
			env.writeSession(state)
			tc.mutate(state)
			env.writeSession(state)

			subagentDecision, err := runSubagentStartDecision(env.projectRoot, state)
			if err != nil {
				t.Fatalf("SubagentStart delegation: %v", err)
			}
			if got, want := subagentDecision, fixture.Expected["subagent_decision"]; got != want {
				t.Fatalf("SubagentStart delegation decision = %q, want %q", got, want)
			}

			agentResp, err := hooks.ExportEvaluatePayload(&hooks.HookPayload{
				ToolName:  "Agent",
				ToolInput: map[string]interface{}{"task": "delegate work to a sub-agent"},
				CWD:       env.projectRoot,
			}, l, state, env.projectRoot)
			if err != nil {
				t.Fatalf("evaluate Agent delegation: %v", err)
			}
			if got, want := string(agentResp.Decision), fixture.Expected["agent_decision"]; got != want {
				t.Fatalf("Agent delegation decision = %q, want %q (reason=%s)", got, want, agentResp.Reason)
			}
		})
	}
}

func runSubagentStartDecision(projectRoot string, state *session.State) (string, error) {
	payloadJSON, err := json.Marshal(hooks.SubagentPayload{
		HookEventName: "SubagentStart",
		AgentName:     "general-purpose",
		Tools:         []string{"Read"},
	})
	if err != nil {
		return "", err
	}

	origStdin, origStdout := os.Stdin, os.Stdout
	defer func() {
		os.Stdin = origStdin
		os.Stdout = origStdout
	}()

	inR, inW, err := os.Pipe()
	if err != nil {
		return "", err
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		return "", err
	}
	os.Stdin = inR
	os.Stdout = outW

	if _, err := inW.Write(payloadJSON); err != nil {
		return "", err
	}
	inW.Close()

	done := make(chan error, 1)
	go func() {
		done <- hooks.EvaluateSubagentStart(projectRoot, &agent.ClaudeAgent{})
	}()

	if err := <-done; err != nil {
		outW.Close()
		return "", err
	}
	outW.Close()

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, outR); err != nil {
		return "", err
	}
	if buf.Len() == 0 {
		return "", nil
	}

	var resp struct {
		HookSpecificOutput struct {
			PermissionDecision string `json:"permissionDecision"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(buf.Bytes(), &resp); err != nil {
		return "", err
	}
	return resp.HookSpecificOutput.PermissionDecision, nil
}
