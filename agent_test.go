//go:build unix && !noagent

package main

import "testing"

func TestAgentModuleRegisters(t *testing.T) {
	for _, name := range []string{"agent", "service"} {
		if commands[name] == nil {
			t.Errorf("subcommand %q is not registered", name)
		}
	}
	if loginAgent == nil || loginAgent.Installed == nil || loginAgent.ForPersist == nil {
		t.Error("the agent module must fill in the core's login-agent hooks")
	}
}
