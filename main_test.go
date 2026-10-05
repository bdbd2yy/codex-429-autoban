package main

import (
	"codex-429-autoban/cpasdk/pluginapi"
	"encoding/json"
	"testing"
	"time"
)

func TestAllBannedRejectsBuiltinFallback(t *testing.T) {
	banStore.bans = map[string]banEntry{"fixture": {ResetAt: time.Now().Add(time.Hour)}}
	defer func() { banStore.bans = nil }()
	raw, _ := json.Marshal(pluginapi.SchedulerPickRequest{Provider: "codex", Candidates: []pluginapi.SchedulerAuthCandidate{{ID: "fixture", Provider: "codex"}}})
	got, err := handleSchedulerPick(raw)
	if err != nil {
		t.Fatal(err)
	}
	var env struct {
		Result pluginapi.SchedulerPickResponse `json:"result"`
	}
	json.Unmarshal(got, &env)
	if !env.Result.Handled || !env.Result.Reject {
		t.Fatalf("banned account can reach builtin scheduler: %+v", env.Result)
	}
}

func TestQuotaBodyRecoveryTime(t *testing.T) {
	banStore.bans = nil
	defer func() { banStore.bans = nil }()
	reset := time.Now().Add(time.Hour).Unix()
	body, _ := json.Marshal(map[string]any{"error": map[string]any{"type": "usage_limit_reached", "resets_at": reset, "limit_window_minutes": 10080}})
	raw, _ := json.Marshal(pluginapi.UsageRecord{Provider: "codex", AuthID: "fixture", Failed: true, Failure: pluginapi.UsageFailure{StatusCode: 429, Body: string(body)}})
	handleUsage(raw)
	entry, _ := banStore.lookup("fixture")
	if entry.ResetAt.Unix() != reset {
		t.Fatalf("reset=%d want=%d", entry.ResetAt.Unix(), reset)
	}
}

func TestHealthyPoolPreservesHostScheduler(t *testing.T) {
	banStore.bans = nil
	raw, _ := json.Marshal(pluginapi.SchedulerPickRequest{Candidates: []pluginapi.SchedulerAuthCandidate{{ID: "healthy", Provider: "codex"}}})
	got, _ := handleSchedulerPick(raw)
	var env struct {
		Result pluginapi.SchedulerPickResponse `json:"result"`
	}
	json.Unmarshal(got, &env)
	if env.Result.Handled || env.Result.DelegateBuiltin != "" {
		t.Fatal("plugin overrides host scheduling policy without a ban")
	}
}
