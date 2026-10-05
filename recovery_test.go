package main

import (
	"codex-429-autoban/cpasdk/pluginapi"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func mockHost(t *testing.T, initiallyDisabled bool) *map[string]json.RawMessage {
	t.Helper()
	original := hostCall
	doc := map[string]json.RawMessage{"type": json.RawMessage(`"codex"`), "access_token": json.RawMessage(`"fixture-token"`), "disabled": json.RawMessage(fmt.Sprint(initiallyDisabled))}
	hostCall = func(method string, payload any) (json.RawMessage, error) {
		var value any
		switch method {
		case "host.auth.list":
			var disabled bool
			json.Unmarshal(doc["disabled"], &disabled)
			value = map[string]any{"files": []pluginapi.HostAuthFileEntry{{ID: "fixture.json", Name: "fixture.json", AuthIndex: "index", Provider: "codex", Disabled: disabled}}}
		case "host.auth.get":
			value = pluginapi.HostAuthGetResponse{Name: "fixture.json", AuthIndex: "index", JSON: mustJSON(doc)}
		case "host.auth.save":
			req := payload.(pluginapi.HostAuthSaveRequest)
			doc = nil
			if err := json.Unmarshal(req.JSON, &doc); err != nil {
				return nil, err
			}
			value = map[string]any{}
		default:
			return nil, fmt.Errorf("unexpected method %s", method)
		}
		return json.Marshal(value)
	}
	banStore.bans = nil
	t.Cleanup(func() { hostCall = original; banStore.bans = nil })
	return &doc
}
func mustJSON(v any) json.RawMessage { b, _ := json.Marshal(v); return b }

func TestDisableAndTimedRecoveryPreserveCredentials(t *testing.T) {
	doc := mockHost(t, false)
	e := banEntry{ResetAt: time.Now().Add(time.Hour), Window: "5h"}
	if err := disableCredential("fixture.json", e); err != nil {
		t.Fatal(err)
	}
	if string((*doc)["disabled"]) != "true" || len((*doc)[ownershipKey]) == 0 {
		t.Fatal("credential not visibly disabled")
	}
	if err := restoreCredential("fixture.json", false); err != nil {
		t.Fatal(err)
	}
	if string((*doc)["disabled"]) != "true" {
		t.Fatal("restored before quota reset")
	}
	(*doc)[ownershipKey] = mustJSON(ownership{ResetAt: time.Now().Add(-time.Second), Window: "5h"})
	banStore.bans = nil // emulate restart: recovery must use persisted ownership
	recoverySweep()
	if string((*doc)["disabled"]) != "false" || len((*doc)[ownershipKey]) != 0 {
		t.Fatal("due credential not recovered after restart")
	}
	if string((*doc)["access_token"]) != `"fixture-token"` {
		t.Fatal("token changed")
	}
}
func TestManualDisableIsNeverOwnedOrRestored(t *testing.T) {
	doc := mockHost(t, true)
	if err := disableCredential("fixture.json", banEntry{ResetAt: time.Now().Add(-time.Second)}); err != nil {
		t.Fatal(err)
	}
	if len((*doc)[ownershipKey]) != 0 {
		t.Fatal("manual disable claimed")
	}
	if err := restoreCredential("fixture.json", true); err != nil {
		t.Fatal(err)
	}
	if string((*doc)["disabled"]) != "true" {
		t.Fatal("manual disable undone")
	}
}
func TestVerifiedResetDoesNotReban(t *testing.T) {
	doc := mockHost(t, false)
	if err := disableCredential("fixture.json", banEntry{ResetAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	// Simulate auto-reset's verified redemption callback.
	delete(*doc, ownershipKey)
	(*doc)["disabled"] = json.RawMessage("false")
	recoverySweep()
	if _, ok := banStore.lookup("fixture.json"); ok {
		t.Fatal("old ban survives verified reset")
	}
	if string((*doc)["disabled"]) != "false" {
		t.Fatal("reset account disabled again")
	}
}
func TestLowercaseHeaderAndLatestWindow(t *testing.T) {
	now := time.Now()
	e, ok := classifyAndBuildBan(map[string][]string{"x-codex-primary-used-percent": {"100"}, "x-codex-secondary-used-percent": {"100"}, "x-codex-primary-reset-at": {fmt.Sprint(now.Add(time.Hour).Unix())}, "x-codex-secondary-reset-at": {fmt.Sprint(now.Add(24 * time.Hour).Unix())}})
	if !ok || e.ResetAt.Unix() != now.Add(24*time.Hour).Unix() {
		t.Fatalf("wrong full-window deadline: %+v", e)
	}
}
