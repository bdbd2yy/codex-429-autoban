package main

import (
	"codex-429-autoban/cpasdk/pluginapi"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

const ownershipKey = "_codex_429_autoban"

var hostCall = nativeHostCall
var recoveryMu sync.Mutex
var lifecycleMu sync.Mutex
var recoveryStop chan struct{}
var recoveryDone chan struct{}

type ownership struct {
	ResetAt time.Time `json:"reset_at"`
	Window  string    `json:"window"`
}

func getHeader(h http.Header, key string) string {
	for k, values := range h {
		if strings.EqualFold(k, key) && len(values) > 0 {
			return values[0]
		}
	}
	return ""
}

func banFromFailureBody(body string) (banEntry, bool) {
	var response struct {
		Error struct {
			Type    string `json:"type"`
			ResetAt int64  `json:"resets_at"`
			ResetIn int64  `json:"resets_in_seconds"`
			Minutes int    `json:"limit_window_minutes"`
		} `json:"error"`
	}
	if json.Unmarshal([]byte(body), &response) != nil || response.Error.Type != "usage_limit_reached" {
		return banEntry{}, false
	}
	reset := time.Unix(response.Error.ResetAt, 0)
	if response.Error.ResetAt <= 0 {
		if response.Error.ResetIn <= 0 {
			return banEntry{}, false
		}
		reset = time.Now().Add(time.Duration(response.Error.ResetIn) * time.Second)
	}
	window := "5h"
	if response.Error.Minutes == windowMinutesWeek {
		window = "week"
	}
	return banEntry{ResetAt: reset, Window: window, BannedAt: time.Now()}, true
}

func authFiles() ([]pluginapi.HostAuthFileEntry, error) {
	raw, err := hostCall("host.auth.list", map[string]any{})
	if err != nil {
		return nil, err
	}
	var r struct {
		Files []pluginapi.HostAuthFileEntry `json:"files"`
	}
	err = json.Unmarshal(raw, &r)
	return r.Files, err
}
func authDocument(index string) (map[string]json.RawMessage, string, error) {
	raw, err := hostCall("host.auth.get", map[string]any{"auth_index": index})
	if err != nil {
		return nil, "", err
	}
	var r pluginapi.HostAuthGetResponse
	if err = json.Unmarshal(raw, &r); err != nil {
		return nil, "", err
	}
	var doc map[string]json.RawMessage
	err = json.Unmarshal(r.JSON, &doc)
	if doc == nil && err == nil {
		err = fmt.Errorf("credential JSON must be an object")
	}
	return doc, r.Name, err
}
func saveDocument(name string, doc map[string]json.RawMessage) error {
	raw, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	_, err = hostCall("host.auth.save", pluginapi.HostAuthSaveRequest{Name: name, JSON: raw})
	return err
}
func disableCredential(id string, e banEntry) error {
	recoveryMu.Lock()
	defer recoveryMu.Unlock()
	files, err := authFiles()
	if err != nil {
		return err
	}
	for _, a := range files {
		if a.ID != id && a.AuthIndex != id {
			continue
		}
		if !strings.EqualFold(a.Provider, "codex") && !strings.EqualFold(a.Type, "codex") {
			return fmt.Errorf("not a Codex credential")
		}
		doc, name, err := authDocument(a.AuthIndex)
		if err != nil {
			return err
		}
		var disabled bool
		json.Unmarshal(doc["disabled"], &disabled)
		// A manual disable predating the ban is never owned or undone by this plugin.
		if disabled && len(doc[ownershipKey]) == 0 {
			return nil
		}
		marker, _ := json.Marshal(ownership{ResetAt: e.ResetAt, Window: e.Window})
		if string(doc[ownershipKey]) == string(marker) && disabled {
			return nil
		}
		doc[ownershipKey] = marker
		doc["disabled"] = json.RawMessage("true")
		if err := saveDocument(name, doc); err != nil {
			return err
		}
		e.Owned = true
		banStore.set(id, e)
		return nil
	}
	return fmt.Errorf("credential %q not found", id)
}

// force is used only by the authenticated unban endpoints. Timed recovery
// re-reads the persisted deadline and touches only plugin-owned disables.
func restoreCredential(id string, force bool) error {
	recoveryMu.Lock()
	defer recoveryMu.Unlock()
	files, err := authFiles()
	if err != nil {
		return err
	}
	for _, a := range files {
		if a.ID != id && a.AuthIndex != id {
			continue
		}
		doc, name, err := authDocument(a.AuthIndex)
		if err != nil {
			return err
		}
		var marker ownership
		if len(doc[ownershipKey]) == 0 {
			return nil
		}
		if err = json.Unmarshal(doc[ownershipKey], &marker); err != nil {
			return err
		}
		if !force && time.Now().Before(marker.ResetAt) {
			return nil
		}
		delete(doc, ownershipKey)
		doc["disabled"] = json.RawMessage("false")
		if err = saveDocument(name, doc); err != nil {
			return err
		}
		banStore.clear(id)
		slog.Info("codex-429-autoban: restored plugin-disabled credential", "auth_id", id)
		return nil
	}
	return fmt.Errorf("credential %q not found", id)
}

func recoverySweep() {
	files, err := authFiles()
	if err != nil {
		return
	}
	for _, a := range files {
		if !strings.EqualFold(a.Provider, "codex") && !strings.EqualFold(a.Type, "codex") {
			continue
		}
		doc, _, err := authDocument(a.AuthIndex)
		if err != nil {
			continue
		}
		var marker ownership
		if len(doc[ownershipKey]) > 0 {
			if json.Unmarshal(doc[ownershipKey], &marker) != nil || marker.ResetAt.IsZero() {
				continue
			}
			banStore.set(a.ID, banEntry{ResetAt: marker.ResetAt, Window: marker.Window, Owned: true})
			if !time.Now().Before(marker.ResetAt) {
				if err := restoreCredential(a.ID, false); err != nil {
					slog.Warn("codex-429-autoban: recovery pending", "auth_id", a.ID, "error", err)
				}
			}
		} else if !a.Disabled {
			// A successful Reset Bank redemption removes the ownership marker and
			// re-enables the credential; discard the old in-memory ban as well.
			if e, ok := banStore.lookup(a.ID); ok {
				// Initial disable failures are retried; previously persisted bans have
				// BannedAt zero when reloaded by this sweep.
				if e.Owned || e.BannedAt.IsZero() || !time.Now().Before(e.ResetAt) {
					banStore.clear(a.ID)
				} else {
					if err := disableCredential(a.ID, e); err != nil {
						slog.Warn("codex-429-autoban: disable retry failed", "auth_id", a.ID, "error", err)
					}
				}
			}
		}
	}
}
func startRecovery() {
	lifecycleMu.Lock()
	defer lifecycleMu.Unlock()
	if recoveryStop != nil {
		return
	}
	recoveryStop = make(chan struct{})
	recoveryDone = make(chan struct{})
	stop, done := recoveryStop, recoveryDone
	go func() {
		defer close(done)
		recoverySweep()
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				recoverySweep()
			}
		}
	}()
}
func stopRecovery() {
	lifecycleMu.Lock()
	defer lifecycleMu.Unlock()
	if recoveryStop == nil {
		return
	}
	close(recoveryStop)
	<-recoveryDone
	recoveryStop = nil
	recoveryDone = nil
}

func headerResetTime(h http.Header, prefix string) time.Time {
	if t := headerUnixTime(h, prefix+"-reset-at"); !t.IsZero() {
		return t
	}
	if seconds := headerInt(h, prefix+"-reset-after-seconds"); seconds > 0 {
		return time.Now().Add(time.Duration(seconds) * time.Second)
	}
	return time.Time{}
}
