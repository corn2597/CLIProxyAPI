package riskcontrol

import (
	"path/filepath"
	"testing"
	"time"
)

func TestSessionBanStorePersistsBlockedSession(t *testing.T) {
	t.Parallel()

	filePath := filepath.Join(t.TempDir(), "risk-control-session-bans.json")
	now := time.Now().UTC().Add(-time.Minute)
	blockedUntil := now.Add(7 * 24 * time.Hour)

	writer := NewSessionBanStore()
	if err := writer.ConfigurePersistence(filePath); err != nil {
		t.Fatalf("ConfigurePersistence(writer): %v", err)
	}
	if err := writer.Upsert("session-1", blockedUntil, "blocked", now); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	reader := NewSessionBanStore()
	if err := reader.ConfigurePersistence(filePath); err != nil {
		t.Fatalf("ConfigurePersistence(reader): %v", err)
	}
	entry, ok, err := reader.Get("session-1", now.Add(time.Minute))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !ok {
		t.Fatal("expected persisted blocked session")
	}
	if entry.SessionID != "session-1" {
		t.Fatalf("SessionID = %q, want session-1", entry.SessionID)
	}
	if !entry.BlockedUntil.Equal(blockedUntil) {
		t.Fatalf("BlockedUntil = %v, want %v", entry.BlockedUntil, blockedUntil)
	}
	if entry.Reason != "blocked" {
		t.Fatalf("Reason = %q, want blocked", entry.Reason)
	}
}

func TestSessionBanStoreDropsExpiredEntry(t *testing.T) {
	t.Parallel()

	filePath := filepath.Join(t.TempDir(), "risk-control-session-bans.json")
	now := time.Now().UTC().Add(-2 * time.Minute)

	store := NewSessionBanStore()
	if err := store.ConfigurePersistence(filePath); err != nil {
		t.Fatalf("ConfigurePersistence: %v", err)
	}
	if err := store.Upsert("session-expired", now.Add(time.Minute), "blocked", now); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	entry, ok, err := store.Get("session-expired", now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("Get expired: %v", err)
	}
	if ok {
		t.Fatalf("expired entry should be removed, got %#v", entry)
	}

	reloaded := NewSessionBanStore()
	if err := reloaded.ConfigurePersistence(filePath); err != nil {
		t.Fatalf("ConfigurePersistence(reloaded): %v", err)
	}
	_, ok, err = reloaded.Get("session-expired", now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("Get expired after reload: %v", err)
	}
	if ok {
		t.Fatal("expired entry should not survive reload")
	}
}
