package riskcontrol

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOverrideStoreAllowOnceMatchesOnce(t *testing.T) {
	t.Parallel()

	store := NewOverrideStore()
	if err := store.ConfigurePersistence(filepath.Join(t.TempDir(), "overrides.json")); err != nil {
		t.Fatalf("ConfigurePersistence: %v", err)
	}
	now := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	if _, err := store.AllowOnce("hash-1", "session-1", 7, now); err != nil {
		t.Fatalf("AllowOnce: %v", err)
	}

	if _, ok, err := store.Match("hash-1", "", now.Add(time.Minute)); err != nil {
		t.Fatalf("Match first: %v", err)
	} else if !ok {
		t.Fatal("expected first allow-once match")
	}
	if _, ok, err := store.Match("hash-1", "", now.Add(2*time.Minute)); err != nil {
		t.Fatalf("Match second: %v", err)
	} else if ok {
		t.Fatal("allow-once override should be consumed after first match")
	}
}

func TestOverrideStoreAllowSessionPersistsAcrossReload(t *testing.T) {
	t.Parallel()

	filePath := filepath.Join(t.TempDir(), "overrides.json")
	now := time.Now().UTC()

	writer := NewOverrideStore()
	if err := writer.ConfigurePersistence(filePath); err != nil {
		t.Fatalf("ConfigurePersistence(writer): %v", err)
	}
	if _, err := writer.AllowSession("session-1", "hash-1", 5, now.Add(24*time.Hour), now); err != nil {
		t.Fatalf("AllowSession: %v", err)
	}

	reader := NewOverrideStore()
	if err := reader.ConfigurePersistence(filePath); err != nil {
		t.Fatalf("ConfigurePersistence(reader): %v", err)
	}
	override, ok, err := reader.Match("", "session-1", now.Add(time.Hour))
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if !ok {
		t.Fatal("expected persisted session override")
	}
	if override.Kind != OverrideAllowSession {
		t.Fatalf("Kind = %q, want %q", override.Kind, OverrideAllowSession)
	}
}

func TestOverrideStoreAllowSessionRequiresFutureExpiration(t *testing.T) {
	t.Parallel()

	store := NewOverrideStore()
	now := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)

	if _, err := store.AllowSession("session-1", "hash-1", 5, time.Time{}, now); err == nil {
		t.Fatal("expected zero expires_at to be rejected")
	}
	if _, err := store.AllowSession("session-1", "hash-1", 5, now.Add(-time.Second), now); err == nil {
		t.Fatal("expected past expires_at to be rejected")
	}
	if _, err := store.AllowSession("session-1", "hash-1", 5, now.Add(time.Hour), now); err != nil {
		t.Fatalf("future expires_at should be accepted: %v", err)
	}
}

func TestOverrideStoreIgnoresPersistedPermanentSessionOverride(t *testing.T) {
	t.Parallel()

	filePath := filepath.Join(t.TempDir(), "overrides.json")
	if err := os.WriteFile(filePath, []byte(`{
  "next_id": 1,
  "items": [
    {
      "id": 1,
      "kind": "allow_session",
      "input_hash": "hash-1",
      "session_id": "session-1",
      "source_blocked_event": 5,
      "created_at": "2026-06-10T12:00:00Z",
      "updated_at": "2026-06-10T12:00:00Z"
    }
  ]
}`), 0o600); err != nil {
		t.Fatalf("write overrides fixture: %v", err)
	}

	store := NewOverrideStore()
	if err := store.ConfigurePersistence(filePath); err != nil {
		t.Fatalf("ConfigurePersistence: %v", err)
	}
	if _, ok, err := store.Match("", "session-1", time.Date(2026, 6, 10, 12, 1, 0, 0, time.UTC)); err != nil {
		t.Fatalf("Match: %v", err)
	} else if ok {
		t.Fatal("permanent session override should be ignored")
	}
}
