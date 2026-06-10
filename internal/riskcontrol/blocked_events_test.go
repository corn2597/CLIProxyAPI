package riskcontrol

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBlockEventStoreRecordsNewestFirstAndPaginates(t *testing.T) {
	t.Parallel()

	store := NewBlockEventStore(3)
	base := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	store.RecordBlockedEvent(BlockEvent{SessionID: "session-1", Reason: "one", BlockedAt: base})
	store.RecordBlockedEvent(BlockEvent{SessionID: "session-2", Reason: "two", BlockedAt: base.Add(time.Second)})
	store.RecordBlockedEvent(BlockEvent{SessionID: "session-3", Reason: "three", BlockedAt: base.Add(2 * time.Second)})
	store.RecordBlockedEvent(BlockEvent{SessionID: "session-4", Reason: "four", BlockedAt: base.Add(3 * time.Second)})

	page := store.ListBlockedEvents(BlockEventListOptions{Limit: 2})
	if page.Returned != 2 {
		t.Fatalf("Returned = %d, want 2", page.Returned)
	}
	if !page.HasMore {
		t.Fatal("HasMore = false, want true")
	}
	if page.Total != 3 {
		t.Fatalf("Total = %d, want 3 after ring overwrite", page.Total)
	}
	if page.Items[0].SessionID != "session-4" || page.Items[1].SessionID != "session-3" {
		t.Fatalf("unexpected order: %#v", page.Items)
	}
	if page.NextBeforeID != page.Items[len(page.Items)-1].ID {
		t.Fatalf("NextBeforeID = %d, want %d", page.NextBeforeID, page.Items[len(page.Items)-1].ID)
	}

	next := store.ListBlockedEvents(BlockEventListOptions{Limit: 2, BeforeID: page.NextBeforeID})
	if next.Returned != 1 {
		t.Fatalf("next Returned = %d, want 1", next.Returned)
	}
	if next.Items[0].SessionID != "session-2" {
		t.Fatalf("next item session = %q, want session-2", next.Items[0].SessionID)
	}
	if next.HasMore {
		t.Fatal("next HasMore = true, want false")
	}
}

func TestBlockEventStoreFiltersBySessionAndSanitizesPreview(t *testing.T) {
	t.Parallel()

	store := NewBlockEventStore(8)
	store.RecordBlockedEvent(BlockEvent{
		SessionID:       "execution:abc-123",
		UserTextPreview: strings.Repeat("x", maxBlockedEventPreviewRunes+100),
		ImageReferences: []string{"img-1"},
	})
	store.RecordBlockedEvent(BlockEvent{SessionID: "conversation:def-456"})

	page := store.ListBlockedEvents(BlockEventListOptions{SessionID: "abc-123", Limit: 10})
	if page.Returned != 1 {
		t.Fatalf("Returned = %d, want 1", page.Returned)
	}
	if page.Items[0].SessionID != "execution:abc-123" {
		t.Fatalf("SessionID = %q, want execution:abc-123", page.Items[0].SessionID)
	}
	if !strings.Contains(page.Items[0].UserTextPreview, "[truncated]") {
		t.Fatalf("UserTextPreview missing truncation marker: %q", page.Items[0].UserTextPreview)
	}
	if len(page.Items[0].ImageReferences) != 1 || page.Items[0].ImageReferences[0] != "img-1" {
		t.Fatalf("ImageReferences = %#v, want preserved clone", page.Items[0].ImageReferences)
	}
}

func TestBlockEventStorePersistsLatestEntriesOnly(t *testing.T) {
	t.Parallel()

	filePath := filepath.Join(t.TempDir(), "risk-control-blocks.json")

	writer := NewBlockEventStore(20)
	if err := writer.ConfigurePersistence(filePath, 20); err != nil {
		t.Fatalf("ConfigurePersistence(writer): %v", err)
	}

	base := time.Date(2026, 6, 10, 12, 30, 0, 0, time.UTC)
	for i := 1; i <= 25; i++ {
		writer.RecordBlockedEvent(BlockEvent{
			SessionID: fmtSession(i),
			Reason:    "reason",
			BlockedAt: base.Add(time.Duration(i) * time.Second),
		})
	}

	reader := NewBlockEventStore(20)
	if err := reader.ConfigurePersistence(filePath, 20); err != nil {
		t.Fatalf("ConfigurePersistence(reader): %v", err)
	}

	page := reader.ListBlockedEvents(BlockEventListOptions{})
	if page.Returned != 20 || page.Total != 20 {
		t.Fatalf("Returned/Total = %d/%d, want 20/20", page.Returned, page.Total)
	}
	if page.Items[0].SessionID != "session-25" {
		t.Fatalf("latest SessionID = %q, want session-25", page.Items[0].SessionID)
	}
	if page.Items[len(page.Items)-1].SessionID != "session-6" {
		t.Fatalf("oldest retained SessionID = %q, want session-6", page.Items[len(page.Items)-1].SessionID)
	}

	writer.RecordBlockedEvent(BlockEvent{SessionID: "session-26", Reason: "reason", BlockedAt: base.Add(26 * time.Second)})
	reloaded := NewBlockEventStore(20)
	if err := reloaded.ConfigurePersistence(filePath, 20); err != nil {
		t.Fatalf("ConfigurePersistence(reloaded): %v", err)
	}
	page = reloaded.ListBlockedEvents(BlockEventListOptions{})
	if page.Items[0].ID != 26 {
		t.Fatalf("latest ID = %d, want 26", page.Items[0].ID)
	}
	if page.Items[0].SessionID != "session-26" {
		t.Fatalf("latest SessionID = %q, want session-26", page.Items[0].SessionID)
	}
}

func TestBlockEventStoreLoadsUTF8BOMJSON(t *testing.T) {
	t.Parallel()

	filePath := filepath.Join(t.TempDir(), "risk-control-blocks.json")
	payload := "\ufeff" + `{"next_id":2,"items":[{"id":2,"blocked_at":"2026-06-10T12:00:02Z","provider":"codex","session_id":"session-2"}]}`
	if err := os.WriteFile(filePath, []byte(payload), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	store := NewBlockEventStore(20)
	if err := store.ConfigurePersistence(filePath, 20); err != nil {
		t.Fatalf("ConfigurePersistence: %v", err)
	}

	page := store.ListBlockedEvents(BlockEventListOptions{})
	if page.Returned != 1 {
		t.Fatalf("Returned = %d, want 1", page.Returned)
	}
	if page.Items[0].SessionID != "session-2" {
		t.Fatalf("SessionID = %q, want session-2", page.Items[0].SessionID)
	}
}

func fmtSession(i int) string {
	return fmt.Sprintf("session-%d", i)
}
