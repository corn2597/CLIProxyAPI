package riskcontrol

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSampleStoreUpsertDedupesByInputHash(t *testing.T) {
	t.Parallel()

	samplePath := filepath.Join(t.TempDir(), "samples.jsonl")
	store := NewSampleStore()
	if err := store.ConfigurePersistence(samplePath); err != nil {
		t.Fatalf("ConfigurePersistence: %v", err)
	}
	event := BlockEvent{
		ID:              7,
		InputHash:       "same-input-hash",
		SessionID:       "prompt-cache:sample-dedupe",
		UserTextPreview: "normal ops request",
	}
	record := NewSampleRecordFromBlockEvent(event, SampleShouldAllow, OverrideAllowSession, time.Now().UTC())

	first, deduped, err := store.Upsert(record)
	if err != nil {
		t.Fatalf("first Upsert: %v", err)
	}
	if deduped {
		t.Fatal("first Upsert deduped = true, want false")
	}
	second, deduped, err := store.Upsert(record)
	if err != nil {
		t.Fatalf("second Upsert: %v", err)
	}
	if !deduped {
		t.Fatal("second Upsert deduped = false, want true")
	}
	if second.ID != first.ID {
		t.Fatalf("deduped sample ID = %d, want %d", second.ID, first.ID)
	}
	if got := sampleFileLineCount(t, samplePath); got != 1 {
		t.Fatalf("sample file line count = %d, want 1", got)
	}
	status, err := store.StatusForBlockEvent(event)
	if err != nil {
		t.Fatalf("StatusForBlockEvent: %v", err)
	}
	if status.LabelStatus != SampleLabelStatusAllow || status.SampleID != first.ID {
		t.Fatalf("status = %#v, want allow sample %d", status, first.ID)
	}
}

func TestSampleStoreUpsertRejectsOppositeLabel(t *testing.T) {
	t.Parallel()

	samplePath := filepath.Join(t.TempDir(), "samples.jsonl")
	store := NewSampleStore()
	if err := store.ConfigurePersistence(samplePath); err != nil {
		t.Fatalf("ConfigurePersistence: %v", err)
	}
	event := BlockEvent{
		ID:              9,
		InputHash:       "conflict-input-hash",
		SessionID:       "prompt-cache:sample-conflict",
		UserTextPreview: "normal ops request",
	}
	if _, _, err := store.Upsert(NewSampleRecordFromBlockEvent(event, SampleShouldAllow, OverrideAllowSession, time.Now().UTC())); err != nil {
		t.Fatalf("initial Upsert: %v", err)
	}
	_, _, err := store.Upsert(NewSampleRecordFromBlockEvent(event, SampleShouldBlock, "confirm_block", time.Now().UTC()))
	var conflict *SampleLabelConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("opposite-label Upsert err = %v, want SampleLabelConflictError", err)
	}
	if got := sampleFileLineCount(t, samplePath); got != 1 {
		t.Fatalf("sample file line count = %d, want 1", got)
	}
}

func TestSampleStoreAnnotatesHistoricalConflict(t *testing.T) {
	t.Parallel()

	samplePath := filepath.Join(t.TempDir(), "samples.jsonl")
	writer := NewSampleStore()
	if err := writer.ConfigurePersistence(samplePath); err != nil {
		t.Fatalf("ConfigurePersistence(writer): %v", err)
	}
	event := BlockEvent{
		ID:              11,
		InputHash:       "historical-conflict-hash",
		SessionID:       "prompt-cache:historical-conflict",
		UserTextPreview: "historical request",
	}
	if _, err := writer.Append(NewSampleRecordFromBlockEvent(event, SampleShouldAllow, "observe_allow", time.Now().UTC())); err != nil {
		t.Fatalf("append allow: %v", err)
	}
	if _, err := writer.Append(NewSampleRecordFromBlockEvent(event, SampleShouldBlock, "observe_block", time.Now().UTC())); err != nil {
		t.Fatalf("append block: %v", err)
	}

	reader := NewSampleStore()
	if err := reader.ConfigurePersistence(samplePath); err != nil {
		t.Fatalf("ConfigurePersistence(reader): %v", err)
	}
	status, err := reader.StatusForBlockEvent(event)
	if err != nil {
		t.Fatalf("StatusForBlockEvent: %v", err)
	}
	if status.LabelStatus != SampleLabelStatusConflict || !status.SampleConflict {
		t.Fatalf("status = %#v, want conflict", status)
	}
	_, _, err = reader.Upsert(NewSampleRecordFromBlockEvent(event, SampleShouldAllow, "observe_allow", time.Now().UTC()))
	var conflict *SampleLabelConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("Upsert on historical conflict err = %v, want SampleLabelConflictError", err)
	}
}

func TestSampleStoreConfigurePersistenceDefersLoadUntilAccess(t *testing.T) {
	t.Parallel()

	samplePath := filepath.Join(t.TempDir(), "samples.jsonl")
	record := sanitizeSample(SampleRecord{
		ID:              1,
		Label:           SampleShouldAllow,
		Action:          OverrideAllowSession,
		SampleKey:       "lazy-load-hash",
		SourceBlockedID: 12,
		SessionID:       "lazy-load-session",
		InputHash:       "lazy-load-hash",
		UserText:        "ops request",
	})
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := os.WriteFile(samplePath, append(raw, '\n'), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	store := NewSampleStore()
	if err := store.ConfigurePersistence(samplePath); err != nil {
		t.Fatalf("ConfigurePersistence: %v", err)
	}
	if store.loaded {
		t.Fatal("store.loaded = true, want lazy load")
	}
	if store.labelsByKey != nil {
		t.Fatalf("labelsByKey = %#v, want nil before first access", store.labelsByKey)
	}

	status, err := store.StatusForBlockEvent(BlockEvent{ID: 12, InputHash: "lazy-load-hash"})
	if err != nil {
		t.Fatalf("StatusForBlockEvent: %v", err)
	}
	if !store.loaded {
		t.Fatal("store.loaded = false after first access")
	}
	if status.LabelStatus != SampleLabelStatusAllow || status.SampleID != 1 {
		t.Fatalf("status = %#v, want allow sample 1", status)
	}
}

func sampleFileLineCount(t *testing.T, path string) int {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read sample file: %v", err)
	}
	content := strings.TrimSpace(string(raw))
	if content == "" {
		return 0
	}
	return strings.Count(content, "\n") + 1
}
