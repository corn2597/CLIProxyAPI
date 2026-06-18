package riskcontrol

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAuditLogStoreRecordsNewestFirstAndFilters(t *testing.T) {
	t.Parallel()

	store := NewAuditLogStore(64 * 1024)
	base := time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)
	store.RecordAuditLog(AuditLogEntry{AuditedAt: base, SessionID: "session-one", Decision: "allow"})
	store.RecordAuditLog(AuditLogEntry{AuditedAt: base.Add(time.Second), SessionID: "session-two", Decision: "block", PolicyCode: "malicious_cyber_abuse", InputHash: "hash-two"})
	store.RecordAuditLog(AuditLogEntry{AuditedAt: base.Add(2 * time.Second), SessionID: "session-three", Decision: "observe", PolicyCode: "privacy_abuse", InputHash: "hash-three"})

	page := store.ListAuditLogs(AuditLogListOptions{Limit: 2})
	if page.Returned != 2 || !page.HasMore {
		t.Fatalf("Returned/HasMore = %d/%v, want 2/true", page.Returned, page.HasMore)
	}
	if page.Items[0].SessionID != "session-three" || page.Items[1].SessionID != "session-two" {
		t.Fatalf("unexpected order: %#v", page.Items)
	}

	filtered := store.ListAuditLogs(AuditLogListOptions{Decision: "block", PolicyCode: "malicious_cyber_abuse", InputHash: "hash-two"})
	if filtered.Returned != 1 || filtered.Items[0].SessionID != "session-two" {
		t.Fatalf("filtered page = %#v, want session-two only", filtered)
	}
}

func TestAuditLogStorePersistsAndDropsOldestByMaxBytes(t *testing.T) {
	t.Parallel()

	filePath := filepath.Join(t.TempDir(), "risk-control-audit-logs.jsonl")
	writer := NewAuditLogStore(1200)
	if err := writer.ConfigurePersistence(filePath, 1200); err != nil {
		t.Fatalf("ConfigurePersistence(writer): %v", err)
	}

	base := time.Date(2026, 6, 16, 12, 30, 0, 0, time.UTC)
	for i := 1; i <= 20; i++ {
		writer.RecordAuditLog(AuditLogEntry{
			AuditedAt:       base.Add(time.Duration(i) * time.Second),
			SessionID:       fmtSession(i),
			Decision:        "allow",
			UserTextPreview: strings.Repeat("x", 120),
			RawAuditResponse: `{"flagged":false,"decision":"allow","policy_code":"none","subcategory_code":"none",
				"confidence":0.1,"authorized_context":"unknown","malicious_intent":false,"evidence":[],"reason":""}`,
		})
	}

	info, err := os.Stat(filePath)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Size() > 1200 {
		t.Fatalf("audit log file size = %d, want <= 1200", info.Size())
	}

	reader := NewAuditLogStore(1200)
	if err := reader.ConfigurePersistence(filePath, 1200); err != nil {
		t.Fatalf("ConfigurePersistence(reader): %v", err)
	}
	page := reader.ListAuditLogs(AuditLogListOptions{Limit: 100})
	if page.Returned == 0 {
		t.Fatal("expected retained audit logs")
	}
	if page.Items[0].SessionID != "session-20" {
		t.Fatalf("latest SessionID = %q, want session-20", page.Items[0].SessionID)
	}
	if page.CurrentBytes > page.MaxBytes {
		t.Fatalf("CurrentBytes/MaxBytes = %d/%d, want current <= max", page.CurrentBytes, page.MaxBytes)
	}
	for _, item := range page.Items {
		if item.SessionID == "session-1" {
			t.Fatalf("oldest audit log was not dropped: %#v", page.Items)
		}
	}
}
