package riskcontrol

import (
	"path/filepath"
	"testing"
	"time"
)

func TestSessionTrackerAuditsFirstAndEveryInterval(t *testing.T) {
	tracker := NewSessionTracker()
	now := time.Unix(1000, 0)
	interval := 5 * time.Minute
	ttl := time.Hour
	blockedTTL := 7 * 24 * time.Hour
	calls := 0
	audit := func() Decision {
		calls++
		return Decision{Reason: "ok"}
	}

	decision, source := tracker.evaluate("session-1", now, interval, ttl, blockedTTL, audit)
	if source != DecisionSourceFreshAudit || !decision.Audited || calls != 1 {
		t.Fatalf("first evaluate source=%q decision=%+v calls=%d, want fresh audit once", source, decision, calls)
	}

	decision, source = tracker.evaluate("session-1", now.Add(interval-time.Second), interval, ttl, blockedTTL, audit)
	if source != DecisionSourceCache || calls != 1 {
		t.Fatalf("second evaluate source=%q calls=%d, want cached decision", source, calls)
	}
	if !decision.Audited {
		t.Fatalf("cached decision should preserve audited marker: %+v", decision)
	}

	_, source = tracker.evaluate("session-1", now.Add(interval), interval, ttl, blockedTTL, audit)
	if source != DecisionSourceFreshAudit || calls != 2 {
		t.Fatalf("third evaluate source=%q calls=%d, want sampled audit", source, calls)
	}
}

func TestSessionTrackerBlocksSessionForBlockedTTL(t *testing.T) {
	tracker := NewSessionTracker()
	now := time.Unix(2000, 0)
	interval := 5 * time.Minute
	ttl := time.Hour
	blockedTTL := 7 * 24 * time.Hour
	calls := 0
	audit := func() Decision {
		calls++
		return Decision{Blocked: true, Reason: "blocked"}
	}

	decision, source := tracker.evaluate("blocked-session", now, interval, ttl, blockedTTL, audit)
	if source != DecisionSourceFreshAudit || !decision.Blocked || calls != 1 {
		t.Fatalf("first blocked evaluate source=%q decision=%+v calls=%d", source, decision, calls)
	}

	decision, source = tracker.evaluate("blocked-session", now.Add(10*time.Minute), interval, ttl, blockedTTL, audit)
	if source != DecisionSourceBlockedBan || !decision.Blocked || calls != 1 {
		t.Fatalf("blocked session should reuse ban source=%q decision=%+v calls=%d", source, decision, calls)
	}

	decision, source = tracker.evaluate("blocked-session", now.Add(blockedTTL), interval, ttl, blockedTTL, audit)
	if source != DecisionSourceFreshAudit || !decision.Blocked || calls != 2 {
		t.Fatalf("expired ban should re-audit source=%q decision=%+v calls=%d", source, decision, calls)
	}
}

func TestSessionTrackerDoesNotBanAuditFailures(t *testing.T) {
	tracker := NewSessionTracker()
	now := time.Unix(2500, 0)
	interval := 5 * time.Minute
	ttl := time.Hour
	blockedTTL := 7 * 24 * time.Hour
	calls := 0
	audit := func() Decision {
		calls++
		return Decision{Blocked: true, Reason: "audit unavailable", Error: "timeout"}
	}

	decision, source := tracker.evaluate("error-session", now, interval, ttl, blockedTTL, audit)
	if source != DecisionSourceFreshAudit || !decision.Blocked || calls != 1 {
		t.Fatalf("first error block source=%q decision=%+v calls=%d", source, decision, calls)
	}

	decision, source = tracker.evaluate("error-session", now.Add(time.Minute), interval, ttl, blockedTTL, audit)
	if source != DecisionSourceCache || !decision.Blocked || calls != 1 {
		t.Fatalf("error block should stay sampled-only source=%q decision=%+v calls=%d", source, decision, calls)
	}
}

func TestSessionTrackerDebugEvaluationIgnoresBlockedBans(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "risk-control-session-bans.json")
	now := time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)
	tracker := NewSessionTracker()
	if err := tracker.ConfigurePersistence(filePath); err != nil {
		t.Fatalf("ConfigurePersistence: %v", err)
	}
	if err := tracker.bans.Upsert("debug-session", now.Add(7*24*time.Hour), "previous block", now); err != nil {
		t.Fatalf("Upsert persisted ban: %v", err)
	}

	calls := 0
	decision, source := tracker.evaluateWithoutBlockedBans("debug-session", now.Add(time.Minute), 5*time.Minute, time.Hour, func() Decision {
		calls++
		return Decision{Reason: "debug audit"}
	})

	if source != DecisionSourceFreshAudit || calls != 1 {
		t.Fatalf("debug evaluate source=%q calls=%d, want fresh audit", source, calls)
	}
	if decision.Blocked {
		t.Fatalf("debug evaluate should use fresh non-block decision, got %+v", decision)
	}
}

func TestSessionTrackerKeepsBlockedSessionUntilBanExpires(t *testing.T) {
	tracker := NewSessionTracker()
	now := time.Unix(3000, 0)
	ttl := time.Minute
	blockedTTL := 7 * 24 * time.Hour
	audit := func() Decision { return Decision{Blocked: true, Reason: "blocked"} }

	tracker.evaluate("blocked-session", now, time.Minute, ttl, blockedTTL, audit)
	tracker.evaluate("new-session", now.Add(sessionCleanupInterval+time.Second), time.Minute, ttl, blockedTTL, func() Decision { return Decision{} })

	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	if _, ok := tracker.sessions["blocked-session"]; !ok {
		t.Fatalf("blocked session should remain until ban expiry")
	}
	if _, ok := tracker.sessions["new-session"]; !ok {
		t.Fatalf("new session missing after cleanup")
	}
}

func TestSessionTrackerExpiresStaleSessionOnAccess(t *testing.T) {
	tracker := NewSessionTracker()
	now := time.Unix(4000, 0)
	ttl := time.Minute
	blockedTTL := 7 * 24 * time.Hour
	calls := 0
	audit := func() Decision {
		calls++
		return Decision{}
	}

	tracker.evaluate("stale-session", now, time.Minute, ttl, blockedTTL, audit)
	tracker.evaluate("other-session", now.Add(2*time.Minute), time.Minute, ttl, blockedTTL, audit)
	tracker.evaluate("stale-session", now.Add(ttl+time.Second), time.Minute, ttl, blockedTTL, audit)

	if calls != 3 {
		t.Fatalf("calls = %d, want 3 after stale session recreation", calls)
	}
}

func TestSessionTrackerLoadsPersistedBlockedSessionAfterRestart(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "risk-control-session-bans.json")
	now := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	interval := 5 * time.Minute
	ttl := time.Hour
	blockedTTL := 7 * 24 * time.Hour

	first := NewSessionTracker()
	if err := first.ConfigurePersistence(filePath); err != nil {
		t.Fatalf("ConfigurePersistence(first): %v", err)
	}
	firstCalls := 0
	blockAudit := func() Decision {
		firstCalls++
		return Decision{Blocked: true, Reason: "blocked"}
	}

	decision, source := first.evaluate("persisted-session", now, interval, ttl, blockedTTL, blockAudit)
	if source != DecisionSourceFreshAudit || !decision.Blocked || firstCalls != 1 {
		t.Fatalf("first evaluate source=%q decision=%+v calls=%d", source, decision, firstCalls)
	}

	second := NewSessionTracker()
	if err := second.ConfigurePersistence(filePath); err != nil {
		t.Fatalf("ConfigurePersistence(second): %v", err)
	}
	secondCalls := 0
	shouldNotRun := func() Decision {
		secondCalls++
		return Decision{}
	}

	decision, source = second.evaluate("persisted-session", now.Add(time.Minute), interval, ttl, blockedTTL, shouldNotRun)
	if source != DecisionSourceBlockedBan || !decision.Blocked {
		t.Fatalf("persisted ban source=%q decision=%+v, want blocked ban", source, decision)
	}
	if secondCalls != 0 {
		t.Fatalf("persisted ban should skip audit, calls=%d", secondCalls)
	}
}
