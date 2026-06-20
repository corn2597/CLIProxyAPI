package riskcontrol

import (
	"path/filepath"
	"testing"
	"time"
)

func TestSessionTrackerReusesLastSuccessfulAuditWithinInterval(t *testing.T) {
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
		t.Fatalf("first evaluate source=%q decision=%+v calls=%d", source, decision, calls)
	}

	decision, source = tracker.evaluate("session-1", now.Add(time.Minute), interval, ttl, blockedTTL, audit)
	if source != DecisionSourceCache || !decision.Audited || calls != 1 {
		t.Fatalf("second evaluate source=%q decision=%+v calls=%d", source, decision, calls)
	}

	decision, source = tracker.evaluate("session-1", now.Add(interval), interval, ttl, blockedTTL, audit)
	if source != DecisionSourceFreshAudit || !decision.Audited || calls != 2 {
		t.Fatalf("third evaluate source=%q decision=%+v calls=%d", source, decision, calls)
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
		t.Fatalf("first evaluate source=%q decision=%+v calls=%d", source, decision, calls)
	}

	decision, source = tracker.evaluate("blocked-session", now.Add(10*time.Minute), interval, ttl, blockedTTL, audit)
	if source != DecisionSourceBlockedBan || !decision.Blocked || calls != 1 {
		t.Fatalf("blocked decision source=%q decision=%+v calls=%d", source, decision, calls)
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
		t.Fatalf("debug evaluate source=%q calls=%d", source, calls)
	}
	if decision.Blocked {
		t.Fatalf("debug evaluate should ignore persisted ban, got %+v", decision)
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
	now := time.Now().UTC().Add(-time.Minute)
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
		t.Fatalf("persisted ban source=%q decision=%+v", source, decision)
	}
	if secondCalls != 0 {
		t.Fatalf("persisted ban should skip audit, calls=%d", secondCalls)
	}
}

func TestSessionTrackerAdmitAsyncUsesPendingAndRecentAuditCache(t *testing.T) {
	tracker := NewSessionTracker()
	now := time.Unix(5000, 0)
	interval := 5 * time.Minute
	ttl := time.Hour

	decision, source, scheduled := tracker.admitAsync("async-session", now, interval, ttl, false)
	if source != DecisionSourceFreshAudit || !scheduled || decision.Blocked {
		t.Fatalf("first admit decision=%+v source=%q scheduled=%t", decision, source, scheduled)
	}

	decision, source, scheduled = tracker.admitAsync("async-session", now.Add(time.Second), interval, ttl, false)
	if source != DecisionSourceCache || scheduled || decision.Blocked {
		t.Fatalf("second admit decision=%+v source=%q scheduled=%t", decision, source, scheduled)
	}

	tracker.completeAsyncAudit("async-session", now.Add(2*time.Second), ttl, 24*time.Hour, 30*time.Second, false, Decision{
		Reason: "allow",
	})

	decision, source, scheduled = tracker.admitAsync("async-session", now.Add(time.Minute), interval, ttl, false)
	if source != DecisionSourceCache || scheduled || decision.Blocked {
		t.Fatalf("third admit decision=%+v source=%q scheduled=%t", decision, source, scheduled)
	}

	decision, source, scheduled = tracker.admitAsync("async-session", now.Add(interval+3*time.Second), interval, ttl, false)
	if source != DecisionSourceFreshAudit || !scheduled || decision.Blocked {
		t.Fatalf("fourth admit decision=%+v source=%q scheduled=%t", decision, source, scheduled)
	}
}

func TestSessionTrackerAsyncCompletionAppliesBlockedBanWhenEnabled(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "risk-control-session-bans.json")
	tracker := NewSessionTracker()
	if err := tracker.ConfigurePersistence(filePath); err != nil {
		t.Fatalf("ConfigurePersistence: %v", err)
	}
	now := time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)

	_, source, scheduled := tracker.admitAsync("async-ban-session", now, 5*time.Minute, time.Hour, true)
	if source != DecisionSourceFreshAudit || !scheduled {
		t.Fatalf("source=%q scheduled=%t", source, scheduled)
	}

	tracker.completeAsyncAudit("async-ban-session", now.Add(time.Second), time.Hour, 24*time.Hour, 30*time.Second, true, Decision{
		Blocked: true,
		Reason:  "blocked",
	})

	decision, source, scheduled := tracker.admitAsync("async-ban-session", now.Add(2*time.Second), 5*time.Minute, time.Hour, true)
	if scheduled || source != DecisionSourceBlockedBan || !decision.Blocked {
		t.Fatalf("decision=%+v source=%q scheduled=%t", decision, source, scheduled)
	}
}

func TestSessionTrackerAsyncFailureBacksOffBeforeRetry(t *testing.T) {
	tracker := NewSessionTracker()
	now := time.Unix(7000, 0)
	interval := 5 * time.Minute
	ttl := time.Hour
	retryDelay := 30 * time.Second

	_, source, scheduled := tracker.admitAsync("async-retry-session", now, interval, ttl, false)
	if source != DecisionSourceFreshAudit || !scheduled {
		t.Fatalf("first admit source=%q scheduled=%t", source, scheduled)
	}

	tracker.completeAsyncAudit("async-retry-session", now.Add(time.Second), ttl, 24*time.Hour, retryDelay, false, Decision{
		Error:        "audit unavailable",
		FailureClass: "audit_failed",
	})

	decision, source, scheduled := tracker.admitAsync("async-retry-session", now.Add(10*time.Second), interval, ttl, false)
	if source != DecisionSourceCache || scheduled || decision.Error == "" {
		t.Fatalf("backoff admit decision=%+v source=%q scheduled=%t", decision, source, scheduled)
	}

	decision, source, scheduled = tracker.admitAsync("async-retry-session", now.Add(time.Second+retryDelay), interval, ttl, false)
	if source != DecisionSourceFreshAudit || !scheduled || decision.Blocked {
		t.Fatalf("retry admit decision=%+v source=%q scheduled=%t", decision, source, scheduled)
	}
}
