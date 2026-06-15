package riskcontrol

import (
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const sessionCleanupInterval = 15 * time.Minute

// Decision stores the latest audit outcome for a session.
type Decision struct {
	Audited           bool
	Blocked           bool
	Reason            string
	Error             string
	PolicyCode        string
	SubcategoryCode   string
	Confidence        float64
	AuthorizedContext string
	MaliciousIntent   bool
	Evidence          []string
	RawResponse       string
	FailureClass      string
}

type sessionState struct {
	mu           sync.Mutex
	firstSeenAt  time.Time
	lastSeenAt   time.Time
	lastAuditAt  time.Time
	blockedUntil time.Time
	lastDecision Decision
}

func (s *sessionState) expired(now time.Time, ttl time.Duration) bool {
	if s == nil {
		return true
	}
	if !s.blockedUntil.IsZero() && now.Before(s.blockedUntil) {
		return false
	}
	return !s.lastSeenAt.IsZero() && now.Sub(s.lastSeenAt) > ttl
}

// SessionTracker keeps deterministic per-session audit cadence.
type SessionTracker struct {
	mu          sync.Mutex
	sessions    map[string]*sessionState
	lastCleanup time.Time
	bans        *SessionBanStore
}

func NewSessionTracker() *SessionTracker {
	return &SessionTracker{
		sessions: make(map[string]*sessionState),
		bans:     NewSessionBanStore(),
	}
}

// ConfigurePersistence enables blocked-session persistence for this tracker.
func (t *SessionTracker) ConfigurePersistence(filePath string) error {
	if t == nil {
		return nil
	}
	if t.bans == nil {
		t.bans = NewSessionBanStore()
	}
	return t.bans.ConfigurePersistence(filePath)
}

// ConfigureDefaultSessionBanStore enables blocked-session persistence for the process-wide tracker.
func ConfigureDefaultSessionBanStore(filePath string) error {
	return defaultTracker.ConfigurePersistence(filePath)
}

func (t *SessionTracker) state(sessionID string, now time.Time, ttl time.Duration) *sessionState {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.sessions == nil {
		t.sessions = make(map[string]*sessionState)
	}
	if t.lastCleanup.IsZero() || now.Sub(t.lastCleanup) >= sessionCleanupInterval {
		for key, state := range t.sessions {
			if state == nil {
				delete(t.sessions, key)
				continue
			}
			state.mu.Lock()
			expired := state.expired(now, ttl)
			state.mu.Unlock()
			if expired {
				delete(t.sessions, key)
			}
		}
		t.lastCleanup = now
	}
	state := t.sessions[sessionID]
	if state != nil {
		state.mu.Lock()
		expired := state.expired(now, ttl)
		state.mu.Unlock()
		if expired {
			delete(t.sessions, sessionID)
			state = nil
		}
	}
	if state == nil {
		state = &sessionState{firstSeenAt: now}
		t.sessions[sessionID] = state
	}
	return state
}

func (t *SessionTracker) evaluate(sessionID string, now time.Time, interval time.Duration, ttl time.Duration, blockedTTL time.Duration, audit func() Decision) (Decision, string) {
	state := t.state(sessionID, now, ttl)
	state.mu.Lock()
	defer state.mu.Unlock()
	state.lastSeenAt = now

	if !state.blockedUntil.IsZero() {
		if now.Before(state.blockedUntil) {
			return state.lastDecision, DecisionSourceBlockedBan
		}
		state.blockedUntil = time.Time{}
	}
	if decision, ok := t.loadPersistedBlockedDecision(sessionID, now, state); ok {
		return decision, DecisionSourceBlockedBan
	}

	due := state.lastAuditAt.IsZero() || now.Sub(state.lastAuditAt) >= interval
	if !due {
		return state.lastDecision, DecisionSourceCache
	}
	decision := audit()
	decision.Audited = true
	state.lastAuditAt = now
	if decision.Blocked && blockedTTL > 0 && decision.Error == "" {
		state.blockedUntil = now.Add(blockedTTL)
		if err := t.upsertPersistedBan(sessionID, state.blockedUntil, decision.Reason, now); err != nil {
			log.WithError(err).WithField("session_id", sessionID).Warn("risk control: failed to persist blocked session")
		}
	} else {
		state.blockedUntil = time.Time{}
		if err := t.deletePersistedBan(sessionID); err != nil {
			log.WithError(err).WithField("session_id", sessionID).Warn("risk control: failed to clear blocked session persistence")
		}
	}
	state.lastDecision = decision
	return decision, DecisionSourceFreshAudit
}

func (t *SessionTracker) loadPersistedBlockedDecision(sessionID string, now time.Time, state *sessionState) (Decision, bool) {
	if t == nil || t.bans == nil || state == nil {
		return Decision{}, false
	}
	entry, ok, err := t.bans.Get(sessionID, now)
	if err != nil {
		log.WithError(err).WithField("session_id", sessionID).Warn("risk control: failed to load blocked session persistence")
		return Decision{}, false
	}
	if !ok {
		return Decision{}, false
	}
	state.blockedUntil = entry.BlockedUntil
	state.lastDecision = Decision{
		Audited: true,
		Blocked: true,
		Reason:  entry.Reason,
	}
	return state.lastDecision, true
}

func (t *SessionTracker) upsertPersistedBan(sessionID string, blockedUntil time.Time, reason string, now time.Time) error {
	if t == nil || t.bans == nil {
		return nil
	}
	return t.bans.Upsert(sessionID, blockedUntil, reason, now)
}

func (t *SessionTracker) deletePersistedBan(sessionID string) error {
	if t == nil || t.bans == nil {
		return nil
	}
	return t.bans.Delete(sessionID)
}
