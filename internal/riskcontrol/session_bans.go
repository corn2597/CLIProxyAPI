package riskcontrol

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type sessionBanEntry struct {
	SessionID    string    `json:"session_id"`
	BlockedUntil time.Time `json:"blocked_until"`
	Reason       string    `json:"reason,omitempty"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type sessionBanState struct {
	Items []sessionBanEntry `json:"items"`
}

// SessionBanStore persists blocked session IDs so bans survive process restarts.
type SessionBanStore struct {
	mu       sync.Mutex
	filePath string
	loaded   bool
	entries  map[string]sessionBanEntry
}

// NewSessionBanStore creates a new blocked-session persistence store.
func NewSessionBanStore() *SessionBanStore {
	return &SessionBanStore{entries: make(map[string]sessionBanEntry)}
}

// ConfigurePersistence enables file persistence for blocked session IDs.
func (s *SessionBanStore) ConfigurePersistence(filePath string) error {
	if s == nil {
		return nil
	}

	filePath = strings.TrimSpace(filePath)
	if filePath != "" && !filepath.IsAbs(filePath) {
		if abs, err := filepath.Abs(filePath); err == nil {
			filePath = abs
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.filePath = filePath
	s.loaded = false
	s.entries = make(map[string]sessionBanEntry)
	return s.ensureLoadedLocked()
}

// Get returns an active blocked-session entry. Expired entries are removed lazily.
func (s *SessionBanStore) Get(sessionID string, now time.Time) (sessionBanEntry, bool, error) {
	if s == nil {
		return sessionBanEntry{}, false, nil
	}

	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return sessionBanEntry{}, false, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.ensureLoadedLocked(); err != nil {
		return sessionBanEntry{}, false, err
	}

	entry, ok := s.entries[sessionID]
	if !ok {
		return sessionBanEntry{}, false, nil
	}
	if !entry.BlockedUntil.IsZero() && !now.Before(entry.BlockedUntil) {
		delete(s.entries, sessionID)
		if err := s.persistLocked(); err != nil {
			return sessionBanEntry{}, false, err
		}
		return sessionBanEntry{}, false, nil
	}
	return entry, true, nil
}

// Upsert stores or refreshes a blocked-session entry.
func (s *SessionBanStore) Upsert(sessionID string, blockedUntil time.Time, reason string, now time.Time) error {
	if s == nil {
		return nil
	}

	entry := sanitizeSessionBanEntry(sessionBanEntry{
		SessionID:    sessionID,
		BlockedUntil: blockedUntil,
		Reason:       reason,
		UpdatedAt:    now,
	})
	if entry.SessionID == "" || entry.BlockedUntil.IsZero() {
		return s.Delete(sessionID)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.ensureLoadedLocked(); err != nil {
		return err
	}
	s.entries[entry.SessionID] = entry
	return s.persistLocked()
}

// Delete removes a blocked-session entry.
func (s *SessionBanStore) Delete(sessionID string) error {
	if s == nil {
		return nil
	}

	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.ensureLoadedLocked(); err != nil {
		return err
	}
	if _, ok := s.entries[sessionID]; !ok {
		return nil
	}
	delete(s.entries, sessionID)
	return s.persistLocked()
}

func (s *SessionBanStore) ensureLoadedLocked() error {
	if s.loaded {
		return nil
	}
	s.loaded = true

	if strings.TrimSpace(s.filePath) == "" {
		return nil
	}

	data, err := os.ReadFile(s.filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	content := strings.TrimSpace(strings.TrimPrefix(string(data), "\ufeff"))
	if content == "" {
		return nil
	}

	var state sessionBanState
	if err := json.Unmarshal([]byte(content), &state); err != nil {
		s.entries = make(map[string]sessionBanEntry)
		return err
	}

	now := time.Now().UTC()
	entries := make(map[string]sessionBanEntry, len(state.Items))
	for _, entry := range state.Items {
		entry = sanitizeSessionBanEntry(entry)
		if entry.SessionID == "" || entry.BlockedUntil.IsZero() || !now.Before(entry.BlockedUntil) {
			continue
		}
		entries[entry.SessionID] = entry
	}
	s.entries = entries
	return nil
}

func (s *SessionBanStore) persistLocked() error {
	if strings.TrimSpace(s.filePath) == "" {
		return nil
	}

	state := sessionBanState{
		Items: make([]sessionBanEntry, 0, len(s.entries)),
	}
	for _, entry := range s.entries {
		if entry.SessionID == "" || entry.BlockedUntil.IsZero() {
			continue
		}
		state.Items = append(state.Items, sanitizeSessionBanEntry(entry))
	}
	sort.Slice(state.Items, func(i, j int) bool {
		if state.Items[i].UpdatedAt.Equal(state.Items[j].UpdatedAt) {
			return state.Items[i].SessionID < state.Items[j].SessionID
		}
		return state.Items[i].UpdatedAt.Before(state.Items[j].UpdatedAt)
	})

	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.filePath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}

	tmpPath := s.filePath + ".tmp"
	if err := os.WriteFile(tmpPath, raw, 0o600); err != nil {
		return err
	}
	if err := os.Remove(s.filePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, s.filePath); err != nil {
		_ = os.Remove(tmpPath)
		return os.WriteFile(s.filePath, raw, 0o600)
	}
	return nil
}

func sanitizeSessionBanEntry(entry sessionBanEntry) sessionBanEntry {
	entry.SessionID = strings.TrimSpace(entry.SessionID)
	entry.Reason = strings.TrimSpace(entry.Reason)
	if entry.BlockedUntil.IsZero() {
		entry.BlockedUntil = time.Time{}
	} else {
		entry.BlockedUntil = entry.BlockedUntil.UTC()
	}
	if entry.UpdatedAt.IsZero() {
		entry.UpdatedAt = time.Now().UTC()
	} else {
		entry.UpdatedAt = entry.UpdatedAt.UTC()
	}
	return entry
}
