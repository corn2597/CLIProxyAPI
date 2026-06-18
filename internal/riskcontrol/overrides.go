package riskcontrol

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	OverrideAllowOnce    = "allow_once"
	OverrideAllowSession = "allow_session"
)

type ManualOverride struct {
	ID                 uint64    `json:"id"`
	Kind               string    `json:"kind"`
	InputHash          string    `json:"input_hash,omitempty"`
	SessionID          string    `json:"session_id,omitempty"`
	SourceBlockedEvent uint64    `json:"source_blocked_event"`
	RemainingUses      int       `json:"remaining_uses,omitempty"`
	ExpiresAt          time.Time `json:"expires_at,omitempty"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

type overrideState struct {
	NextID uint64           `json:"next_id"`
	Items  []ManualOverride `json:"items"`
}

type OverrideStore struct {
	mu       sync.Mutex
	filePath string
	loaded   bool
	nextID   uint64
	entries  map[string]ManualOverride
}

var defaultOverrideStore = NewOverrideStore()

func DefaultOverrideStore() *OverrideStore {
	return defaultOverrideStore
}

func ConfigureDefaultOverrideStore(filePath string) error {
	return defaultOverrideStore.ConfigurePersistence(filePath)
}

func NewOverrideStore() *OverrideStore {
	return &OverrideStore{entries: make(map[string]ManualOverride)}
}

func (s *OverrideStore) ConfigurePersistence(filePath string) error {
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
	s.nextID = 0
	s.entries = make(map[string]ManualOverride)
	return s.ensureLoadedLocked()
}

func (s *OverrideStore) AllowOnce(inputHash string, sessionID string, sourceBlockedEvent uint64, now time.Time) (ManualOverride, error) {
	if s == nil {
		return ManualOverride{}, nil
	}
	override := sanitizeOverride(ManualOverride{
		Kind:               OverrideAllowOnce,
		InputHash:          inputHash,
		SessionID:          sessionID,
		SourceBlockedEvent: sourceBlockedEvent,
		RemainingUses:      1,
		CreatedAt:          now,
		UpdatedAt:          now,
	})
	if override.InputHash == "" {
		return ManualOverride{}, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureLoadedLocked(); err != nil {
		return ManualOverride{}, err
	}
	s.nextID++
	override.ID = s.nextID
	s.entries[inputHashKey(override.InputHash)] = override
	return override, s.persistLocked()
}

func (s *OverrideStore) AllowSession(sessionID string, inputHash string, sourceBlockedEvent uint64, expiresAt time.Time, now time.Time) (ManualOverride, error) {
	if s == nil {
		return ManualOverride{}, nil
	}
	now = now.UTC()
	override := sanitizeOverride(ManualOverride{
		Kind:               OverrideAllowSession,
		SessionID:          sessionID,
		InputHash:          inputHash,
		SourceBlockedEvent: sourceBlockedEvent,
		ExpiresAt:          expiresAt,
		CreatedAt:          now,
		UpdatedAt:          now,
	})
	if override.SessionID == "" {
		return ManualOverride{}, nil
	}
	if override.ExpiresAt.IsZero() || !now.Before(override.ExpiresAt) {
		return ManualOverride{}, errors.New("session allow override requires a future expires_at")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureLoadedLocked(); err != nil {
		return ManualOverride{}, err
	}
	s.nextID++
	override.ID = s.nextID
	s.entries[sessionKey(override.SessionID)] = override
	return override, s.persistLocked()
}

func (s *OverrideStore) Match(inputHash string, sessionID string, now time.Time) (ManualOverride, bool, error) {
	if s == nil {
		return ManualOverride{}, false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureLoadedLocked(); err != nil {
		return ManualOverride{}, false, err
	}
	if override, ok, changed := s.matchLocked(sessionKey(strings.TrimSpace(sessionID)), now); ok {
		if changed {
			if err := s.persistLocked(); err != nil {
				return ManualOverride{}, false, err
			}
		}
		return override, true, nil
	}
	if override, ok, changed := s.matchLocked(inputHashKey(strings.TrimSpace(inputHash)), now); ok {
		if changed {
			if err := s.persistLocked(); err != nil {
				return ManualOverride{}, false, err
			}
		}
		return override, true, nil
	}
	return ManualOverride{}, false, nil
}

func (s *OverrideStore) matchLocked(key string, now time.Time) (ManualOverride, bool, bool) {
	if key == "" {
		return ManualOverride{}, false, false
	}
	override, ok := s.entries[key]
	if !ok {
		return ManualOverride{}, false, false
	}
	if !override.ExpiresAt.IsZero() && !now.Before(override.ExpiresAt) {
		delete(s.entries, key)
		return ManualOverride{}, false, true
	}
	if override.Kind == OverrideAllowSession && override.ExpiresAt.IsZero() {
		delete(s.entries, key)
		return ManualOverride{}, false, true
	}
	if override.Kind == OverrideAllowOnce {
		if override.RemainingUses <= 0 {
			delete(s.entries, key)
			return ManualOverride{}, false, true
		}
		override.RemainingUses--
		override.UpdatedAt = now.UTC()
		if override.RemainingUses <= 0 {
			delete(s.entries, key)
		} else {
			s.entries[key] = override
		}
		return override, true, true
	}
	return override, true, false
}

func (s *OverrideStore) ensureLoadedLocked() error {
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
	var state overrideState
	if err := json.Unmarshal([]byte(content), &state); err != nil {
		s.entries = make(map[string]ManualOverride)
		return err
	}
	s.entries = make(map[string]ManualOverride, len(state.Items))
	var maxID uint64
	now := time.Now().UTC()
	for _, item := range state.Items {
		item = sanitizeOverride(item)
		if item.ID > maxID {
			maxID = item.ID
		}
		if !item.ExpiresAt.IsZero() && !now.Before(item.ExpiresAt) {
			continue
		}
		switch item.Kind {
		case OverrideAllowSession:
			if item.ExpiresAt.IsZero() {
				continue
			}
			s.entries[sessionKey(item.SessionID)] = item
		case OverrideAllowOnce:
			if item.RemainingUses > 0 {
				s.entries[inputHashKey(item.InputHash)] = item
			}
		}
	}
	s.nextID = maxID
	return nil
}

func (s *OverrideStore) persistLocked() error {
	if strings.TrimSpace(s.filePath) == "" {
		return nil
	}
	dir := filepath.Dir(s.filePath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	state := overrideState{
		NextID: s.nextID,
		Items:  make([]ManualOverride, 0, len(s.entries)),
	}
	for _, item := range s.entries {
		state.Items = append(state.Items, sanitizeOverride(item))
	}
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	tmpPath := s.filePath + ".tmp"
	if err := os.WriteFile(tmpPath, raw, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, s.filePath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

func sanitizeOverride(override ManualOverride) ManualOverride {
	override.Kind = strings.TrimSpace(override.Kind)
	override.InputHash = strings.TrimSpace(override.InputHash)
	override.SessionID = strings.TrimSpace(override.SessionID)
	if override.ExpiresAt.IsZero() {
		override.ExpiresAt = time.Time{}
	} else {
		override.ExpiresAt = override.ExpiresAt.UTC()
	}
	if override.CreatedAt.IsZero() {
		override.CreatedAt = time.Now().UTC()
	} else {
		override.CreatedAt = override.CreatedAt.UTC()
	}
	if override.UpdatedAt.IsZero() {
		override.UpdatedAt = override.CreatedAt
	} else {
		override.UpdatedAt = override.UpdatedAt.UTC()
	}
	return override
}

func inputHashKey(inputHash string) string {
	inputHash = strings.TrimSpace(inputHash)
	if inputHash == "" {
		return ""
	}
	return "input_hash:" + inputHash
}

func sessionKey(sessionID string) string {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return ""
	}
	return "session_id:" + sessionID
}
