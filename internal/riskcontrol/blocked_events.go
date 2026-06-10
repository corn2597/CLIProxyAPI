package riskcontrol

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	defaultBlockedEventRetentionLimit = 20
	defaultBlockedEventPageLimit      = 20
	maxBlockedEventPageLimit          = 20
	maxBlockedEventPreviewRunes       = 2000
)

const (
	DecisionSourceFreshAudit = "fresh_audit"
	DecisionSourceCache      = "session_cache"
	DecisionSourceBlockedBan = "blocked_ban"
)

// BlockEvent captures a request that was actively blocked by risk control.
type BlockEvent struct {
	ID              uint64    `json:"id"`
	BlockedAt       time.Time `json:"blocked_at"`
	Provider        string    `json:"provider"`
	SessionID       string    `json:"session_id"`
	RequestedModel  string    `json:"requested_model,omitempty"`
	UpstreamModel   string    `json:"upstream_model,omitempty"`
	AuditModel      string    `json:"audit_model,omitempty"`
	AuditEndpoint   string    `json:"audit_endpoint,omitempty"`
	Mode            string    `json:"mode,omitempty"`
	SourceFormat    string    `json:"source_format,omitempty"`
	RequestPath     string    `json:"request_path,omitempty"`
	MessageCount    int       `json:"message_count"`
	InputHash       string    `json:"input_hash,omitempty"`
	UserTextPreview string    `json:"user_text_preview,omitempty"`
	ImageReferences []string  `json:"image_references,omitempty"`
	DecisionSource  string    `json:"decision_source,omitempty"`
	Reason          string    `json:"reason,omitempty"`
	AuditError      string    `json:"audit_error,omitempty"`
	BlockMessage    string    `json:"block_message,omitempty"`
}

// BlockEventListOptions controls blocked-event listing.
type BlockEventListOptions struct {
	SessionID string
	BeforeID  uint64
	Limit     int
}

// BlockEventPage is a paginated blocked-event response.
type BlockEventPage struct {
	Items        []BlockEvent `json:"items"`
	HasMore      bool         `json:"has_more"`
	NextBeforeID uint64       `json:"next_before_id,omitempty"`
	Returned     int          `json:"returned"`
	Total        int          `json:"total"`
}

// BlockEventReader exposes read access to blocked events.
type BlockEventReader interface {
	ListBlockedEvents(BlockEventListOptions) BlockEventPage
}

type blockedEventState struct {
	NextID uint64       `json:"next_id"`
	Items  []BlockEvent `json:"items"`
}

// BlockEventStore is a bounded blocked-event store backed by optional file persistence.
type BlockEventStore struct {
	mu         sync.Mutex
	maxEntries int
	filePath   string
	loaded     bool
	nextID     uint64
	events     []BlockEvent // oldest -> newest
}

var defaultBlockedEventStore = NewBlockEventStore(defaultBlockedEventRetentionLimit)

// DefaultBlockedEventStore returns the process-wide blocked-event store.
func DefaultBlockedEventStore() *BlockEventStore {
	return defaultBlockedEventStore
}

// NewBlockEventStore creates a bounded blocked-event store.
func NewBlockEventStore(maxEntries int) *BlockEventStore {
	if maxEntries <= 0 {
		maxEntries = defaultBlockedEventRetentionLimit
	}
	return &BlockEventStore{maxEntries: maxEntries}
}

// ConfigurePersistence enables file persistence for the blocked-event store.
func (s *BlockEventStore) ConfigurePersistence(filePath string, maxEntries int) error {
	if s == nil {
		return nil
	}

	filePath = strings.TrimSpace(filePath)
	if filePath != "" && !filepath.IsAbs(filePath) {
		if abs, err := filepath.Abs(filePath); err == nil {
			filePath = abs
		}
	}
	if maxEntries <= 0 {
		maxEntries = defaultBlockedEventRetentionLimit
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.filePath = filePath
	s.maxEntries = maxEntries
	s.loaded = false
	s.nextID = 0
	s.events = nil

	if err := s.ensureLoadedLocked(); err != nil {
		log.WithError(err).Warn("risk control: failed to load blocked-event store")
		return err
	}
	return nil
}

// RecordBlockedEvent appends a blocked-event entry and persists the latest bounded set.
func (s *BlockEventStore) RecordBlockedEvent(event BlockEvent) BlockEvent {
	if s == nil {
		return BlockEvent{}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.ensureLoadedLocked(); err != nil {
		log.WithError(err).Warn("risk control: failed to prepare blocked-event store before record")
	}

	event = sanitizeBlockedEvent(event)
	s.nextID++
	event.ID = s.nextID
	s.events = append(s.events, event)
	if len(s.events) > s.maxEntries {
		s.events = append([]BlockEvent(nil), s.events[len(s.events)-s.maxEntries:]...)
	}
	if err := s.persistLocked(); err != nil {
		log.WithError(err).Warn("risk control: failed to persist blocked-event store")
	}
	return cloneBlockedEvent(event)
}

// ListBlockedEvents returns blocked events in reverse chronological order.
func (s *BlockEventStore) ListBlockedEvents(opts BlockEventListOptions) BlockEventPage {
	page := BlockEventPage{}
	if s == nil {
		return page
	}

	limit := opts.Limit
	if limit <= 0 {
		limit = defaultBlockedEventPageLimit
	}
	if limit > maxBlockedEventPageLimit {
		limit = maxBlockedEventPageLimit
	}
	needle := strings.ToLower(strings.TrimSpace(opts.SessionID))

	s.mu.Lock()
	if err := s.ensureLoadedLocked(); err != nil {
		log.WithError(err).Warn("risk control: failed to load blocked-event store for listing")
	}
	snapshot := cloneBlockedEvents(s.events)
	s.mu.Unlock()

	page.Items = make([]BlockEvent, 0, minInt(limit, len(snapshot)))

	for i := len(snapshot) - 1; i >= 0; i-- {
		event := snapshot[i]
		if event.ID == 0 {
			continue
		}
		if opts.BeforeID > 0 && event.ID >= opts.BeforeID {
			continue
		}
		if needle != "" && !strings.Contains(strings.ToLower(event.SessionID), needle) {
			continue
		}
		page.Total++
		if len(page.Items) < limit {
			page.Items = append(page.Items, event)
			continue
		}
		page.HasMore = true
		if page.NextBeforeID == 0 && len(page.Items) > 0 {
			page.NextBeforeID = page.Items[len(page.Items)-1].ID
		}
	}

	page.Returned = len(page.Items)
	return page
}

func (s *BlockEventStore) ensureLoadedLocked() error {
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

	var state blockedEventState
	if err := json.Unmarshal([]byte(content), &state); err != nil {
		s.events = nil
		s.nextID = 0
		return fmt.Errorf("decode blocked-event store: %w", err)
	}

	items := make([]BlockEvent, 0, len(state.Items))
	var maxID uint64
	for _, item := range state.Items {
		item = sanitizeBlockedEvent(item)
		if item.ID > maxID {
			maxID = item.ID
		}
		items = append(items, item)
	}
	if len(items) > s.maxEntries {
		items = append([]BlockEvent(nil), items[len(items)-s.maxEntries:]...)
	}
	if state.NextID < maxID {
		state.NextID = maxID
	}
	s.events = items
	s.nextID = state.NextID
	return nil
}

func (s *BlockEventStore) persistLocked() error {
	if strings.TrimSpace(s.filePath) == "" {
		return nil
	}
	state := blockedEventState{
		NextID: s.nextID,
		Items:  cloneBlockedEvents(s.events),
	}
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

func sanitizeBlockedEvent(event BlockEvent) BlockEvent {
	event.Provider = strings.TrimSpace(event.Provider)
	if event.Provider == "" {
		event.Provider = "codex"
	}
	event.SessionID = strings.TrimSpace(event.SessionID)
	event.RequestedModel = strings.TrimSpace(event.RequestedModel)
	event.UpstreamModel = strings.TrimSpace(event.UpstreamModel)
	event.AuditModel = strings.TrimSpace(event.AuditModel)
	event.AuditEndpoint = strings.TrimSpace(event.AuditEndpoint)
	event.Mode = strings.TrimSpace(event.Mode)
	event.SourceFormat = strings.TrimSpace(event.SourceFormat)
	event.RequestPath = strings.TrimSpace(event.RequestPath)
	event.InputHash = strings.TrimSpace(event.InputHash)
	event.DecisionSource = strings.TrimSpace(event.DecisionSource)
	event.Reason = strings.TrimSpace(event.Reason)
	event.AuditError = strings.TrimSpace(event.AuditError)
	event.BlockMessage = strings.TrimSpace(event.BlockMessage)
	event.UserTextPreview = truncateRunes(strings.TrimSpace(event.UserTextPreview), maxBlockedEventPreviewRunes)
	event.ImageReferences = cloneStrings(event.ImageReferences)
	if event.BlockedAt.IsZero() {
		event.BlockedAt = time.Now().UTC()
	} else {
		event.BlockedAt = event.BlockedAt.UTC()
	}
	return event
}

func cloneBlockedEvents(events []BlockEvent) []BlockEvent {
	if len(events) == 0 {
		return nil
	}
	out := make([]BlockEvent, len(events))
	for i := range events {
		out[i] = cloneBlockedEvent(events[i])
	}
	return out
}

func cloneBlockedEvent(event BlockEvent) BlockEvent {
	event.ImageReferences = cloneStrings(event.ImageReferences)
	return event
}

func cloneStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, len(values))
	copy(out, values)
	return out
}

func minInt(a int, b int) int {
	if a < b {
		return a
	}
	return b
}
