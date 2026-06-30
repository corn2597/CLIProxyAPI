package riskcontrol

import (
	"bufio"
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
	defaultBlockedEventRetentionLimit = 0
	defaultBlockedEventPageLimit      = 20
	maxBlockedEventPageLimit          = 100
)

const (
	DecisionSourceFreshAudit  = "fresh_audit"
	DecisionSourceCache       = "session_cache"
	DecisionSourceBlockedBan  = "blocked_ban"
	DecisionSourceObserveOnly = "observe_only"
)

// BlockEvent captures a request that was actively blocked by risk control.
type BlockEvent struct {
	ID                uint64    `json:"id"`
	BlockedAt         time.Time `json:"blocked_at"`
	Provider          string    `json:"provider"`
	SessionID         string    `json:"session_id"`
	RequestedModel    string    `json:"requested_model,omitempty"`
	UpstreamModel     string    `json:"upstream_model,omitempty"`
	AuditModel        string    `json:"audit_model,omitempty"`
	AuditEndpoint     string    `json:"audit_endpoint,omitempty"`
	Mode              string    `json:"mode,omitempty"`
	SourceFormat      string    `json:"source_format,omitempty"`
	RequestPath       string    `json:"request_path,omitempty"`
	MessageCount      int       `json:"message_count"`
	InputHash         string    `json:"input_hash,omitempty"`
	UserTextPreview   string    `json:"user_text_preview,omitempty"`
	ImageReferences   []string  `json:"image_references,omitempty"`
	DecisionSource    string    `json:"decision_source,omitempty"`
	Debug             bool      `json:"debug,omitempty"`
	BanApplied        bool      `json:"ban_applied,omitempty"`
	Reason            string    `json:"reason,omitempty"`
	AuditError        string    `json:"audit_error,omitempty"`
	BlockMessage      string    `json:"block_message,omitempty"`
	PolicyCode        string    `json:"policy_code,omitempty"`
	SubcategoryCode   string    `json:"subcategory_code,omitempty"`
	Confidence        float64   `json:"confidence,omitempty"`
	AuthorizedContext string    `json:"authorized_context,omitempty"`
	MaliciousIntent   bool      `json:"malicious_intent,omitempty"`
	Evidence          []string  `json:"evidence,omitempty"`
	RawAuditResponse  string    `json:"raw_audit_response,omitempty"`
	LabelStatus       string    `json:"label_status,omitempty"`
	SampleID          uint64    `json:"sample_id,omitempty"`
	SampleKey         string    `json:"sample_key,omitempty"`
	SampleLabel       string    `json:"sample_label,omitempty"`
	SampleAction      string    `json:"sample_action,omitempty"`
	SampleLabeledAt   time.Time `json:"sample_labeled_at,omitempty"`
	SampleConflict    bool      `json:"sample_conflict,omitempty"`
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

// BlockEventStore is a blocked-event store backed by optional JSONL persistence.
type BlockEventStore struct {
	mu         sync.Mutex
	maxEntries int
	filePath   string
	loaded     bool
	nextID     uint64
	events     []BlockEvent // oldest -> newest
}

var defaultBlockedEventStore = NewBlockEventStore(defaultBlockedEventRetentionLimit)
var defaultObserveEventStore = NewBlockEventStore(defaultBlockedEventRetentionLimit)

// DefaultBlockedEventStore returns the process-wide blocked-event store.
func DefaultBlockedEventStore() *BlockEventStore {
	return defaultBlockedEventStore
}

// DefaultObserveEventStore returns the process-wide observe-only audit-event store.
func DefaultObserveEventStore() *BlockEventStore {
	return defaultObserveEventStore
}

// ConfigureDefaultObserveEventStore enables observe-only audit-event persistence for the process-wide store.
func ConfigureDefaultObserveEventStore(filePath string) error {
	return defaultObserveEventStore.ConfigurePersistence(filePath, defaultBlockedEventRetentionLimit)
}

// NewBlockEventStore creates a blocked-event store.
// maxEntries <= 0 keeps the full in-memory history.
func NewBlockEventStore(maxEntries int) *BlockEventStore {
	return &BlockEventStore{maxEntries: maxEntries}
}

// ConfigurePersistence enables JSONL file persistence for the blocked-event store.
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

	s.mu.Lock()
	defer s.mu.Unlock()

	s.filePath = filePath
	s.maxEntries = maxEntries
	s.loaded = false
	s.nextID = 0
	s.events = nil
	if strings.TrimSpace(s.filePath) == "" {
		return nil
	}
	if err := s.validatePersistentFileLocked(); err != nil {
		return err
	}
	return nil
}

// RecordBlockedEvent appends a blocked-event entry and persists it to disk when configured.
func (s *BlockEventStore) RecordBlockedEvent(event BlockEvent) BlockEvent {
	if s == nil {
		return BlockEvent{}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.ensureLoadedLocked(); err != nil {
		log.WithError(err).Warn("risk control: failed to prepare blocked-event store before record")
		return cloneBlockedEvent(sanitizeBlockedEvent(event))
	}

	event = sanitizeBlockedEvent(event)
	s.nextID++
	event.ID = s.nextID
	if strings.TrimSpace(s.filePath) == "" {
		s.events = append(s.events, event)
		if s.maxEntries > 0 && len(s.events) > s.maxEntries {
			s.events = append([]BlockEvent(nil), s.events[len(s.events)-s.maxEntries:]...)
		}
	}
	if err := s.appendLocked(event); err != nil {
		log.WithError(err).Warn("risk control: failed to append blocked-event store")
		return cloneBlockedEvent(event)
	}
	if strings.TrimSpace(s.filePath) != "" {
		if err := s.enforceMaxEntriesLocked(); err != nil {
			log.WithError(err).Warn("risk control: failed to trim blocked-event store")
		}
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
	var (
		snapshot []BlockEvent
		errLoad  error
	)
	if strings.TrimSpace(s.filePath) == "" {
		snapshot = cloneBlockedEvents(s.events)
	} else {
		snapshot, errLoad = s.loadPersistentEventsLocked()
	}
	s.mu.Unlock()
	if errLoad != nil {
		log.WithError(errLoad).Warn("risk control: failed to load blocked-event store for listing")
	}

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

// GetBlockedEventByID returns one blocked event by ID.
func (s *BlockEventStore) GetBlockedEventByID(id uint64) (BlockEvent, bool) {
	if s == nil || id == 0 {
		return BlockEvent{}, false
	}
	s.mu.Lock()
	var (
		snapshot []BlockEvent
		errLoad  error
	)
	if strings.TrimSpace(s.filePath) == "" {
		snapshot = cloneBlockedEvents(s.events)
	} else {
		snapshot, errLoad = s.loadPersistentEventsLocked()
	}
	s.mu.Unlock()
	if errLoad != nil {
		log.WithError(errLoad).Warn("risk control: failed to load blocked-event store for lookup")
	}
	for i := len(snapshot) - 1; i >= 0; i-- {
		if snapshot[i].ID == id {
			return cloneBlockedEvent(snapshot[i]), true
		}
	}
	return BlockEvent{}, false
}

type blockedEventState struct {
	NextID uint64       `json:"next_id"`
	Items  []BlockEvent `json:"items"`
}

func (s *BlockEventStore) ensureLoadedLocked() error {
	if s.loaded {
		return nil
	}
	s.nextID = 0

	if strings.TrimSpace(s.filePath) == "" {
		s.loaded = true
		return nil
	}

	events, ok, err := s.tryLoadLegacyJSONLocked()
	if err != nil {
		return err
	}
	if ok {
		if s.maxEntries > 0 && len(events) > s.maxEntries {
			events = append([]BlockEvent(nil), events[len(events)-s.maxEntries:]...)
		}
		if len(events) > 0 {
			s.nextID = events[len(events)-1].ID
		}
		if err := s.rewriteAllLocked(events); err != nil {
			return err
		}
		s.loaded = true
		return nil
	}

	line, err := readLastNonEmptyLine(s.filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			s.loaded = true
			return nil
		}
		return fmt.Errorf("read blocked-event tail: %w", err)
	}
	if len(line) == 0 {
		s.loaded = true
		return nil
	}
	var event BlockEvent
	if err := json.Unmarshal(line, &event); err != nil {
		return fmt.Errorf("decode blocked-event tail: %w", err)
	}
	event = sanitizeBlockedEvent(event)
	s.nextID = event.ID
	s.loaded = true
	return nil
}

func (s *BlockEventStore) validatePersistentFileLocked() error {
	s.nextID = 0
	s.loaded = false

	if strings.TrimSpace(s.filePath) == "" {
		s.loaded = true
		return nil
	}

	events, ok, err := s.tryLoadLegacyJSONLocked()
	if err != nil {
		return err
	}
	if ok {
		if s.maxEntries > 0 && len(events) > s.maxEntries {
			events = append([]BlockEvent(nil), events[len(events)-s.maxEntries:]...)
		}
		if len(events) > 0 {
			s.nextID = events[len(events)-1].ID
		}
		if err := s.rewriteAllLocked(events); err != nil {
			return err
		}
		s.loaded = true
		return nil
	}

	var (
		maxID    uint64
		total    int
		retained []BlockEvent
	)
	err = scanJSONLFile(s.filePath, func(line []byte) error {
		var event BlockEvent
		if err := json.Unmarshal(line, &event); err != nil {
			return fmt.Errorf("decode blocked-event jsonl: %w", err)
		}
		event = sanitizeBlockedEvent(event)
		if event.ID > maxID {
			maxID = event.ID
		}
		total++
		if s.maxEntries > 0 {
			if len(retained) < s.maxEntries {
				retained = append(retained, event)
			} else {
				copy(retained, retained[1:])
				retained[len(retained)-1] = event
			}
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			s.loaded = true
			return nil
		}
		return err
	}

	s.nextID = maxID
	if s.maxEntries > 0 && total > s.maxEntries {
		if err := s.rewriteAllLocked(retained); err != nil {
			return err
		}
	}
	s.loaded = true
	return nil
}

func (s *BlockEventStore) tryLoadLegacyJSONLocked() ([]BlockEvent, bool, error) {
	data, err := readTrimmedFile(s.filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, err
	}
	if len(data) == 0 {
		return nil, false, nil
	}

	var state blockedEventState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, false, nil
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
	if state.NextID > maxID {
		maxID = state.NextID
	}
	s.nextID = maxID
	return items, true, nil
}

func (s *BlockEventStore) appendLocked(event BlockEvent) error {
	if strings.TrimSpace(s.filePath) == "" {
		return nil
	}
	dir := filepath.Dir(s.filePath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	file, err := os.OpenFile(s.filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	raw, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if _, err := file.Write(append(raw, '\n')); err != nil {
		return err
	}
	return nil
}

func (s *BlockEventStore) loadPersistentEventsLocked() ([]BlockEvent, error) {
	if strings.TrimSpace(s.filePath) == "" {
		return cloneBlockedEvents(s.events), nil
	}

	if err := s.ensureLoadedLocked(); err != nil {
		return nil, err
	}

	events := make([]BlockEvent, 0, 32)
	var maxID uint64
	err := scanJSONLFile(s.filePath, func(line []byte) error {
		var event BlockEvent
		if err := json.Unmarshal(line, &event); err != nil {
			return fmt.Errorf("decode blocked-event jsonl: %w", err)
		}
		event = sanitizeBlockedEvent(event)
		if event.ID > maxID {
			maxID = event.ID
		}
		events = append(events, event)
		return nil
	})
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			s.nextID = 0
			return nil, nil
		}
		return nil, err
	}
	if s.maxEntries > 0 && len(events) > s.maxEntries {
		events = append([]BlockEvent(nil), events[len(events)-s.maxEntries:]...)
	}
	s.nextID = maxID
	return events, nil
}

func (s *BlockEventStore) rewriteAllLocked(events []BlockEvent) error {
	if strings.TrimSpace(s.filePath) == "" {
		return nil
	}
	dir := filepath.Dir(s.filePath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	tmpPath := s.filePath + ".tmp"
	file, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	writer := bufio.NewWriter(file)
	for _, event := range events {
		raw, err := json.Marshal(event)
		if err != nil {
			_ = file.Close()
			_ = os.Remove(tmpPath)
			return err
		}
		if _, err := writer.Write(append(raw, '\n')); err != nil {
			_ = file.Close()
			_ = os.Remove(tmpPath)
			return err
		}
	}
	if err := writer.Flush(); err != nil {
		_ = file.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, s.filePath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

func (s *BlockEventStore) enforceMaxEntriesLocked() error {
	if s.maxEntries <= 0 {
		return nil
	}
	if strings.TrimSpace(s.filePath) == "" {
		if len(s.events) > s.maxEntries {
			s.events = append([]BlockEvent(nil), s.events[len(s.events)-s.maxEntries:]...)
		}
		return nil
	}

	events, err := s.loadPersistentEventsLocked()
	if err != nil {
		return err
	}
	if len(events) <= s.maxEntries {
		return nil
	}
	events = append([]BlockEvent(nil), events[len(events)-s.maxEntries:]...)
	return s.rewriteAllLocked(events)
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
	event.PolicyCode = normalizePolicyCode(event.PolicyCode)
	event.SubcategoryCode = normalizeSubcategoryCode(event.SubcategoryCode)
	event.AuthorizedContext = normalizeAuthorizedContext(event.AuthorizedContext)
	event.RawAuditResponse = strings.TrimSpace(event.RawAuditResponse)
	event.LabelStatus = strings.TrimSpace(event.LabelStatus)
	event.SampleKey = strings.TrimSpace(event.SampleKey)
	event.SampleLabel = strings.TrimSpace(event.SampleLabel)
	event.SampleAction = strings.TrimSpace(event.SampleAction)
	event.UserTextPreview = strings.TrimSpace(event.UserTextPreview)
	event.ImageReferences = cloneStrings(event.ImageReferences)
	event.Evidence = cloneStrings(event.Evidence)
	if !event.SampleLabeledAt.IsZero() {
		event.SampleLabeledAt = event.SampleLabeledAt.UTC()
	}
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
	event.Evidence = cloneStrings(event.Evidence)
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
