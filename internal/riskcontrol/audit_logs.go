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
	defaultAuditLogMaxBytes      int64 = 100 * 1024 * 1024
	defaultAuditLogPageLimit           = 20
	maxAuditLogPageLimit               = 100
	auditLogUserTextPreviewLimit       = 8 * 1024
	auditLogRawResponseLimit           = 32 * 1024
	auditLogErrorLimit                 = 4 * 1024
	auditLogReasonLimit                = 1024
	auditLogEvidenceLimit              = 1024
)

// AuditLogEntry captures one fresh LLM audit call and its parsed outcome.
type AuditLogEntry struct {
	ID                uint64    `json:"id"`
	AuditedAt         time.Time `json:"audited_at"`
	DurationMS        int64     `json:"duration_ms,omitempty"`
	Provider          string    `json:"provider"`
	SessionID         string    `json:"session_id"`
	RequestedModel    string    `json:"requested_model,omitempty"`
	UpstreamModel     string    `json:"upstream_model,omitempty"`
	AuditModel        string    `json:"audit_model,omitempty"`
	AuditEndpoint     string    `json:"audit_endpoint,omitempty"`
	Mode              string    `json:"mode,omitempty"`
	Threshold         float64   `json:"threshold,omitempty"`
	SourceFormat      string    `json:"source_format,omitempty"`
	RequestPath       string    `json:"request_path,omitempty"`
	MessageCount      int       `json:"message_count,omitempty"`
	InputHash         string    `json:"input_hash,omitempty"`
	UserTextPreview   string    `json:"user_text_preview,omitempty"`
	ImageReferences   []string  `json:"image_references,omitempty"`
	Decision          string    `json:"decision"`
	Debug             bool      `json:"debug,omitempty"`
	Enforced          bool      `json:"enforced,omitempty"`
	BanApplied        bool      `json:"ban_applied,omitempty"`
	Blocked           bool      `json:"blocked,omitempty"`
	ObserveOnly       bool      `json:"observe_only,omitempty"`
	PolicyCode        string    `json:"policy_code,omitempty"`
	SubcategoryCode   string    `json:"subcategory_code,omitempty"`
	Confidence        float64   `json:"confidence,omitempty"`
	AuthorizedContext string    `json:"authorized_context,omitempty"`
	MaliciousIntent   bool      `json:"malicious_intent,omitempty"`
	Evidence          []string  `json:"evidence,omitempty"`
	Reason            string    `json:"reason,omitempty"`
	AuditError        string    `json:"audit_error,omitempty"`
	FailureClass      string    `json:"failure_class,omitempty"`
	RawAuditResponse  string    `json:"raw_audit_response,omitempty"`
}

// AuditLogListOptions controls audit-log listing.
type AuditLogListOptions struct {
	SessionID  string
	Decision   string
	PolicyCode string
	InputHash  string
	BeforeID   uint64
	Limit      int
}

// AuditLogPage is a paginated audit-log response.
type AuditLogPage struct {
	Items        []AuditLogEntry `json:"items"`
	HasMore      bool            `json:"has_more"`
	NextBeforeID uint64          `json:"next_before_id,omitempty"`
	Returned     int             `json:"returned"`
	Total        int             `json:"total"`
	CurrentBytes int64           `json:"current_bytes"`
	MaxBytes     int64           `json:"max_bytes"`
}

// AuditLogStore is an append-only JSONL audit-log store with byte-size retention.
type AuditLogStore struct {
	mu           sync.Mutex
	maxBytes     int64
	filePath     string
	loaded       bool
	nextID       uint64
	currentBytes int64
	logs         []AuditLogEntry // oldest -> newest
}

var defaultAuditLogStore = NewAuditLogStore(defaultAuditLogMaxBytes)

// DefaultAuditLogStore returns the process-wide audit-log store.
func DefaultAuditLogStore() *AuditLogStore {
	return defaultAuditLogStore
}

// ConfigureDefaultAuditLogStore enables audit-log JSONL persistence for the process-wide store.
func ConfigureDefaultAuditLogStore(filePath string) error {
	return defaultAuditLogStore.ConfigurePersistence(filePath, defaultAuditLogMaxBytes)
}

// NewAuditLogStore creates an audit-log store. maxBytes <= 0 disables in-memory byte-size trimming.
func NewAuditLogStore(maxBytes int64) *AuditLogStore {
	return &AuditLogStore{maxBytes: maxBytes}
}

// ConfigurePersistence enables JSONL file persistence for the audit-log store.
// maxBytes <= 0 uses the default 100MB retention cap.
func (s *AuditLogStore) ConfigurePersistence(filePath string, maxBytes int64) error {
	if s == nil {
		return nil
	}
	filePath = strings.TrimSpace(filePath)
	if filePath != "" && !filepath.IsAbs(filePath) {
		if abs, err := filepath.Abs(filePath); err == nil {
			filePath = abs
		}
	}
	if maxBytes <= 0 {
		maxBytes = defaultAuditLogMaxBytes
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.filePath = filePath
	s.maxBytes = maxBytes
	s.loaded = false
	s.nextID = 0
	s.currentBytes = 0
	s.logs = nil
	if strings.TrimSpace(s.filePath) == "" {
		return nil
	}
	if err := s.ensureLoadedLocked(); err != nil {
		return err
	}
	if s.currentBytes > s.maxBytes {
		if err := s.enforceMaxBytesLocked(); err != nil {
			return err
		}
	}
	return nil
}

// RecordAuditLog appends one audit-log entry and enforces byte-size retention.
func (s *AuditLogStore) RecordAuditLog(entry AuditLogEntry) AuditLogEntry {
	if s == nil {
		return AuditLogEntry{}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	entry = sanitizeAuditLogEntry(entry)
	if strings.TrimSpace(s.filePath) == "" {
		s.nextID++
		entry.ID = s.nextID
		s.logs = append(s.logs, entry)
		lineSize := auditLogLineSize(entry)
		s.currentBytes += lineSize
		if err := s.enforceMaxBytesLocked(); err != nil {
			log.WithError(err).Warn("risk control: failed to trim audit-log store")
		}
		return cloneAuditLogEntry(entry)
	}

	if err := s.ensureLoadedLocked(); err != nil {
		log.WithError(err).Warn("risk control: failed to prepare audit-log store before record")
		return cloneAuditLogEntry(entry)
	}

	entry.ID = s.nextID + 1
	lineSize := auditLogLineSize(entry)
	if err := s.appendLocked(entry); err != nil {
		log.WithError(err).Warn("risk control: failed to append audit-log store")
		return cloneAuditLogEntry(entry)
	}
	s.nextID = entry.ID
	s.currentBytes += lineSize
	if err := s.enforceMaxBytesLocked(); err != nil {
		log.WithError(err).Warn("risk control: failed to trim audit-log store")
	}
	return cloneAuditLogEntry(entry)
}

// ListAuditLogs returns audit logs in reverse chronological order.
func (s *AuditLogStore) ListAuditLogs(opts AuditLogListOptions) AuditLogPage {
	page := AuditLogPage{}
	if s == nil {
		return page
	}

	limit := opts.Limit
	if limit <= 0 {
		limit = defaultAuditLogPageLimit
	}
	if limit > maxAuditLogPageLimit {
		limit = maxAuditLogPageLimit
	}
	sessionNeedle := strings.ToLower(strings.TrimSpace(opts.SessionID))
	decisionNeedle := strings.ToLower(strings.TrimSpace(opts.Decision))
	policyNeedle := normalizePolicyCode(opts.PolicyCode)
	inputHashNeedle := strings.ToLower(strings.TrimSpace(opts.InputHash))

	s.mu.Lock()
	var (
		snapshot []AuditLogEntry
		errLoad  error
	)
	if strings.TrimSpace(s.filePath) == "" {
		snapshot = cloneAuditLogEntries(s.logs)
		page.CurrentBytes = s.currentBytes
		page.MaxBytes = s.maxBytes
	} else {
		snapshot, page.CurrentBytes, errLoad = s.loadPersistentEntriesLocked()
		page.MaxBytes = s.maxBytes
	}
	s.mu.Unlock()
	if errLoad != nil {
		log.WithError(errLoad).Warn("risk control: failed to load audit-log store for listing")
	}

	page.Items = make([]AuditLogEntry, 0, minInt(limit, len(snapshot)))
	for i := len(snapshot) - 1; i >= 0; i-- {
		entry := snapshot[i]
		if entry.ID == 0 {
			continue
		}
		if opts.BeforeID > 0 && entry.ID >= opts.BeforeID {
			continue
		}
		if sessionNeedle != "" && !strings.Contains(strings.ToLower(entry.SessionID), sessionNeedle) {
			continue
		}
		if decisionNeedle != "" && decisionNeedle != "all" && strings.ToLower(entry.Decision) != decisionNeedle {
			continue
		}
		if policyNeedle != "" && policyNeedle != "none" && entry.PolicyCode != policyNeedle {
			continue
		}
		if inputHashNeedle != "" && !strings.Contains(strings.ToLower(entry.InputHash), inputHashNeedle) {
			continue
		}
		page.Total++
		if len(page.Items) < limit {
			page.Items = append(page.Items, entry)
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

func (s *AuditLogStore) ensureLoadedLocked() error {
	if s.loaded {
		return nil
	}
	s.nextID = 0
	s.currentBytes = 0

	if strings.TrimSpace(s.filePath) == "" {
		s.loaded = true
		return nil
	}

	info, err := os.Stat(s.filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			s.loaded = true
			return nil
		}
		return err
	}
	s.currentBytes = info.Size()
	line, err := readLastNonEmptyLine(s.filePath)
	if err != nil {
		return fmt.Errorf("read audit-log tail: %w", err)
	}
	if len(line) == 0 {
		s.loaded = true
		return nil
	}
	var entry AuditLogEntry
	if err := json.Unmarshal(line, &entry); err != nil {
		return fmt.Errorf("decode audit-log tail: %w", err)
	}
	entry = sanitizeAuditLogEntry(entry)
	s.nextID = entry.ID
	s.loaded = true
	return nil
}

func (s *AuditLogStore) appendLocked(entry AuditLogEntry) error {
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

	raw, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	if _, err := file.Write(append(raw, '\n')); err != nil {
		return err
	}
	return nil
}

func (s *AuditLogStore) enforceMaxBytesLocked() error {
	if s.maxBytes <= 0 || s.currentBytes <= s.maxBytes {
		return nil
	}

	if strings.TrimSpace(s.filePath) == "" {
		var total int64
		start := len(s.logs)
		for i := len(s.logs) - 1; i >= 0; i-- {
			lineSize := auditLogLineSize(s.logs[i])
			if total > 0 && total+lineSize > s.maxBytes {
				break
			}
			total += lineSize
			start = i
		}
		if start < 0 {
			start = 0
		}
		if start > 0 {
			s.logs = append([]AuditLogEntry(nil), s.logs[start:]...)
			s.currentBytes = total
		}
		return nil
	}

	entries, currentBytes, err := s.loadPersistentEntriesLocked()
	if err != nil {
		return err
	}
	if currentBytes <= s.maxBytes {
		return nil
	}

	var total int64
	start := len(entries)
	for i := len(entries) - 1; i >= 0; i-- {
		lineSize := auditLogLineSize(entries[i])
		if total > 0 && total+lineSize > s.maxBytes {
			break
		}
		total += lineSize
		start = i
	}
	if start < 0 {
		start = 0
	}
	if start > 0 {
		entries = append([]AuditLogEntry(nil), entries[start:]...)
	}
	s.currentBytes = total
	return s.rewriteAllLocked(entries)
}

func (s *AuditLogStore) loadPersistentEntriesLocked() ([]AuditLogEntry, int64, error) {
	if strings.TrimSpace(s.filePath) == "" {
		return cloneAuditLogEntries(s.logs), s.currentBytes, nil
	}

	entries := make([]AuditLogEntry, 0, 128)
	var (
		maxID        uint64
		currentBytes int64
	)
	err := scanJSONLFile(s.filePath, func(line []byte) error {
		var entry AuditLogEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			return fmt.Errorf("decode audit-log jsonl: %w", err)
		}
		entry = sanitizeAuditLogEntry(entry)
		if entry.ID > maxID {
			maxID = entry.ID
		}
		entries = append(entries, entry)
		currentBytes += auditLogLineSize(entry)
		return nil
	})
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			s.nextID = 0
			s.currentBytes = 0
			return nil, 0, nil
		}
		return nil, 0, err
	}
	s.loaded = true
	s.nextID = maxID
	s.currentBytes = currentBytes
	return entries, currentBytes, nil
}

func (s *AuditLogStore) rewriteAllLocked(entries []AuditLogEntry) error {
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
	for _, entry := range entries {
		raw, err := json.Marshal(entry)
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

func sanitizeAuditLogEntry(entry AuditLogEntry) AuditLogEntry {
	entry.Provider = strings.TrimSpace(entry.Provider)
	if entry.Provider == "" {
		entry.Provider = "codex"
	}
	if entry.AuditedAt.IsZero() {
		entry.AuditedAt = time.Now().UTC()
	} else {
		entry.AuditedAt = entry.AuditedAt.UTC()
	}
	entry.SessionID = strings.TrimSpace(entry.SessionID)
	entry.RequestedModel = strings.TrimSpace(entry.RequestedModel)
	entry.UpstreamModel = strings.TrimSpace(entry.UpstreamModel)
	entry.AuditModel = strings.TrimSpace(entry.AuditModel)
	entry.AuditEndpoint = strings.TrimSpace(entry.AuditEndpoint)
	entry.Mode = strings.TrimSpace(entry.Mode)
	entry.SourceFormat = strings.TrimSpace(entry.SourceFormat)
	entry.RequestPath = strings.TrimSpace(entry.RequestPath)
	entry.InputHash = strings.TrimSpace(entry.InputHash)
	entry.Decision = normalizeAuditLogDecision(entry.Decision, entry)
	entry.PolicyCode = normalizePolicyCode(entry.PolicyCode)
	entry.SubcategoryCode = normalizeSubcategoryCode(entry.SubcategoryCode)
	entry.AuthorizedContext = normalizeAuthorizedContext(entry.AuthorizedContext)
	entry.UserTextPreview = truncateAuditLogRunes(strings.TrimSpace(entry.UserTextPreview), auditLogUserTextPreviewLimit)
	entry.Reason = truncateAuditLogRunes(strings.TrimSpace(entry.Reason), auditLogReasonLimit)
	entry.AuditError = truncateAuditLogRunes(strings.TrimSpace(entry.AuditError), auditLogErrorLimit)
	entry.FailureClass = truncateAuditLogRunes(strings.TrimSpace(entry.FailureClass), auditLogReasonLimit)
	entry.RawAuditResponse = truncateAuditLogRunes(strings.TrimSpace(entry.RawAuditResponse), auditLogRawResponseLimit)
	entry.ImageReferences = cloneStrings(entry.ImageReferences)
	entry.Evidence = sanitizeAuditLogEvidence(entry.Evidence)
	return entry
}

func normalizeAuditLogDecision(raw string, entry AuditLogEntry) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "allow":
		return "allow"
	case "block":
		return "block"
	case "observe":
		return "observe"
	case "error":
		return "error"
	}
	if strings.TrimSpace(entry.AuditError) != "" || strings.TrimSpace(entry.FailureClass) != "" {
		return "error"
	}
	if entry.Blocked {
		return "block"
	}
	if entry.ObserveOnly {
		return "observe"
	}
	return "allow"
}

func sanitizeAuditLogEvidence(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	limit := len(values)
	if limit > 2 {
		limit = 2
	}
	out := make([]string, 0, limit)
	for _, value := range values[:limit] {
		value = truncateAuditLogRunes(strings.TrimSpace(value), auditLogEvidenceLimit)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func auditLogLineSize(entry AuditLogEntry) int64 {
	raw, err := json.Marshal(entry)
	if err != nil {
		return 1
	}
	return int64(len(raw) + 1)
}

func cloneAuditLogEntries(entries []AuditLogEntry) []AuditLogEntry {
	if len(entries) == 0 {
		return nil
	}
	out := make([]AuditLogEntry, len(entries))
	for i := range entries {
		out[i] = cloneAuditLogEntry(entries[i])
	}
	return out
}

func cloneAuditLogEntry(entry AuditLogEntry) AuditLogEntry {
	entry.ImageReferences = cloneStrings(entry.ImageReferences)
	entry.Evidence = cloneStrings(entry.Evidence)
	return entry
}

func truncateAuditLogRunes(value string, limit int) string {
	if limit <= 0 || value == "" {
		return ""
	}
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit]) + "...[truncated]"
}
