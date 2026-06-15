package riskcontrol

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	SampleShouldAllow = "should_allow"
	SampleShouldBlock = "should_block"
)

type SampleRecord struct {
	ID                uint64    `json:"id"`
	LabeledAt         time.Time `json:"labeled_at"`
	Label             string    `json:"label"`
	Action            string    `json:"action,omitempty"`
	SourceBlockedID   uint64    `json:"source_blocked_id"`
	SessionID         string    `json:"session_id,omitempty"`
	InputHash         string    `json:"input_hash,omitempty"`
	UserText          string    `json:"user_text,omitempty"`
	ImageReferences   []string  `json:"image_references,omitempty"`
	PolicyCode        string    `json:"policy_code,omitempty"`
	SubcategoryCode   string    `json:"subcategory_code,omitempty"`
	Confidence        float64   `json:"confidence,omitempty"`
	AuthorizedContext string    `json:"authorized_context,omitempty"`
	MaliciousIntent   bool      `json:"malicious_intent,omitempty"`
	Evidence          []string  `json:"evidence,omitempty"`
	Reason            string    `json:"reason,omitempty"`
	AuditModel        string    `json:"audit_model,omitempty"`
	AuditEndpoint     string    `json:"audit_endpoint,omitempty"`
	RawAuditResponse  string    `json:"raw_audit_response,omitempty"`
}

type SampleStore struct {
	mu       sync.Mutex
	filePath string
	loaded   bool
	nextID   uint64
}

var defaultSampleStore = NewSampleStore()

func DefaultSampleStore() *SampleStore {
	return defaultSampleStore
}

func ConfigureDefaultSampleStore(filePath string) error {
	return defaultSampleStore.ConfigurePersistence(filePath)
}

func NewSampleStore() *SampleStore {
	return &SampleStore{}
}

func (s *SampleStore) ConfigurePersistence(filePath string) error {
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
	return s.ensureLoadedLocked()
}

func (s *SampleStore) Append(record SampleRecord) (SampleRecord, error) {
	if s == nil {
		return record, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureLoadedLocked(); err != nil {
		return SampleRecord{}, err
	}
	record = sanitizeSample(record)
	s.nextID++
	record.ID = s.nextID
	if err := s.appendLocked(record); err != nil {
		return SampleRecord{}, err
	}
	return record, nil
}

func NewSampleRecordFromBlockEvent(event BlockEvent, label string, action string, now time.Time) SampleRecord {
	return sanitizeSample(SampleRecord{
		LabeledAt:         now,
		Label:             label,
		Action:            action,
		SourceBlockedID:   event.ID,
		SessionID:         event.SessionID,
		InputHash:         event.InputHash,
		UserText:          event.UserTextPreview,
		ImageReferences:   cloneStrings(event.ImageReferences),
		PolicyCode:        event.PolicyCode,
		SubcategoryCode:   event.SubcategoryCode,
		Confidence:        event.Confidence,
		AuthorizedContext: event.AuthorizedContext,
		MaliciousIntent:   event.MaliciousIntent,
		Evidence:          cloneStrings(event.Evidence),
		Reason:            event.Reason,
		AuditModel:        event.AuditModel,
		AuditEndpoint:     event.AuditEndpoint,
		RawAuditResponse:  event.RawAuditResponse,
	})
}

func (s *SampleStore) ensureLoadedLocked() error {
	if s.loaded {
		return nil
	}
	s.loaded = true
	if strings.TrimSpace(s.filePath) == "" {
		return nil
	}
	file, err := os.Open(s.filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 4<<20)
	var maxID uint64
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var record SampleRecord
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			return err
		}
		if record.ID > maxID {
			maxID = record.ID
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	s.nextID = maxID
	return nil
}

func (s *SampleStore) appendLocked(record SampleRecord) error {
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

	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if _, err := file.Write(append(raw, '\n')); err != nil {
		return err
	}
	return nil
}

func sanitizeSample(record SampleRecord) SampleRecord {
	record.Label = strings.TrimSpace(record.Label)
	record.Action = strings.TrimSpace(record.Action)
	record.SessionID = strings.TrimSpace(record.SessionID)
	record.InputHash = strings.TrimSpace(record.InputHash)
	record.UserText = strings.TrimSpace(record.UserText)
	record.PolicyCode = normalizePolicyCode(record.PolicyCode)
	record.SubcategoryCode = normalizeSubcategoryCode(record.SubcategoryCode)
	record.AuthorizedContext = normalizeAuthorizedContext(record.AuthorizedContext)
	record.Reason = strings.TrimSpace(record.Reason)
	record.AuditModel = strings.TrimSpace(record.AuditModel)
	record.AuditEndpoint = strings.TrimSpace(record.AuditEndpoint)
	record.RawAuditResponse = strings.TrimSpace(record.RawAuditResponse)
	record.ImageReferences = cloneStrings(record.ImageReferences)
	record.Evidence = cloneStrings(record.Evidence)
	if record.LabeledAt.IsZero() {
		record.LabeledAt = time.Now().UTC()
	} else {
		record.LabeledAt = record.LabeledAt.UTC()
	}
	return record
}
