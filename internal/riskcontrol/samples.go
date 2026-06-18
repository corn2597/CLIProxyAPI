package riskcontrol

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	SampleShouldAllow = "should_allow"
	SampleShouldBlock = "should_block"
)

const (
	SampleLabelStatusUnlabeled = "unlabeled"
	SampleLabelStatusAllow     = "allow"
	SampleLabelStatusBlock     = "block"
	SampleLabelStatusConflict  = "conflict"
)

type SampleRecord struct {
	ID                uint64    `json:"id"`
	LabeledAt         time.Time `json:"labeled_at"`
	Label             string    `json:"label"`
	Action            string    `json:"action,omitempty"`
	SampleKey         string    `json:"sample_key,omitempty"`
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

type SampleStatus struct {
	LabelStatus     string    `json:"label_status"`
	SampleID        uint64    `json:"sample_id,omitempty"`
	SampleKey       string    `json:"sample_key,omitempty"`
	SampleLabel     string    `json:"sample_label,omitempty"`
	SampleAction    string    `json:"sample_action,omitempty"`
	SampleLabeledAt time.Time `json:"sample_labeled_at,omitempty"`
	SampleConflict  bool      `json:"sample_conflict,omitempty"`
}

type SampleLabelConflictError struct {
	SampleKey string
	Existing  SampleRecord
	Incoming  SampleRecord
}

func (e *SampleLabelConflictError) Error() string {
	if e == nil {
		return "risk control sample label conflict"
	}
	return fmt.Sprintf("risk control sample label conflict for key %q: existing=%s incoming=%s", e.SampleKey, e.Existing.Label, e.Incoming.Label)
}

type SampleStore struct {
	mu          sync.Mutex
	filePath    string
	loaded      bool
	nextID      uint64
	records     []SampleRecord
	labelsByKey map[string]map[string]SampleRecord
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
	s.records = nil
	s.labelsByKey = nil
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
	if record.SampleKey == "" {
		record.SampleKey = sampleKeyFromRecord(record)
	}
	s.nextID++
	record.ID = s.nextID
	s.records = append(s.records, record)
	s.indexSampleLocked(record)
	if err := s.appendLocked(record); err != nil {
		return SampleRecord{}, err
	}
	return record, nil
}

func (s *SampleStore) Upsert(record SampleRecord) (SampleRecord, bool, error) {
	if s == nil {
		return record, false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureLoadedLocked(); err != nil {
		return SampleRecord{}, false, err
	}
	record = sanitizeSample(record)
	if record.SampleKey == "" {
		record.SampleKey = sampleKeyFromRecord(record)
	}
	if record.SampleKey != "" {
		if labels := s.labelsByKey[record.SampleKey]; len(labels) > 0 {
			if len(labels) > 1 {
				return SampleRecord{}, false, &SampleLabelConflictError{
					SampleKey: record.SampleKey,
					Existing:  cloneSampleRecord(latestSample(labels)),
					Incoming:  cloneSampleRecord(record),
				}
			}
			if existing, ok := labels[record.Label]; ok {
				return cloneSampleRecord(existing), true, nil
			}
			for _, existing := range labels {
				return SampleRecord{}, false, &SampleLabelConflictError{
					SampleKey: record.SampleKey,
					Existing:  cloneSampleRecord(existing),
					Incoming:  cloneSampleRecord(record),
				}
			}
		}
	}
	s.nextID++
	record.ID = s.nextID
	s.records = append(s.records, record)
	s.indexSampleLocked(record)
	if err := s.appendLocked(record); err != nil {
		return SampleRecord{}, false, err
	}
	return cloneSampleRecord(record), false, nil
}

func (s *SampleStore) StatusForBlockEvent(event BlockEvent) (SampleStatus, error) {
	status := SampleStatus{
		LabelStatus: SampleLabelStatusUnlabeled,
		SampleKey:   SampleKeyForBlockEvent(event),
	}
	if s == nil {
		return status, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureLoadedLocked(); err != nil {
		return status, err
	}
	return s.statusForKeyLocked(status.SampleKey), nil
}

func (s *SampleStore) AnnotateBlockEvents(events []BlockEvent) ([]BlockEvent, error) {
	if len(events) == 0 || s == nil {
		return events, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureLoadedLocked(); err != nil {
		return events, err
	}
	for i := range events {
		status := s.statusForKeyLocked(SampleKeyForBlockEvent(events[i]))
		events[i] = applySampleStatus(events[i], status)
	}
	return events, nil
}

func NewSampleRecordFromBlockEvent(event BlockEvent, label string, action string, now time.Time) SampleRecord {
	return sanitizeSample(SampleRecord{
		LabeledAt:         now,
		Label:             label,
		Action:            action,
		SampleKey:         SampleKeyForBlockEvent(event),
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
	records := make([]SampleRecord, 0, 32)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var record SampleRecord
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			return err
		}
		record = sanitizeSample(record)
		if record.SampleKey == "" {
			record.SampleKey = sampleKeyFromRecord(record)
		}
		if record.ID > maxID {
			maxID = record.ID
		}
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	s.nextID = maxID
	s.records = records
	s.rebuildIndexLocked()
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
	record.SampleKey = strings.TrimSpace(record.SampleKey)
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

func (s *SampleStore) rebuildIndexLocked() {
	s.labelsByKey = make(map[string]map[string]SampleRecord)
	for _, record := range s.records {
		s.indexSampleLocked(record)
	}
}

func (s *SampleStore) indexSampleLocked(record SampleRecord) {
	if s.labelsByKey == nil {
		s.labelsByKey = make(map[string]map[string]SampleRecord)
	}
	key := strings.TrimSpace(record.SampleKey)
	if key == "" {
		return
	}
	label := strings.TrimSpace(record.Label)
	if label == "" {
		return
	}
	if s.labelsByKey[key] == nil {
		s.labelsByKey[key] = make(map[string]SampleRecord)
	}
	existing, ok := s.labelsByKey[key][label]
	if !ok || record.ID >= existing.ID {
		s.labelsByKey[key][label] = cloneSampleRecord(record)
	}
}

func (s *SampleStore) statusForKeyLocked(key string) SampleStatus {
	status := SampleStatus{
		LabelStatus: SampleLabelStatusUnlabeled,
		SampleKey:   strings.TrimSpace(key),
	}
	if status.SampleKey == "" {
		return status
	}
	labels := s.labelsByKey[status.SampleKey]
	if len(labels) == 0 {
		return status
	}
	labelNames := make([]string, 0, len(labels))
	for label := range labels {
		labelNames = append(labelNames, label)
	}
	sort.Strings(labelNames)
	if len(labelNames) > 1 {
		status.LabelStatus = SampleLabelStatusConflict
		status.SampleConflict = true
		latest := latestSample(labels)
		status.SampleID = latest.ID
		status.SampleLabel = latest.Label
		status.SampleAction = latest.Action
		status.SampleLabeledAt = latest.LabeledAt
		return status
	}
	record := labels[labelNames[0]]
	status.SampleID = record.ID
	status.SampleLabel = record.Label
	status.SampleAction = record.Action
	status.SampleLabeledAt = record.LabeledAt
	switch record.Label {
	case SampleShouldAllow:
		status.LabelStatus = SampleLabelStatusAllow
	case SampleShouldBlock:
		status.LabelStatus = SampleLabelStatusBlock
	default:
		status.LabelStatus = record.Label
	}
	return status
}

func latestSample(labels map[string]SampleRecord) SampleRecord {
	var latest SampleRecord
	for _, record := range labels {
		if record.ID >= latest.ID {
			latest = record
		}
	}
	return latest
}

func SampleKeyForBlockEvent(event BlockEvent) string {
	return sampleKey(event.InputHash, event.UserTextPreview, event.ImageReferences, event.ID)
}

func sampleKeyFromRecord(record SampleRecord) string {
	return sampleKey(record.InputHash, record.UserText, record.ImageReferences, record.SourceBlockedID)
}

func sampleKey(inputHash string, text string, images []string, sourceID uint64) string {
	inputHash = strings.TrimSpace(inputHash)
	if inputHash != "" {
		return inputHash
	}
	text = strings.TrimSpace(text)
	cleanImages := cloneStrings(images)
	if text != "" || len(cleanImages) > 0 {
		hash := sha256.New()
		_, _ = hash.Write([]byte(text))
		for _, image := range cleanImages {
			_, _ = hash.Write([]byte{0})
			_, _ = hash.Write([]byte(strings.TrimSpace(image)))
		}
		return "body:" + hex.EncodeToString(hash.Sum(nil))
	}
	if sourceID > 0 {
		return fmt.Sprintf("source:%d", sourceID)
	}
	return ""
}

func applySampleStatus(event BlockEvent, status SampleStatus) BlockEvent {
	event.LabelStatus = status.LabelStatus
	event.SampleID = status.SampleID
	event.SampleKey = status.SampleKey
	event.SampleLabel = status.SampleLabel
	event.SampleAction = status.SampleAction
	event.SampleLabeledAt = status.SampleLabeledAt
	event.SampleConflict = status.SampleConflict
	return event
}

func cloneSampleRecord(record SampleRecord) SampleRecord {
	record.ImageReferences = cloneStrings(record.ImageReferences)
	record.Evidence = cloneStrings(record.Evidence)
	return record
}
