package riskcontrol

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

const (
	defaultAuditSpoolCleanupAge = 24 * time.Hour
	auditSummaryTextLimit       = auditLogUserTextPreviewLimit
	auditSummaryFocusTextLimit  = 2048
	auditSummaryImageLimit      = 8
)

type auditRecordMeta struct {
	RequestedModel string
	UpstreamModel  string
	SourceFormat   string
	RequestPath    string
}

type auditSpoolRef struct {
	FilePath string `json:"file_path,omitempty"`
}

type auditSpoolRecord struct {
	CreatedAt time.Time  `json:"created_at"`
	Input     AuditInput `json:"input"`
}

type AuditSpoolStore struct {
	mu          sync.Mutex
	dir         string
	cleanupAge  time.Duration
	cleanupDone bool
}

var defaultAuditSpoolStore = NewAuditSpoolStore()

func NewAuditSpoolStore() *AuditSpoolStore {
	return &AuditSpoolStore{cleanupAge: defaultAuditSpoolCleanupAge}
}

func ConfigureDefaultAuditSpoolStore(dir string) error {
	return defaultAuditSpoolStore.Configure(dir)
}

func (s *AuditSpoolStore) Configure(dir string) error {
	if s == nil {
		return nil
	}
	dir = strings.TrimSpace(dir)
	if dir != "" && !filepath.IsAbs(dir) {
		if abs, err := filepath.Abs(dir); err == nil {
			dir = abs
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.dir = dir
	s.cleanupDone = false
	if dir == "" {
		return nil
	}
	return os.MkdirAll(dir, 0o755)
}

func (s *AuditSpoolStore) Store(input AuditInput) (auditSpoolRef, error) {
	if s == nil {
		return auditSpoolRef{}, fmt.Errorf("risk control audit spool store unavailable")
	}
	dir, err := s.ensureDir()
	if err != nil {
		return auditSpoolRef{}, err
	}

	file, err := os.CreateTemp(dir, "audit-*.json")
	if err != nil {
		return auditSpoolRef{}, err
	}
	path := file.Name()

	record := auditSpoolRecord{
		CreatedAt: time.Now().UTC(),
		Input:     cloneAuditInput(input),
	}
	raw, err := json.Marshal(record)
	if err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return auditSpoolRef{}, err
	}
	if _, err := file.Write(raw); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return auditSpoolRef{}, err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return auditSpoolRef{}, err
	}
	return auditSpoolRef{FilePath: path}, nil
}

func (s *AuditSpoolStore) Load(ref auditSpoolRef) (AuditInput, error) {
	path := strings.TrimSpace(ref.FilePath)
	if path == "" {
		return AuditInput{}, fmt.Errorf("risk control audit spool reference missing path")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return AuditInput{}, err
	}
	var record auditSpoolRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return AuditInput{}, fmt.Errorf("decode audit spool record: %w", err)
	}
	return cloneAuditInput(record.Input), nil
}

func (s *AuditSpoolStore) Remove(ref auditSpoolRef) {
	path := strings.TrimSpace(ref.FilePath)
	if path == "" {
		return
	}
	_ = os.Remove(path)
}

func (s *AuditSpoolStore) ensureDir() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cleanupAge <= 0 {
		s.cleanupAge = defaultAuditSpoolCleanupAge
	}
	if strings.TrimSpace(s.dir) == "" {
		s.dir = filepath.Join(os.TempDir(), "cli-proxy-api-risk-control", "audit-spool")
	}
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return "", err
	}
	if !s.cleanupDone {
		cleanupAuditSpoolDir(s.dir, s.cleanupAge)
		s.cleanupDone = true
	}
	return s.dir, nil
}

func cleanupAuditSpoolDir(dir string, maxAge time.Duration) {
	if maxAge <= 0 || strings.TrimSpace(dir) == "" {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-maxAge)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			_ = os.Remove(filepath.Join(dir, entry.Name()))
		}
	}
}

func newAuditRecordMeta(req executor.Request, opts executor.Options) auditRecordMeta {
	requestedModel := metadataString(opts.Metadata, executor.RequestedModelMetadataKey)
	if requestedModel == "" {
		requestedModel = metadataString(req.Metadata, executor.RequestedModelMetadataKey)
	}
	if requestedModel == "" {
		requestedModel = req.Model
	}

	requestPath := metadataString(opts.Metadata, executor.RequestPathMetadataKey)
	if requestPath == "" {
		requestPath = metadataString(req.Metadata, executor.RequestPathMetadataKey)
	}

	return auditRecordMeta{
		RequestedModel: strings.TrimSpace(requestedModel),
		UpstreamModel:  strings.TrimSpace(req.Model),
		SourceFormat:   strings.TrimSpace(opts.SourceFormat.String()),
		RequestPath:    strings.TrimSpace(requestPath),
	}
}

func summarizeAuditInput(input AuditInput) AuditInput {
	summary := cloneAuditInput(input)
	summary.Text = truncateAuditLogRunes(strings.TrimSpace(summary.Text), auditSummaryTextLimit)
	summary.FocusText = truncateAuditLogRunes(strings.TrimSpace(summary.FocusText), auditSummaryFocusTextLimit)
	summary.FocusStatus = strings.TrimSpace(summary.FocusStatus)
	summary.FocusReason = truncateAuditLogRunes(strings.TrimSpace(summary.FocusReason), auditLogReasonLimit)
	if len(summary.Images) > auditSummaryImageLimit {
		summary.Images = append([]string(nil), summary.Images[:auditSummaryImageLimit]...)
	}
	return summary
}

func cloneAuditInput(input AuditInput) AuditInput {
	input.Images = cloneStrings(input.Images)
	return input
}
