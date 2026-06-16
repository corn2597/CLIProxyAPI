package management

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/riskcontrol"
)

func TestGetRiskControlBlocksReturnsPaginatedEvents(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	store := riskcontrol.NewBlockEventStore(8)
	store.RecordBlockedEvent(riskcontrol.BlockEvent{
		BlockedAt:      time.Date(2026, 6, 10, 10, 0, 0, 0, time.UTC),
		SessionID:      "execution:session-one",
		Reason:         "reason-one",
		DecisionSource: riskcontrol.DecisionSourceFreshAudit,
	})
	event := store.RecordBlockedEvent(riskcontrol.BlockEvent{
		BlockedAt:      time.Date(2026, 6, 10, 10, 1, 0, 0, time.UTC),
		SessionID:      "execution:session-two",
		InputHash:      "hash-two",
		Reason:         "reason-two",
		DecisionSource: riskcontrol.DecisionSourceCache,
	})
	samples := riskcontrol.NewSampleStore()
	if err := samples.ConfigurePersistence(filepath.Join(t.TempDir(), "samples.jsonl")); err != nil {
		t.Fatalf("ConfigurePersistence(samples): %v", err)
	}
	if _, _, err := samples.Upsert(riskcontrol.NewSampleRecordFromBlockEvent(event, riskcontrol.SampleShouldAllow, "allow_session", time.Now().UTC())); err != nil {
		t.Fatalf("Upsert sample: %v", err)
	}

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/v0/management/risk-control/blocks?session_id=session-two&limit=1", nil)

	h := &Handler{riskBlockStore: store, riskSampleStore: samples}
	h.GetRiskControlBlocks(c)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var payload struct {
		Items    []riskcontrol.BlockEvent `json:"items"`
		Returned int                      `json:"returned"`
		Total    int                      `json:"total"`
		HasMore  bool                     `json:"has_more"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rec.Body.String())
	}
	if payload.Returned != 1 || payload.Total != 1 {
		t.Fatalf("Returned/Total = %d/%d, want 1/1", payload.Returned, payload.Total)
	}
	if payload.HasMore {
		t.Fatal("HasMore = true, want false")
	}
	if len(payload.Items) != 1 || payload.Items[0].SessionID != "execution:session-two" {
		t.Fatalf("items = %#v, want filtered latest session-two event", payload.Items)
	}
	if payload.Items[0].LabelStatus != riskcontrol.SampleLabelStatusAllow || payload.Items[0].SampleLabel != riskcontrol.SampleShouldAllow {
		t.Fatalf("sample status = %q/%q, want allow/%q", payload.Items[0].LabelStatus, payload.Items[0].SampleLabel, riskcontrol.SampleShouldAllow)
	}
}

func TestGetRiskControlPageServesStandaloneHTML(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/v0/management/risk-control/page", nil)

	h := &Handler{}
	h.GetRiskControlPage(c)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if contentType := rec.Header().Get("Content-Type"); !strings.Contains(contentType, "text/html") {
		t.Fatalf("Content-Type = %q, want text/html", contentType)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"Risk Control Blocks",
		"/v0/management/risk-control/blocks",
		"/v0/management/risk-control/observations",
		"/v0/management/risk-control/logs",
		"Load older",
		"Observe",
		"Logs",
		"Audit logs",
		"Audited At",
		"Observe-only audit events",
		"Observe ALLOW label saved",
		"Observe BLOCK label saved",
		"status-success",
		"status-error",
		"readResponsePayload",
		"Allow session succeeded",
		"Confirm block succeeded",
		"Action failed for event",
		"Label status",
		"Unlabeled",
		"Existing sample reused",
		"label_status",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("page body missing %q", want)
		}
	}
}

func TestGetRiskControlLogsReturnsPaginatedAuditLogs(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	store := riskcontrol.NewAuditLogStore(64 * 1024)
	store.RecordAuditLog(riskcontrol.AuditLogEntry{
		AuditedAt:       time.Date(2026, 6, 16, 10, 0, 0, 0, time.UTC),
		SessionID:       "execution:log-one",
		Decision:        "allow",
		UserTextPreview: "safe request",
	})
	store.RecordAuditLog(riskcontrol.AuditLogEntry{
		AuditedAt:       time.Date(2026, 6, 16, 10, 1, 0, 0, time.UTC),
		SessionID:       "execution:log-two",
		Decision:        "block",
		PolicyCode:      "malicious_cyber_abuse",
		SubcategoryCode: "reverse_cracking_or_drm_bypass",
		Confidence:      0.97,
		InputHash:       "hash-two",
		UserTextPreview: "逆向抖音app",
	})

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/v0/management/risk-control/logs?decision=block&session_id=log-two&limit=10", nil)

	h := &Handler{riskAuditLogStore: store}
	h.GetRiskControlLogs(c)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var payload struct {
		Items        []riskcontrol.AuditLogEntry `json:"items"`
		Returned     int                         `json:"returned"`
		Total        int                         `json:"total"`
		CurrentBytes int64                       `json:"current_bytes"`
		MaxBytes     int64                       `json:"max_bytes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rec.Body.String())
	}
	if payload.Returned != 1 || payload.Total != 1 {
		t.Fatalf("Returned/Total = %d/%d, want 1/1", payload.Returned, payload.Total)
	}
	if payload.Items[0].SessionID != "execution:log-two" || payload.Items[0].Decision != "block" {
		t.Fatalf("items = %#v, want block log-two", payload.Items)
	}
	if payload.CurrentBytes <= 0 || payload.MaxBytes <= 0 {
		t.Fatalf("CurrentBytes/MaxBytes = %d/%d, want positive sizes", payload.CurrentBytes, payload.MaxBytes)
	}
}

func TestGetRiskControlObservationsReturnsPaginatedEvents(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	store := riskcontrol.NewBlockEventStore(8)
	store.RecordBlockedEvent(riskcontrol.BlockEvent{
		BlockedAt:       time.Date(2026, 6, 10, 10, 0, 0, 0, time.UTC),
		SessionID:       "execution:observe-one",
		Reason:          "observe reason",
		DecisionSource:  riskcontrol.DecisionSourceObserveOnly,
		PolicyCode:      "malicious_cyber_abuse",
		SubcategoryCode: "unauthorized_third_party_access",
	})

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/v0/management/risk-control/observations?limit=20", nil)

	h := &Handler{riskObserveStore: store}
	h.GetRiskControlObservations(c)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var payload struct {
		Items    []riskcontrol.BlockEvent `json:"items"`
		Returned int                      `json:"returned"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rec.Body.String())
	}
	if payload.Returned != 1 || len(payload.Items) != 1 {
		t.Fatalf("returned items = %d/%d, want 1/1", payload.Returned, len(payload.Items))
	}
	if payload.Items[0].DecisionSource != riskcontrol.DecisionSourceObserveOnly {
		t.Fatalf("DecisionSource = %q, want observe_only", payload.Items[0].DecisionSource)
	}
}

func TestPostRiskControlAllowOnceCreatesOverrideAndSample(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	store := riskcontrol.NewBlockEventStore(8)
	event := store.RecordBlockedEvent(riskcontrol.BlockEvent{
		BlockedAt:       time.Date(2026, 6, 10, 10, 0, 0, 0, time.UTC),
		SessionID:       "execution:session-one",
		InputHash:       "hash-one",
		UserTextPreview: "ssh root@example.com collect logs",
		DecisionSource:  riskcontrol.DecisionSourceFreshAudit,
		PolicyCode:      "malicious_cyber_abuse",
		SubcategoryCode: "unauthorized_third_party_access",
		Confidence:      0.99,
		Reason:          "blocked",
	})
	overrides := riskcontrol.NewOverrideStore()
	if err := overrides.ConfigurePersistence(filepath.Join(t.TempDir(), "overrides.json")); err != nil {
		t.Fatalf("ConfigurePersistence(overrides): %v", err)
	}
	samples := riskcontrol.NewSampleStore()
	if err := samples.ConfigurePersistence(filepath.Join(t.TempDir(), "samples.jsonl")); err != nil {
		t.Fatalf("ConfigurePersistence(samples): %v", err)
	}

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Params = gin.Params{{Key: "id", Value: "1"}}
	c.Request = httptest.NewRequest(http.MethodPost, "/v0/management/risk-control/blocks/1/allow-once", nil)

	h := &Handler{
		riskBlockStore:    store,
		riskOverrideStore: overrides,
		riskSampleStore:   samples,
	}
	h.PostRiskControlAllowOnce(c)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	if _, ok, err := overrides.Match(event.InputHash, "", time.Now().UTC()); err != nil {
		t.Fatalf("Match: %v", err)
	} else if !ok {
		t.Fatal("expected allow-once override to be persisted")
	}
}

func TestPostRiskControlAllowSessionCreatesOverrideAndSample(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	store := riskcontrol.NewBlockEventStore(8)
	store.RecordBlockedEvent(riskcontrol.BlockEvent{
		BlockedAt:       time.Date(2026, 6, 10, 10, 0, 0, 0, time.UTC),
		SessionID:       "execution:session-two",
		InputHash:       "hash-two",
		UserTextPreview: "quoted text",
		DecisionSource:  riskcontrol.DecisionSourceFreshAudit,
	})
	overrides := riskcontrol.NewOverrideStore()
	if err := overrides.ConfigurePersistence(filepath.Join(t.TempDir(), "overrides.json")); err != nil {
		t.Fatalf("ConfigurePersistence(overrides): %v", err)
	}
	samples := riskcontrol.NewSampleStore()
	if err := samples.ConfigurePersistence(filepath.Join(t.TempDir(), "samples.jsonl")); err != nil {
		t.Fatalf("ConfigurePersistence(samples): %v", err)
	}

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Params = gin.Params{{Key: "id", Value: "1"}}
	c.Request = httptest.NewRequest(http.MethodPost, "/v0/management/risk-control/blocks/1/allow-session", nil)

	h := &Handler{
		riskBlockStore:    store,
		riskOverrideStore: overrides,
		riskSampleStore:   samples,
		cfg:               &config.Config{RiskControl: config.RiskControlConfig{AllowSessionTTL: "30m"}},
	}
	h.PostRiskControlAllowSession(c)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	if _, ok, err := overrides.Match("", "execution:session-two", time.Now().UTC()); err != nil {
		t.Fatalf("Match: %v", err)
	} else if !ok {
		t.Fatal("expected session override to be persisted")
	}
	if _, ok, err := overrides.Match("", "execution:session-two", time.Now().UTC().Add(31*time.Minute)); err != nil {
		t.Fatalf("Match after TTL: %v", err)
	} else if ok {
		t.Fatal("session override should expire after configured TTL")
	}
}

func TestPostRiskControlObservationLabelsSamples(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	store := riskcontrol.NewBlockEventStore(8)
	store.RecordBlockedEvent(riskcontrol.BlockEvent{
		BlockedAt:       time.Date(2026, 6, 10, 10, 0, 0, 0, time.UTC),
		SessionID:       "execution:observe-two",
		InputHash:       "observe-hash-allow",
		UserTextPreview: "ssh root@example.com collect logs",
		DecisionSource:  riskcontrol.DecisionSourceObserveOnly,
		PolicyCode:      "malicious_cyber_abuse",
		SubcategoryCode: "unauthorized_third_party_access",
		Confidence:      0.99,
		Reason:          "observe only",
	})
	store.RecordBlockedEvent(riskcontrol.BlockEvent{
		BlockedAt:       time.Date(2026, 6, 10, 10, 1, 0, 0, time.UTC),
		SessionID:       "execution:observe-three",
		InputHash:       "observe-hash-block",
		UserTextPreview: "build malware",
		DecisionSource:  riskcontrol.DecisionSourceObserveOnly,
		PolicyCode:      "malicious_cyber_abuse",
		SubcategoryCode: "malware_or_evasion",
		Confidence:      0.99,
		Reason:          "observe only",
	})

	samplePath := filepath.Join(t.TempDir(), "samples.jsonl")
	samples := riskcontrol.NewSampleStore()
	if err := samples.ConfigurePersistence(samplePath); err != nil {
		t.Fatalf("ConfigurePersistence(samples): %v", err)
	}
	h := &Handler{
		riskObserveStore: store,
		riskSampleStore:  samples,
	}

	for _, tc := range []struct {
		name       string
		path       string
		id         string
		handler    func(*gin.Context)
		wantLabel  string
		wantAction string
	}{
		{
			name:       "allow",
			path:       "/v0/management/risk-control/observations/1/allow",
			id:         "1",
			handler:    h.PostRiskControlObservationAllow,
			wantLabel:  riskcontrol.SampleShouldAllow,
			wantAction: "observe_allow",
		},
		{
			name:       "block",
			path:       "/v0/management/risk-control/observations/2/block",
			id:         "2",
			handler:    h.PostRiskControlObservationBlock,
			wantLabel:  riskcontrol.SampleShouldBlock,
			wantAction: "observe_block",
		},
	} {
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Params = gin.Params{{Key: "id", Value: tc.id}}
		c.Request = httptest.NewRequest(http.MethodPost, tc.path, nil)
		tc.handler(c)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status = %d, want %d body=%s", tc.name, rec.Code, http.StatusOK, rec.Body.String())
		}

		var payload struct {
			Sample riskcontrol.SampleRecord `json:"sample"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
			t.Fatalf("%s decode response: %v body=%s", tc.name, err, rec.Body.String())
		}
		if payload.Sample.Label != tc.wantLabel || payload.Sample.Action != tc.wantAction {
			t.Fatalf("%s sample label/action = %q/%q, want %q/%q", tc.name, payload.Sample.Label, payload.Sample.Action, tc.wantLabel, tc.wantAction)
		}
	}

	raw, err := os.ReadFile(samplePath)
	if err != nil {
		t.Fatalf("read sample file: %v", err)
	}
	if got := strings.Count(strings.TrimSpace(string(raw)), "\n") + 1; got != 2 {
		t.Fatalf("sample line count = %d, want 2; file=%s", got, string(raw))
	}
}

func TestPostRiskControlConfirmBlockDedupesSample(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	store := riskcontrol.NewBlockEventStore(8)
	store.RecordBlockedEvent(riskcontrol.BlockEvent{
		BlockedAt:       time.Date(2026, 6, 10, 10, 0, 0, 0, time.UTC),
		SessionID:       "execution:block-dedupe",
		InputHash:       "block-dedupe-hash",
		UserTextPreview: "build malware",
		DecisionSource:  riskcontrol.DecisionSourceFreshAudit,
		PolicyCode:      "malicious_cyber_abuse",
		SubcategoryCode: "malware_or_evasion",
		Confidence:      0.99,
		Reason:          "blocked",
	})
	samplePath := filepath.Join(t.TempDir(), "samples.jsonl")
	samples := riskcontrol.NewSampleStore()
	if err := samples.ConfigurePersistence(samplePath); err != nil {
		t.Fatalf("ConfigurePersistence(samples): %v", err)
	}
	h := &Handler{riskBlockStore: store, riskSampleStore: samples}

	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Params = gin.Params{{Key: "id", Value: "1"}}
		c.Request = httptest.NewRequest(http.MethodPost, "/v0/management/risk-control/blocks/1/confirm-block", nil)
		h.PostRiskControlConfirmBlock(c)
		if rec.Code != http.StatusOK {
			t.Fatalf("attempt %d status = %d, want %d body=%s", i+1, rec.Code, http.StatusOK, rec.Body.String())
		}
		var payload struct {
			Deduped bool `json:"deduped"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
			t.Fatalf("attempt %d decode response: %v body=%s", i+1, err, rec.Body.String())
		}
		if i == 1 && !payload.Deduped {
			t.Fatal("second confirm-block should reuse existing sample")
		}
	}

	raw, err := os.ReadFile(samplePath)
	if err != nil {
		t.Fatalf("read sample file: %v", err)
	}
	if got := strings.Count(strings.TrimSpace(string(raw)), "\n") + 1; got != 1 {
		t.Fatalf("sample line count = %d, want 1; file=%s", got, string(raw))
	}
}

func TestPostRiskControlOppositeLabelReturnsConflict(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	store := riskcontrol.NewBlockEventStore(8)
	event := store.RecordBlockedEvent(riskcontrol.BlockEvent{
		BlockedAt:       time.Date(2026, 6, 10, 10, 0, 0, 0, time.UTC),
		SessionID:       "execution:conflict",
		InputHash:       "conflict-hash",
		UserTextPreview: "ssh root@example.com collect logs",
		DecisionSource:  riskcontrol.DecisionSourceFreshAudit,
		Reason:          "blocked",
	})
	samples := riskcontrol.NewSampleStore()
	if err := samples.ConfigurePersistence(filepath.Join(t.TempDir(), "samples.jsonl")); err != nil {
		t.Fatalf("ConfigurePersistence(samples): %v", err)
	}
	if _, _, err := samples.Upsert(riskcontrol.NewSampleRecordFromBlockEvent(event, riskcontrol.SampleShouldAllow, "allow_session", time.Now().UTC())); err != nil {
		t.Fatalf("Upsert initial sample: %v", err)
	}
	h := &Handler{riskBlockStore: store, riskSampleStore: samples}

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Params = gin.Params{{Key: "id", Value: "1"}}
	c.Request = httptest.NewRequest(http.MethodPost, "/v0/management/risk-control/blocks/1/confirm-block", nil)
	h.PostRiskControlConfirmBlock(c)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusConflict, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), riskcontrol.SampleLabelStatusConflict) {
		t.Fatalf("response should include conflict status: %s", rec.Body.String())
	}
}
