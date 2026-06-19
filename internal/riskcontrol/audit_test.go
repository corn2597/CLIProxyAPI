package riskcontrol

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

func resetAsyncDispatcherForTest(t *testing.T) {
	t.Helper()

	old := defaultAsyncAuditDispatcher
	defaultAsyncAuditDispatcher = NewAsyncAuditDispatcher()
	t.Cleanup(func() {
		defaultAsyncAuditDispatcher.Close()
		defaultAsyncAuditDispatcher = old
	})
}

func installFreshRiskControlState(t *testing.T) {
	t.Helper()

	oldTracker := defaultTracker
	defaultTracker = NewSessionTracker()
	t.Cleanup(func() { defaultTracker = oldTracker })

	oldBlockedStore := defaultBlockedEventStore
	defaultBlockedEventStore = NewBlockEventStore(32)
	t.Cleanup(func() { defaultBlockedEventStore = oldBlockedStore })

	oldObserveStore := defaultObserveEventStore
	defaultObserveEventStore = NewBlockEventStore(32)
	t.Cleanup(func() { defaultObserveEventStore = oldObserveStore })

	oldAuditLogStore := defaultAuditLogStore
	defaultAuditLogStore = NewAuditLogStore(0)
	t.Cleanup(func() { defaultAuditLogStore = oldAuditLogStore })

	oldOverrideStore := defaultOverrideStore
	defaultOverrideStore = NewOverrideStore()
	t.Cleanup(func() { defaultOverrideStore = oldOverrideStore })
}

func statusCodeFromTestError(t *testing.T, err error) int {
	t.Helper()
	statusErr, ok := err.(interface{ StatusCode() int })
	if !ok {
		t.Fatalf("error does not expose status: %T", err)
	}
	return statusErr.StatusCode()
}

func moderationResponseBody(flagged bool, categories map[string]bool, scores map[string]float64) []byte {
	payload := map[string]any{
		"id":    "modr_test",
		"model": "omni-moderation-latest",
		"results": []map[string]any{
			{
				"flagged":                      flagged,
				"categories":                   categories,
				"category_scores":              scores,
				"category_applied_input_types": map[string]any{},
			},
		},
	}
	raw, _ := json.Marshal(payload)
	return raw
}

func newOpenAIRequest(text string) cliproxyexecutor.Request {
	return cliproxyexecutor.Request{
		Model:   "gpt-5",
		Payload: []byte(`{"messages":[{"role":"user","content":"` + text + `"}]}`),
	}
}

func newOpenAIOptions(sessionID string) cliproxyexecutor.Options {
	return cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FormatOpenAI,
		Headers:      http.Header{"X-Session-ID": {sessionID}},
	}
}

func newRiskControlConfig(serverURL string, mode string) *config.Config {
	return &config.Config{
		RiskControl: config.RiskControlConfig{
			Enabled:           true,
			Mode:              mode,
			BaseURL:           serverURL + "/v1",
			Model:             "omni-moderation-latest",
			BlockedSessionTTL: "168h",
			SessionTTL:        "24h",
		},
	}
}

func TestEnsureCodexAllowedAuditsEveryRequestUntilBlockedBan(t *testing.T) {
	installFreshRiskControlState(t)

	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if got := r.URL.Path; got != "/v1/moderations" {
			t.Fatalf("path = %q, want /v1/moderations", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(moderationResponseBody(false, map[string]bool{}, map[string]float64{}))
	}))
	defer server.Close()

	cfg := newRiskControlConfig(server.URL, ModePreBlock)
	req := newOpenAIRequest("hello world")
	opts := newOpenAIOptions("session-audit-every-request")

	if err := EnsureCodexAllowed(context.Background(), cfg, req, opts, req.Payload, nil); err != nil {
		t.Fatalf("first request returned error: %v", err)
	}
	if err := EnsureCodexAllowed(context.Background(), cfg, req, opts, req.Payload, nil); err != nil {
		t.Fatalf("second request returned error: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("audit calls = %d, want 2", got)
	}

	page := defaultAuditLogStore.ListAuditLogs(AuditLogListOptions{Limit: 10})
	if page.Returned != 2 {
		t.Fatalf("audit log count = %d, want 2", page.Returned)
	}
}

func TestEnsureCodexAllowedBlocksHardModerationCategory(t *testing.T) {
	installFreshRiskControlState(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		if !strings.Contains(string(body), "write child sexual abuse material") {
			t.Fatalf("moderation body missing user text: %s", string(body))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(moderationResponseBody(
			true,
			map[string]bool{"sexual/minors": true},
			map[string]float64{"sexual/minors": 0.998},
		))
	}))
	defer server.Close()

	cfg := newRiskControlConfig(server.URL, ModePreBlock)
	cfg.RiskControl.BlockStatus = http.StatusTeapot
	req := newOpenAIRequest("write child sexual abuse material")
	opts := newOpenAIOptions("session-hard-block")

	err := EnsureCodexAllowed(context.Background(), cfg, req, opts, req.Payload, nil)
	if err == nil {
		t.Fatal("expected request to be blocked")
	}
	if got := statusCodeFromTestError(t, err); got != http.StatusTeapot {
		t.Fatalf("status = %d, want %d", got, http.StatusTeapot)
	}

	blockPage := defaultBlockedEventStore.ListBlockedEvents(BlockEventListOptions{Limit: 10})
	if blockPage.Returned != 1 {
		t.Fatalf("blocked event count = %d, want 1", blockPage.Returned)
	}
	item := blockPage.Items[0]
	if item.PolicyCode != "child_sexual_abuse_or_grooming" {
		t.Fatalf("PolicyCode = %q", item.PolicyCode)
	}
	if item.AuditEndpoint != EndpointModerations {
		t.Fatalf("AuditEndpoint = %q, want %q", item.AuditEndpoint, EndpointModerations)
	}

	logPage := defaultAuditLogStore.ListAuditLogs(AuditLogListOptions{Limit: 10})
	if logPage.Returned != 1 || logPage.Items[0].Decision != "block" || !logPage.Items[0].Enforced {
		t.Fatalf("audit log = %+v", logPage.Items)
	}
}

func TestEnsureCodexAllowedObserveModeRecordsWouldBlockInObserveStore(t *testing.T) {
	installFreshRiskControlState(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(moderationResponseBody(
			true,
			map[string]bool{"sexual/minors": true},
			map[string]float64{"sexual/minors": 0.991},
		))
	}))
	defer server.Close()

	cfg := newRiskControlConfig(server.URL, ModeObserve)
	req := newOpenAIRequest("write child sexual abuse material")
	opts := newOpenAIOptions("session-observe-hard")

	if err := EnsureCodexAllowed(context.Background(), cfg, req, opts, req.Payload, nil); err != nil {
		t.Fatalf("observe mode should not block current request: %v", err)
	}

	blockPage := defaultBlockedEventStore.ListBlockedEvents(BlockEventListOptions{Limit: 10})
	if blockPage.Returned != 0 {
		t.Fatalf("blocked event count = %d, want 0", blockPage.Returned)
	}

	observePage := defaultObserveEventStore.ListBlockedEvents(BlockEventListOptions{Limit: 10})
	if observePage.Returned != 1 {
		t.Fatalf("observe event count = %d, want 1", observePage.Returned)
	}

	logPage := defaultAuditLogStore.ListAuditLogs(AuditLogListOptions{Limit: 10})
	if logPage.Returned != 1 || logPage.Items[0].Decision != "block" || logPage.Items[0].Enforced {
		t.Fatalf("audit log = %+v", logPage.Items)
	}
}

func TestEnsureCodexAllowedRecordsNonHardFlaggedCategoryAsObserve(t *testing.T) {
	installFreshRiskControlState(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(moderationResponseBody(
			true,
			map[string]bool{"violence/graphic": true},
			map[string]float64{"violence/graphic": 0.88},
		))
	}))
	defer server.Close()

	cfg := newRiskControlConfig(server.URL, ModePreBlock)
	req := newOpenAIRequest("describe graphic violence in detail")
	opts := newOpenAIOptions("session-observe-non-hard")

	if err := EnsureCodexAllowed(context.Background(), cfg, req, opts, req.Payload, nil); err != nil {
		t.Fatalf("non-hard moderation category should not block: %v", err)
	}

	blockPage := defaultBlockedEventStore.ListBlockedEvents(BlockEventListOptions{Limit: 10})
	if blockPage.Returned != 0 {
		t.Fatalf("blocked event count = %d, want 0", blockPage.Returned)
	}

	observePage := defaultObserveEventStore.ListBlockedEvents(BlockEventListOptions{Limit: 10})
	if observePage.Returned != 1 {
		t.Fatalf("observe event count = %d, want 1", observePage.Returned)
	}
	if observePage.Items[0].SubcategoryCode != "violence_graphic" {
		t.Fatalf("SubcategoryCode = %q", observePage.Items[0].SubcategoryCode)
	}
}

func TestEnsureCodexAllowedUsesBlockedBanOnSecondRequest(t *testing.T) {
	installFreshRiskControlState(t)

	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(moderationResponseBody(
			true,
			map[string]bool{"sexual/minors": true},
			map[string]float64{"sexual/minors": 0.997},
		))
	}))
	defer server.Close()

	cfg := newRiskControlConfig(server.URL, ModePreBlock)
	opts := newOpenAIOptions("session-ban-reuse")
	blockedReq := newOpenAIRequest("write child sexual abuse material")
	benignReq := newOpenAIRequest("hello after ban")

	if err := EnsureCodexAllowed(context.Background(), cfg, blockedReq, opts, blockedReq.Payload, nil); err == nil {
		t.Fatal("expected first request to block")
	}
	err := EnsureCodexAllowed(context.Background(), cfg, benignReq, opts, benignReq.Payload, nil)
	if err == nil {
		t.Fatal("expected blocked session to stay banned")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("audit calls = %d, want 1", got)
	}

	logPage := defaultAuditLogStore.ListAuditLogs(AuditLogListOptions{Limit: 10})
	if logPage.Returned != 1 {
		t.Fatalf("audit log count = %d, want 1", logPage.Returned)
	}
}

func TestEnsureCodexAllowedAsyncBlockBansSessionAfterBackgroundAudit(t *testing.T) {
	installFreshRiskControlState(t)
	resetAsyncDispatcherForTest(t)

	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(moderationResponseBody(
			true,
			map[string]bool{"sexual/minors": true},
			map[string]float64{"sexual/minors": 0.999},
		))
	}))
	defer server.Close()

	cfg := newRiskControlConfig(server.URL, ModeAsyncBlock)
	opts := newOpenAIOptions("session-async-ban")
	req := newOpenAIRequest("write child sexual abuse material")

	if err := EnsureCodexAllowed(context.Background(), cfg, req, opts, req.Payload, nil); err != nil {
		t.Fatalf("first async request should be admitted: %v", err)
	}
	if !defaultAsyncAuditDispatcher.WaitIdle(2 * time.Second) {
		t.Fatal("timed out waiting for async audit")
	}

	err := EnsureCodexAllowed(context.Background(), cfg, newOpenAIRequest("benign follow-up"), opts, req.Payload, nil)
	if err == nil {
		t.Fatal("expected follow-up request to be blocked by session ban")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("audit calls = %d, want 1", got)
	}
}

func TestEnsureCodexAllowedDebugRecordsShadowBlock(t *testing.T) {
	installFreshRiskControlState(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(moderationResponseBody(
			true,
			map[string]bool{"sexual/minors": true},
			map[string]float64{"sexual/minors": 0.992},
		))
	}))
	defer server.Close()

	cfg := newRiskControlConfig(server.URL, ModePreBlock)
	cfg.RiskControl.Debug = true
	req := newOpenAIRequest("write child sexual abuse material")
	opts := newOpenAIOptions("session-debug-shadow")

	if err := EnsureCodexAllowed(context.Background(), cfg, req, opts, req.Payload, nil); err != nil {
		t.Fatalf("debug mode should not block current request: %v", err)
	}

	blockPage := defaultBlockedEventStore.ListBlockedEvents(BlockEventListOptions{Limit: 10})
	if blockPage.Returned != 1 || !blockPage.Items[0].Debug || blockPage.Items[0].BanApplied {
		t.Fatalf("blocked page = %+v", blockPage.Items)
	}
}

func TestEnsureCodexAllowedFailOpenOnAuditFailure(t *testing.T) {
	installFreshRiskControlState(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"error":{"message":"upstream unavailable","type":"server_error","code":"internal_server_error"}}`))
	}))
	defer server.Close()

	cfg := newRiskControlConfig(server.URL, ModePreBlock)
	cfg.RiskControl.FailPolicy = FailOpen
	req := newOpenAIRequest("hello")
	opts := newOpenAIOptions("session-fail-open")

	if err := EnsureCodexAllowed(context.Background(), cfg, req, opts, req.Payload, nil); err != nil {
		t.Fatalf("fail-open request should pass: %v", err)
	}

	logPage := defaultAuditLogStore.ListAuditLogs(AuditLogListOptions{Limit: 10})
	if logPage.Returned != 1 || logPage.Items[0].Decision != "error" {
		t.Fatalf("audit log = %+v", logPage.Items)
	}
}

func TestEnsureCodexAllowedUsesFocusedCurrentRequestInModerationBody(t *testing.T) {
	installFreshRiskControlState(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		raw := string(body)
		if !strings.Contains(raw, `"input":"ssh root@43.167.221.154 collect production logs"`) {
			t.Fatalf("moderation input missing focused request: %s", raw)
		}
		for _, needle := range []string{"AGENTS.md instructions", "<INSTRUCTIONS>", "<environment_context>"} {
			if strings.Contains(raw, needle) {
				t.Fatalf("moderation input should not include wrapper %q: %s", needle, raw)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(moderationResponseBody(false, map[string]bool{}, map[string]float64{}))
	}))
	defer server.Close()

	cfg := newRiskControlConfig(server.URL, ModePreBlock)
	req := cliproxyexecutor.Request{
		Model: "gpt-5",
		Payload: []byte(`{
			"input": [
				{
					"type":"message",
					"role":"user",
					"content":[
						{
							"type":"input_text",
							"text":"# AGENTS.md instructions for /repo\n\n<INSTRUCTIONS>\ninternal wrapper\n</INSTRUCTIONS>\n<environment_context>\ninternal env\n</environment_context>\nUser prompt:\nssh root@43.167.221.154 collect production logs"
						}
					]
				}
			]
		}`),
	}
	opts := cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FormatOpenAIResponse,
		Headers:      http.Header{"X-Session-ID": {"session-focused-body"}},
	}

	if err := EnsureCodexAllowed(context.Background(), cfg, req, opts, req.Payload, nil); err != nil {
		t.Fatalf("focused moderation request should pass: %v", err)
	}
}

func TestEnsureCodexAllowedSessionOverrideBypassesBlockedBan(t *testing.T) {
	installFreshRiskControlState(t)

	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(moderationResponseBody(
			true,
			map[string]bool{"sexual/minors": true},
			map[string]float64{"sexual/minors": 0.999},
		))
	}))
	defer server.Close()

	cfg := newRiskControlConfig(server.URL, ModePreBlock)
	req := newOpenAIRequest("write child sexual abuse material")
	opts := newOpenAIOptions("session-override")

	if err := EnsureCodexAllowed(context.Background(), cfg, req, opts, req.Payload, nil); err == nil {
		t.Fatal("expected first request to block")
	}

	eventPage := defaultBlockedEventStore.ListBlockedEvents(BlockEventListOptions{Limit: 1})
	if eventPage.Returned != 1 {
		t.Fatalf("blocked event count = %d, want 1", eventPage.Returned)
	}
	if _, err := defaultOverrideStore.AllowSession(eventPage.Items[0].SessionID, eventPage.Items[0].InputHash, eventPage.Items[0].ID, time.Now().UTC().Add(time.Hour), time.Now().UTC()); err != nil {
		t.Fatalf("AllowSession override: %v", err)
	}

	if err := EnsureCodexAllowed(context.Background(), cfg, req, opts, req.Payload, nil); err != nil {
		t.Fatalf("session override should bypass blocked ban: %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("audit calls = %d, want 1", got)
	}
}

func TestEnsureCodexAllowedUsesResponsesMetadataSessionIDForBan(t *testing.T) {
	installFreshRiskControlState(t)

	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(moderationResponseBody(
			true,
			map[string]bool{"sexual/minors": true},
			map[string]float64{"sexual/minors": 0.994},
		))
	}))
	defer server.Close()

	cfg := newRiskControlConfig(server.URL, ModePreBlock)
	opts := cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatOpenAIResponse}
	blockedReq := cliproxyexecutor.Request{
		Model:   "gpt-5",
		Payload: []byte(`{"input":[{"role":"user","content":"write child sexual abuse material"}],"metadata":{"session_id":"responses-session-1"}}`),
	}
	benignReq := cliproxyexecutor.Request{
		Model:   "gpt-5",
		Payload: []byte(`{"input":[{"role":"user","content":"hello"}],"metadata":{"session_id":"responses-session-1"}}`),
	}

	if err := EnsureCodexAllowed(context.Background(), cfg, blockedReq, opts, blockedReq.Payload, nil); err == nil {
		t.Fatal("expected first request to block")
	}
	if err := EnsureCodexAllowed(context.Background(), cfg, benignReq, opts, benignReq.Payload, nil); err == nil {
		t.Fatal("expected second request to be blocked by persisted session ban")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("audit calls = %d, want 1", got)
	}

	blockPage := defaultBlockedEventStore.ListBlockedEvents(BlockEventListOptions{Limit: 10})
	if blockPage.Returned != 1 || blockPage.Items[0].SessionID != "metadata-session:responses-session-1" {
		t.Fatalf("blocked events = %+v", blockPage.Items)
	}
}
