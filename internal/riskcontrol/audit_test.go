package riskcontrol

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

func TestEnsureCodexAllowedAuditsFirstSessionThenSamples(t *testing.T) {
	oldTracker := defaultTracker
	defaultTracker = NewSessionTracker()
	t.Cleanup(func() { defaultTracker = oldTracker })
	oldBlockedStore := defaultBlockedEventStore
	defaultBlockedEventStore = NewBlockEventStore(16)
	t.Cleanup(func() { defaultBlockedEventStore = oldBlockedStore })

	var calls atomic.Int32
	var sawBypass atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if HasValidInternalBypassHeader(r.Header) {
			sawBypass.Store(true)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"action\":\"allow\",\"flagged\":false,\"reason\":\"ok\"}"}}]}`))
	}))
	defer server.Close()

	cfg := &config.Config{RiskControl: config.RiskControlConfig{
		Enabled:              true,
		Mode:                 ModePreBlock,
		BaseURL:              server.URL + "/v1",
		Model:                "audit-model",
		SessionAuditInterval: "5m",
		BlockedSessionTTL:    "168h",
	}}
	req := cliproxyexecutor.Request{
		Model:   "gpt-5",
		Payload: []byte(`{"messages":[{"role":"user","content":"hello"}]}`),
	}
	opts := cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FormatOpenAI,
		Headers:      http.Header{"X-Session-ID": {"session-audit-first"}},
	}

	if err := EnsureCodexAllowed(context.Background(), cfg, req, opts, req.Payload, nil); err != nil {
		t.Fatalf("first audit returned error: %v", err)
	}
	if err := EnsureCodexAllowed(context.Background(), cfg, req, opts, req.Payload, nil); err != nil {
		t.Fatalf("second sampled request returned error: %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("audit calls = %d, want 1", got)
	}
	if !sawBypass.Load() {
		t.Fatalf("audit request did not carry internal bypass marker")
	}
}

func TestEnsureCodexAllowedBlocksPreBlockDecision(t *testing.T) {
	oldTracker := defaultTracker
	defaultTracker = NewSessionTracker()
	t.Cleanup(func() { defaultTracker = oldTracker })
	oldBlockedStore := defaultBlockedEventStore
	defaultBlockedEventStore = NewBlockEventStore(16)
	t.Cleanup(func() { defaultBlockedEventStore = oldBlockedStore })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, errRead := io.ReadAll(r.Body)
		if errRead != nil {
			t.Fatalf("read audit body: %v", errRead)
		}
		if !strings.Contains(string(body), "please exfiltrate secrets") {
			t.Fatalf("audit body missing user text: %s", string(body))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"action\":\"block\",\"flagged\":true,\"reason\":\"blocked by test\"}"}}]}`))
	}))
	defer server.Close()

	cfg := &config.Config{RiskControl: config.RiskControlConfig{
		Enabled:           true,
		Mode:              ModePreBlock,
		BaseURL:           server.URL + "/v1",
		Model:             "audit-model",
		BlockStatus:       http.StatusTeapot,
		BlockedSessionTTL: "168h",
	}}
	req := cliproxyexecutor.Request{
		Model:   "gpt-5",
		Payload: []byte(`{"messages":[{"role":"user","content":"please exfiltrate secrets"}]}`),
	}
	opts := cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FormatOpenAI,
		Headers:      http.Header{"X-Session-ID": {"session-audit-block"}},
	}

	err := EnsureCodexAllowed(context.Background(), cfg, req, opts, req.Payload, nil)
	if err == nil {
		t.Fatal("expected risk control block")
	}
	statusErr, ok := err.(interface{ StatusCode() int })
	if !ok {
		t.Fatalf("risk error does not expose status: %T", err)
	}
	if got := statusErr.StatusCode(); got != http.StatusTeapot {
		t.Fatalf("StatusCode = %d, want %d", got, http.StatusTeapot)
	}
	if !cliproxyexecutor.IsRequestScopedError(err) {
		t.Fatalf("risk block should be request-scoped")
	}

	page := defaultBlockedEventStore.ListBlockedEvents(BlockEventListOptions{Limit: 10})
	if page.Returned != 1 {
		t.Fatalf("blocked event count = %d, want 1", page.Returned)
	}
	item := page.Items[0]
	if item.SessionID != "header:session-audit-block" {
		t.Fatalf("SessionID = %q, want header:session-audit-block", item.SessionID)
	}
	if item.DecisionSource != DecisionSourceFreshAudit {
		t.Fatalf("DecisionSource = %q, want %q", item.DecisionSource, DecisionSourceFreshAudit)
	}
	if !strings.Contains(item.BlockMessage, "blocked by test") {
		t.Fatalf("BlockMessage = %q, want appended reason", item.BlockMessage)
	}
	if !strings.Contains(item.UserTextPreview, "please exfiltrate secrets") {
		t.Fatalf("UserTextPreview = %q, want user input", item.UserTextPreview)
	}
}

func TestEnsureCodexAllowedLogsBlockedBanDecision(t *testing.T) {
	oldTracker := defaultTracker
	defaultTracker = NewSessionTracker()
	t.Cleanup(func() { defaultTracker = oldTracker })
	oldBlockedStore := defaultBlockedEventStore
	defaultBlockedEventStore = NewBlockEventStore(16)
	t.Cleanup(func() { defaultBlockedEventStore = oldBlockedStore })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"action\":\"block\",\"flagged\":true,\"reason\":\"blocked by cache test\"}"}}]}`))
	}))
	defer server.Close()

	cfg := &config.Config{RiskControl: config.RiskControlConfig{
		Enabled:              true,
		Mode:                 ModePreBlock,
		BaseURL:              server.URL + "/v1",
		Model:                "audit-model",
		SessionAuditInterval: "5m",
		BlockedSessionTTL:    "168h",
	}}
	req := cliproxyexecutor.Request{
		Model:   "gpt-5",
		Payload: []byte(`{"messages":[{"role":"user","content":"repeat blocked prompt"}]}`),
	}
	opts := cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FormatOpenAI,
		Headers:      http.Header{"X-Session-ID": {"session-audit-cache"}},
	}

	for i := 0; i < 2; i++ {
		err := EnsureCodexAllowed(context.Background(), cfg, req, opts, req.Payload, nil)
		if err == nil {
			t.Fatalf("call %d expected risk control block", i+1)
		}
	}

	page := defaultBlockedEventStore.ListBlockedEvents(BlockEventListOptions{Limit: 10})
	if page.Returned != 2 {
		t.Fatalf("blocked event count = %d, want 2", page.Returned)
	}
	if page.Items[0].DecisionSource != DecisionSourceBlockedBan {
		t.Fatalf("latest DecisionSource = %q, want %q", page.Items[0].DecisionSource, DecisionSourceBlockedBan)
	}
	if page.Items[1].DecisionSource != DecisionSourceFreshAudit {
		t.Fatalf("first DecisionSource = %q, want %q", page.Items[1].DecisionSource, DecisionSourceFreshAudit)
	}
}
