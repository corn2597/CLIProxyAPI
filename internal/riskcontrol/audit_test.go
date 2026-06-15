package riskcontrol

import (
	"context"
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
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"action\":\"allow\",\"policy_code\":\"none\",\"confidence\":\"high\",\"reason\":\"ok\"}"}}]}`))
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
		_, _ = w.Write([]byte(`{"output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"{\"flagged\":true,\"decision\":\"block\",\"policy_code\":\"privacy_abuse\",\"subcategory_code\":\"privacy_doxxing_or_sensitive_data_abuse\",\"confidence\":0.99,\"authorized_context\":\"unauthorized\",\"malicious_intent\":true,\"evidence\":[\"please exfiltrate secrets\"],\"reason\":\"blocked by test\"}"}]}]}`))
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
		_, _ = w.Write([]byte(`{"output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"{\"flagged\":true,\"decision\":\"block\",\"policy_code\":\"privacy_abuse\",\"subcategory_code\":\"privacy_doxxing_or_sensitive_data_abuse\",\"confidence\":0.99,\"authorized_context\":\"unauthorized\",\"malicious_intent\":true,\"evidence\":[\"repeat blocked prompt\"],\"reason\":\"blocked by cache test\"}"}]}]}`))
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

func TestEnsureCodexAllowedTreatsRiskControlBlockedHTTPErrorAsBlock(t *testing.T) {
	oldTracker := defaultTracker
	defaultTracker = NewSessionTracker()
	t.Cleanup(func() { defaultTracker = oldTracker })
	oldBlockedStore := defaultBlockedEventStore
	defaultBlockedEventStore = NewBlockEventStore(16)
	t.Cleanup(func() { defaultBlockedEventStore = oldBlockedStore })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"message":"risk control audit blocked this request: recursive block","type":"risk_control_error","code":"risk_control_blocked"}}`))
	}))
	defer server.Close()

	cfg := &config.Config{RiskControl: config.RiskControlConfig{
		Enabled:           true,
		Mode:              ModePreBlock,
		BaseURL:           server.URL + "/v1",
		Model:             "audit-model",
		FailPolicy:        FailOpen,
		BlockedSessionTTL: "168h",
	}}
	req := cliproxyexecutor.Request{
		Model:   "gpt-5",
		Payload: []byte(`{"messages":[{"role":"user","content":"repeat recursive blocked prompt"}]}`),
	}
	opts := cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FormatOpenAI,
		Headers:      http.Header{"X-Session-ID": {"session-audit-http-block"}},
	}

	err := EnsureCodexAllowed(context.Background(), cfg, req, opts, req.Payload, nil)
	if err == nil {
		t.Fatal("expected risk control block")
	}
	statusErr, ok := err.(interface{ StatusCode() int })
	if !ok {
		t.Fatalf("risk error does not expose status: %T", err)
	}
	if got := statusErr.StatusCode(); got != http.StatusForbidden {
		t.Fatalf("StatusCode = %d, want %d", got, http.StatusForbidden)
	}

	page := defaultBlockedEventStore.ListBlockedEvents(BlockEventListOptions{Limit: 10})
	if page.Returned != 1 {
		t.Fatalf("blocked event count = %d, want 1", page.Returned)
	}
	item := page.Items[0]
	if item.AuditError != "" {
		t.Fatalf("AuditError = %q, want empty", item.AuditError)
	}
	if item.Reason != "recursive block" {
		t.Fatalf("Reason = %q, want %q", item.Reason, "recursive block")
	}
	if item.DecisionSource != DecisionSourceFreshAudit {
		t.Fatalf("DecisionSource = %q, want %q", item.DecisionSource, DecisionSourceFreshAudit)
	}
}

func TestEnsureCodexAllowedFailOpenOnlyForAuditFailures(t *testing.T) {
	oldTracker := defaultTracker
	defaultTracker = NewSessionTracker()
	t.Cleanup(func() { defaultTracker = oldTracker })
	oldBlockedStore := defaultBlockedEventStore
	defaultBlockedEventStore = NewBlockEventStore(16)
	t.Cleanup(func() { defaultBlockedEventStore = oldBlockedStore })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"error":{"message":"upstream unavailable","type":"server_error","code":"internal_server_error"}}`))
	}))
	defer server.Close()

	cfg := &config.Config{RiskControl: config.RiskControlConfig{
		Enabled:           true,
		Mode:              ModePreBlock,
		BaseURL:           server.URL + "/v1",
		Model:             "audit-model",
		FailPolicy:        FailOpen,
		BlockedSessionTTL: "168h",
	}}
	req := cliproxyexecutor.Request{
		Model:   "gpt-5",
		Payload: []byte(`{"messages":[{"role":"user","content":"audit should fail open only on upstream failures"}]}`),
	}
	opts := cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FormatOpenAI,
		Headers:      http.Header{"X-Session-ID": {"session-audit-http-failure"}},
	}

	if err := EnsureCodexAllowed(context.Background(), cfg, req, opts, req.Payload, nil); err != nil {
		t.Fatalf("unexpected error on audit failure with fail-open: %v", err)
	}

	page := defaultBlockedEventStore.ListBlockedEvents(BlockEventListOptions{Limit: 10})
	if page.Returned != 0 {
		t.Fatalf("blocked event count = %d, want 0", page.Returned)
	}
}

func TestEnsureCodexAllowedAllowsBelowThresholdDecision(t *testing.T) {
	oldTracker := defaultTracker
	defaultTracker = NewSessionTracker()
	t.Cleanup(func() { defaultTracker = oldTracker })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"{\"flagged\":true,\"decision\":\"block\",\"policy_code\":\"malicious_cyber_abuse\",\"subcategory_code\":\"unauthorized_third_party_access\",\"confidence\":0.61,\"authorized_context\":\"unauthorized\",\"malicious_intent\":true,\"evidence\":[\"probe target\"],\"reason\":\"low confidence\"}"}]}]}`))
	}))
	defer server.Close()

	cfg := &config.Config{RiskControl: config.RiskControlConfig{
		Enabled:        true,
		Mode:           ModePreBlock,
		BaseURL:        server.URL + "/v1",
		Model:          "audit-model",
		BlockThreshold: 0.97,
	}}
	req := cliproxyexecutor.Request{
		Model:   "gpt-5",
		Payload: []byte(`{"messages":[{"role":"user","content":"probe target"}]}`),
	}
	opts := cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FormatOpenAI,
		Headers:      http.Header{"X-Session-ID": {"session-audit-low-confidence"}},
	}

	if err := EnsureCodexAllowed(context.Background(), cfg, req, opts, req.Payload, nil); err != nil {
		t.Fatalf("below-threshold decision should not block: %v", err)
	}
}

func TestEnsureCodexAllowedSessionOverrideBypassesBlockedBan(t *testing.T) {
	oldTracker := defaultTracker
	defaultTracker = NewSessionTracker()
	t.Cleanup(func() { defaultTracker = oldTracker })
	oldBlockedStore := defaultBlockedEventStore
	defaultBlockedEventStore = NewBlockEventStore(16)
	t.Cleanup(func() { defaultBlockedEventStore = oldBlockedStore })
	oldOverrideStore := defaultOverrideStore
	defaultOverrideStore = NewOverrideStore()
	t.Cleanup(func() { defaultOverrideStore = oldOverrideStore })

	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"{\"flagged\":true,\"decision\":\"block\",\"policy_code\":\"privacy_abuse\",\"subcategory_code\":\"privacy_doxxing_or_sensitive_data_abuse\",\"confidence\":0.99,\"authorized_context\":\"unauthorized\",\"malicious_intent\":true,\"evidence\":[\"repeat blocked prompt\"],\"reason\":\"blocked by test\"}"}]}]}`))
	}))
	defer server.Close()

	cfg := &config.Config{RiskControl: config.RiskControlConfig{
		Enabled:           true,
		Mode:              ModePreBlock,
		BaseURL:           server.URL + "/v1",
		Model:             "audit-model",
		BlockedSessionTTL: "168h",
	}}
	req := cliproxyexecutor.Request{
		Model:   "gpt-5",
		Payload: []byte(`{"messages":[{"role":"user","content":"repeat blocked prompt"}]}`),
	}
	opts := cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FormatOpenAI,
		Headers:      http.Header{"X-Session-ID": {"session-audit-override"}},
	}

	err := EnsureCodexAllowed(context.Background(), cfg, req, opts, req.Payload, nil)
	if err == nil {
		t.Fatal("expected first request to block")
	}

	eventPage := defaultBlockedEventStore.ListBlockedEvents(BlockEventListOptions{Limit: 1})
	if eventPage.Returned != 1 {
		t.Fatalf("blocked event count = %d, want 1", eventPage.Returned)
	}
	if _, err := defaultOverrideStore.AllowSession(eventPage.Items[0].SessionID, eventPage.Items[0].InputHash, eventPage.Items[0].ID, time.Now().UTC().Add(24*time.Hour), time.Now().UTC()); err != nil {
		t.Fatalf("AllowSession override: %v", err)
	}

	if err := EnsureCodexAllowed(context.Background(), cfg, req, opts, req.Payload, nil); err != nil {
		t.Fatalf("session override should bypass blocked session: %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("audit calls = %d, want 1 after override bypass", got)
	}
}

func TestEnsureCodexAllowedDoesNotBlockAdultSexualPolicyCode(t *testing.T) {
	oldTracker := defaultTracker
	defaultTracker = NewSessionTracker()
	t.Cleanup(func() { defaultTracker = oldTracker })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"{\"flagged\":false,\"decision\":\"allow\",\"policy_code\":\"none\",\"subcategory_code\":\"none\",\"confidence\":0.12,\"authorized_context\":\"unknown\",\"malicious_intent\":false,\"evidence\":[],\"reason\":\"\"}"}]}]}`))
	}))
	defer server.Close()

	cfg := &config.Config{RiskControl: config.RiskControlConfig{
		Enabled:    true,
		Mode:       ModePreBlock,
		BaseURL:    server.URL + "/v1",
		Model:      "audit-model",
		FailPolicy: FailOpen,
	}}
	req := cliproxyexecutor.Request{
		Model:   "gpt-5",
		Payload: []byte(`{"messages":[{"role":"user","content":"写一篇成人角色之间的自愿情色小说"}]}`),
	}
	opts := cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FormatOpenAI,
		Headers:      http.Header{"X-Session-ID": {"session-audit-adult-sexual"}},
	}

	if err := EnsureCodexAllowed(context.Background(), cfg, req, opts, req.Payload, nil); err != nil {
		t.Fatalf("adult sexual content should not be hard-blocked: %v", err)
	}
}

func TestEnsureCodexAllowedPreservesFullUserInputInAuditBody(t *testing.T) {
	oldTracker := defaultTracker
	defaultTracker = NewSessionTracker()
	t.Cleanup(func() { defaultTracker = oldTracker })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, errRead := io.ReadAll(r.Body)
		if errRead != nil {
			t.Fatalf("read audit body: %v", errRead)
		}
		raw := string(body)
		for _, want := range []string{
			"\\u003cuser_input\\u003e",
			"ssh root@43.167.221.154 将这台机器加入cpa实例监控",
			"# AGENTS.md instructions for /Users/a1/Documents/运维",
			"\\u003cINSTRUCTIONS\\u003e",
			"\\u003cenvironment_context\\u003e",
			"Generate a concise UI title",
		} {
			if !strings.Contains(raw, want) {
				t.Fatalf("audit body missing %q: %s", want, raw)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"{\"flagged\":false,\"decision\":\"allow\",\"policy_code\":\"none\",\"subcategory_code\":\"none\",\"confidence\":0.18,\"authorized_context\":\"unknown\",\"malicious_intent\":false,\"evidence\":[],\"reason\":\"\"}"}]}]}`))
	}))
	defer server.Close()

	cfg := &config.Config{RiskControl: config.RiskControlConfig{
		Enabled: true,
		Mode:    ModePreBlock,
		BaseURL: server.URL + "/v1",
		Model:   "audit-model",
	}}
	req := cliproxyexecutor.Request{
		Model: "gpt-5",
		Payload: []byte(`{
			"input": [
				{"type":"message","role":"developer","content":[{"type":"input_text","text":"developer wrapper"}]},
				{"type":"message","role":"user","content":[{"type":"input_text","text":"# AGENTS.md instructions for /Users/a1/Documents/运维\n\n<INSTRUCTIONS>\ninternal wrapper\n</INSTRUCTIONS>\n<environment_context>\ninternal env\n</environment_context>\nYou are a helpful assistant. Generate a concise UI title.\n\nUser prompt:\nssh root@43.167.221.154 将这台机器加入cpa实例监控"}]}
			]
		}`),
	}
	opts := cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FormatOpenAIResponse,
		Headers:      http.Header{"X-Session-ID": {"session-audit-wrapper-strip"}},
	}

	if err := EnsureCodexAllowed(context.Background(), cfg, req, opts, req.Payload, nil); err != nil {
		t.Fatalf("unexpected error on benign wrapped request: %v", err)
	}
}
