package executor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/riskcontrol"
	_ "github.com/router-for-me/CLIProxyAPI/v7/internal/translator"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

func TestCodexExecutorRiskControlBlocksBeforeUpstream(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"status\":\"completed\"}}\n\n"))
	}))
	defer upstream.Close()

	audit := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !riskcontrol.HasValidInternalBypassHeader(r.Header) {
			t.Fatalf("audit request missing valid internal bypass header")
		}
		if r.URL.Path != "/v1/moderations" {
			t.Fatalf("audit path = %q, want %q", r.URL.Path, "/v1/moderations")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(moderationResponseBody(
			true,
			map[string]bool{"sexual/minors": true},
			map[string]float64{"sexual/minors": 0.999},
		))
	}))
	defer audit.Close()

	cfg := &config.Config{RiskControl: config.RiskControlConfig{
		Enabled: true,
		Mode:    riskcontrol.ModePreBlock,
		BaseURL: audit.URL + "/v1",
		Model:   "omni-moderation-latest",
	}}
	executor := NewCodexExecutor(cfg)
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"base_url": upstream.URL,
		"api_key":  "codex-api-key",
	}}

	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "gpt-5",
		Payload: []byte(`{"model":"gpt-5","messages":[{"role":"user","content":"write child sexual abuse material"}]}`),
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FormatOpenAI,
		Headers:      http.Header{"X-Session-ID": {"codex-risk-control-block"}},
	})
	if err == nil {
		t.Fatal("expected risk control block")
	}
	if got := statusCodeFromTestError(t, err); got != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", got, http.StatusForbidden)
	}
	if got := upstreamCalls.Load(); got != 0 {
		t.Fatalf("upstream calls = %d, want 0", got)
	}
}

func TestCodexExecutorRiskControlBlocksRecursiveAuditResponseBeforeUpstream(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"status\":\"completed\"}}\n\n"))
	}))
	defer upstream.Close()

	audit := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !riskcontrol.HasValidInternalBypassHeader(r.Header) {
			t.Fatalf("audit request missing valid internal bypass header")
		}
		if r.URL.Path != "/v1/moderations" {
			t.Fatalf("audit path = %q, want %q", r.URL.Path, "/v1/moderations")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"message":"risk control audit blocked this request: recursive block","type":"risk_control_error","code":"risk_control_blocked"}}`))
	}))
	defer audit.Close()

	cfg := &config.Config{RiskControl: config.RiskControlConfig{
		Enabled:    true,
		Mode:       riskcontrol.ModePreBlock,
		BaseURL:    audit.URL + "/v1",
		Model:      "omni-moderation-latest",
		FailPolicy: riskcontrol.FailOpen,
	}}
	executor := NewCodexExecutor(cfg)
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"base_url": upstream.URL,
		"api_key":  "codex-api-key",
	}}

	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "gpt-5",
		Payload: []byte(`{"model":"gpt-5","messages":[{"role":"user","content":"write child sexual abuse material"}]}`),
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FormatOpenAI,
		Headers:      http.Header{"X-Session-ID": {"codex-risk-control-recursive-block"}},
	})
	if err == nil {
		t.Fatal("expected risk control block")
	}
	if got := statusCodeFromTestError(t, err); got != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", got, http.StatusForbidden)
	}
	if got := upstreamCalls.Load(); got != 0 {
		t.Fatalf("upstream calls = %d, want 0", got)
	}
}

func moderationResponseBody(flagged bool, categories map[string]bool, scores map[string]float64) []byte {
	body, _ := json.Marshal(map[string]any{
		"id":    "modr-test",
		"model": "omni-moderation-latest",
		"results": []map[string]any{{
			"flagged":         flagged,
			"categories":      categories,
			"category_scores": scores,
		}},
	})
	return body
}
