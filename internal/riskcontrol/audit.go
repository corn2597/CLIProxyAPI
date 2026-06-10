package riskcontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/proxyutil"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
)

var (
	defaultTracker       = NewSessionTracker()
	auditAPIKeyCursor    atomic.Uint64
	claudeSessionPattern = regexp.MustCompile(`_session_([a-fA-F0-9-]+)`)
)

// RiskError is request-scoped and must not cool down provider credentials.
type RiskError struct {
	status  int
	code    string
	message string
}

func (e RiskError) Error() string {
	body := map[string]any{
		"error": map[string]any{
			"message": e.message,
			"type":    "risk_control_error",
			"code":    e.code,
		},
	}
	raw, errMarshal := json.Marshal(body)
	if errMarshal != nil {
		return e.message
	}
	return string(raw)
}

func (e RiskError) StatusCode() int { return e.status }

func (e RiskError) RequestScoped() bool { return true }

// EnsureCodexAllowed audits a Codex request before any upstream Codex network call.
func EnsureCodexAllowed(ctx context.Context, cfg *config.Config, req executor.Request, opts executor.Options, originalPayload []byte, translatedPayload []byte) error {
	settings := normalizeSettings(cfg)
	if !settings.enabled || settings.mode == ModeOff {
		return nil
	}
	if IsBypassed(opts) {
		return nil
	}

	input := bestAuditInput(opts.SourceFormat, settings, originalPayload, req.Payload, translatedPayload)
	if input.Empty() {
		log.WithField("provider", "codex").Debug("risk control: no user input extracted; skipping audit")
		return nil
	}

	sessionID := codexSessionID(ctx, req, opts, originalPayload, translatedPayload)
	if sessionID == "" {
		sessionID = "request:" + input.Hash[:24]
	}

	now := time.Now()
	decision, decisionSource := defaultTracker.evaluate(sessionID, now, settings.sessionAuditInterval, settings.sessionTTL, settings.blockedSessionTTL, func() Decision {
		return performAudit(ctx, cfg, settings, sessionID, req.Model, input)
	})
	if decisionSource == DecisionSourceFreshAudit {
		log.WithFields(log.Fields{
			"provider":        "codex",
			"session_id":      sessionID,
			"blocked":         decision.Blocked,
			"error":           decision.Error,
			"decision_source": decisionSource,
		}).Debug("risk control: audited codex session")
	}
	if settings.mode == ModePreBlock && decision.Blocked {
		message := settings.blockMessage
		if decision.Reason != "" {
			message = message + ": " + decision.Reason
		}
		recordCodexBlockedEvent(now, settings, sessionID, req, opts, input, decision, decisionSource, message)
		status := settings.blockStatus
		if status <= 0 {
			status = defaultBlockStatus
		}
		return RiskError{status: status, code: "risk_control_blocked", message: message}
	}
	return nil
}

func recordCodexBlockedEvent(now time.Time, settings settings, sessionID string, req executor.Request, opts executor.Options, input AuditInput, decision Decision, decisionSource string, blockMessage string) {
	if decisionSource == "" {
		decisionSource = DecisionSourceFreshAudit
	}

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

	DefaultBlockedEventStore().RecordBlockedEvent(BlockEvent{
		BlockedAt:       now,
		Provider:        "codex",
		SessionID:       sessionID,
		RequestedModel:  requestedModel,
		UpstreamModel:   strings.TrimSpace(req.Model),
		AuditModel:      settings.model,
		AuditEndpoint:   settings.endpoint,
		Mode:            settings.mode,
		SourceFormat:    strings.TrimSpace(opts.SourceFormat.String()),
		RequestPath:     requestPath,
		MessageCount:    input.MessageCount,
		InputHash:       input.Hash,
		UserTextPreview: input.Text,
		ImageReferences: input.Images,
		DecisionSource:  decisionSource,
		Reason:          decision.Reason,
		AuditError:      decision.Error,
		BlockMessage:    blockMessage,
	})
}

func bestAuditInput(format sdktranslator.Format, settings settings, payloads ...[]byte) AuditInput {
	for _, payload := range payloads {
		input := ExtractFullUserInput(format, payload, settings.maxInputRunes, settings.maxInputImages)
		if !input.Empty() {
			return input
		}
	}
	for _, payload := range payloads {
		input := ExtractFullUserInput(sdktranslator.FormatCodex, payload, settings.maxInputRunes, settings.maxInputImages)
		if !input.Empty() {
			return input
		}
	}
	return AuditInput{}
}

func performAudit(ctx context.Context, cfg *config.Config, settings settings, sessionID string, model string, input AuditInput) Decision {
	if settings.baseURL == "" {
		return decisionFromAuditError(settings, "missing risk-control base-url")
	}
	if settings.model == "" {
		return decisionFromAuditError(settings, "missing risk-control model")
	}
	decision, errAudit := callAuditAPI(ctx, cfg, settings, sessionID, model, input)
	if errAudit != nil {
		return decisionFromAuditError(settings, errAudit.Error())
	}
	return decision
}

func decisionFromAuditError(settings settings, message string) Decision {
	log.WithField("error", message).Warn("risk control: audit failed")
	if settings.failPolicy == FailClosed {
		return Decision{Blocked: true, Reason: "audit unavailable", Error: message}
	}
	return Decision{Blocked: false, Reason: "audit failed open", Error: message}
}

func callAuditAPI(ctx context.Context, cfg *config.Config, settings settings, sessionID string, model string, input AuditInput) (Decision, error) {
	apiURL := auditURL(settings)
	if apiURL == "" {
		return Decision{}, fmt.Errorf("risk control: invalid audit endpoint")
	}
	body, errBody := auditRequestBody(settings, sessionID, model, input)
	if errBody != nil {
		return Decision{}, errBody
	}
	auditCtx := ctx
	var cancel context.CancelFunc
	if settings.timeout > 0 {
		auditCtx, cancel = context.WithTimeout(ctx, settings.timeout)
		defer cancel()
	}
	req, errReq := http.NewRequestWithContext(auditCtx, http.MethodPost, apiURL, bytes.NewReader(body))
	if errReq != nil {
		return Decision{}, errReq
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "cli-proxy-risk-control")
	AddInternalBypassHeader(req.Header)
	if apiKey := nextAPIKey(settings.apiKeys); apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	client := newAuditHTTPClient(ctx, cfg, settings.timeout)
	resp, errDo := client.Do(req)
	if errDo != nil {
		return Decision{}, errDo
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.WithError(errClose).Debug("risk control: close audit response body failed")
		}
	}()
	raw, errRead := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if errRead != nil {
		return Decision{}, errRead
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Decision{}, fmt.Errorf("risk control audit HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return parseAuditDecision(settings, raw)
}

func auditRequestBody(settings settings, sessionID string, model string, input AuditInput) ([]byte, error) {
	switch settings.endpoint {
	case EndpointModerations:
		return json.Marshal(map[string]any{
			"model": settings.model,
			"input": auditInputText(sessionID, model, input),
		})
	default:
		prompt := settings.prompt
		if prompt == "" {
			prompt = defaultAuditPrompt()
		}
		return json.Marshal(map[string]any{
			"model":       settings.model,
			"temperature": 0,
			"stream":      false,
			"messages": []map[string]string{
				{"role": "system", "content": prompt},
				{"role": "user", "content": auditInputText(sessionID, model, input)},
			},
		})
	}
}

func defaultAuditPrompt() string {
	return strings.Join([]string{
		"You are a risk-control auditor for user prompts.",
		"Audit only the supplied user-authored content.",
		"Return compact JSON only with this schema:",
		`{"action":"allow|block","flagged":true|false,"reason":"short reason","categories":["category"]}`,
		"Use block only for clearly unsafe or policy-violating user requests.",
	}, "\n")
}

func auditInputText(sessionID string, model string, input AuditInput) string {
	var builder strings.Builder
	builder.WriteString("session_id: ")
	builder.WriteString(sessionID)
	builder.WriteString("\nmodel: ")
	builder.WriteString(model)
	builder.WriteString("\nmessage_count: ")
	builder.WriteString(fmt.Sprintf("%d", input.MessageCount))
	builder.WriteString("\n\n[user_messages]\n")
	builder.WriteString(input.Text)
	if len(input.Images) > 0 {
		builder.WriteString("\n\n[image_references]\n")
		for i, image := range input.Images {
			builder.WriteString(fmt.Sprintf("%d. %s\n", i+1, image))
		}
	}
	return builder.String()
}

func auditURL(settings settings) string {
	base := strings.TrimRight(settings.baseURL, "/")
	if base == "" {
		return ""
	}
	lowerBase := strings.ToLower(base)
	if strings.HasSuffix(lowerBase, "/chat/completions") || strings.HasSuffix(lowerBase, "/moderations") {
		return base
	}
	path := "/chat/completions"
	switch settings.endpoint {
	case EndpointModerations:
		path = "/moderations"
	case EndpointChatCompletions:
		path = "/chat/completions"
	default:
		if strings.HasPrefix(settings.endpoint, "/") {
			path = settings.endpoint
		}
	}
	return base + path
}

func nextAPIKey(keys []string) string {
	if len(keys) == 0 {
		return ""
	}
	idx := auditAPIKeyCursor.Add(1)
	return keys[int(idx-1)%len(keys)]
}

func newAuditHTTPClient(_ context.Context, cfg *config.Config, timeout time.Duration) *http.Client {
	client := &http.Client{}
	if timeout > 0 {
		client.Timeout = timeout
	}
	proxyURL := ""
	if cfg != nil {
		proxyURL = strings.TrimSpace(cfg.ProxyURL)
	}
	if proxyURL != "" {
		if transport, _, errBuild := proxyutil.BuildHTTPTransport(proxyURL); errBuild == nil && transport != nil {
			client.Transport = transport
		}
	}
	return client
}

func parseAuditDecision(settings settings, raw []byte) (Decision, error) {
	if flagged := gjson.GetBytes(raw, "results.0.flagged"); flagged.Exists() {
		reason := highestModerationCategory(raw)
		return Decision{Blocked: flagged.Bool(), Reason: reason}, nil
	}
	content := strings.TrimSpace(gjson.GetBytes(raw, "choices.0.message.content").String())
	if content == "" {
		if gjson.GetBytes(raw, "flagged").Exists() || gjson.GetBytes(raw, "action").Exists() {
			content = string(raw)
		} else {
			return Decision{}, fmt.Errorf("risk control: audit response missing decision content")
		}
	}
	jsonContent := extractJSONObject(content)
	if jsonContent == "" {
		return Decision{}, fmt.Errorf("risk control: audit decision is not JSON")
	}
	action := strings.ToLower(strings.TrimSpace(gjson.Get(jsonContent, "action").String()))
	flagged := gjson.Get(jsonContent, "flagged").Bool()
	blocked := flagged || action == "block" || action == "blocked" || action == "deny"
	reason := strings.TrimSpace(gjson.Get(jsonContent, "reason").String())
	if reason == "" {
		reason = strings.TrimSpace(gjson.Get(jsonContent, "category").String())
	}
	return Decision{Blocked: blocked, Reason: reason}, nil
}

func highestModerationCategory(raw []byte) string {
	categories := gjson.GetBytes(raw, "results.0.categories")
	if !categories.IsObject() {
		return ""
	}
	var out string
	categories.ForEach(func(key, value gjson.Result) bool {
		if value.Bool() {
			out = key.String()
			return false
		}
		return true
	})
	return out
}

func extractJSONObject(content string) string {
	content = strings.TrimSpace(content)
	content = strings.TrimPrefix(content, "```json")
	content = strings.TrimPrefix(content, "```")
	content = strings.TrimSuffix(content, "```")
	content = strings.TrimSpace(content)
	if gjson.Valid(content) && gjson.Parse(content).IsObject() {
		return content
	}
	start := strings.Index(content, "{")
	end := strings.LastIndex(content, "}")
	if start >= 0 && end > start {
		candidate := content[start : end+1]
		if gjson.Valid(candidate) && gjson.Parse(candidate).IsObject() {
			return candidate
		}
	}
	return ""
}

func codexSessionID(ctx context.Context, req executor.Request, opts executor.Options, payloads ...[]byte) string {
	if value := metadataString(opts.Metadata, executor.ExecutionSessionMetadataKey); value != "" {
		return "execution:" + value
	}
	if value := metadataString(req.Metadata, executor.ExecutionSessionMetadataKey); value != "" {
		return "execution:" + value
	}
	if value := codexSessionIDFromHeaders(opts.Headers); value != "" {
		return value
	}
	for _, payload := range payloads {
		if value := codexSessionIDFromPayload(payload); value != "" {
			return value
		}
	}
	if headers := headersFromGinContext(ctx); headers != nil {
		if value := codexSessionIDFromHeaders(headers); value != "" {
			return value
		}
	}
	return ""
}

func metadataString(meta map[string]any, key string) string {
	if len(meta) == 0 {
		return ""
	}
	raw, ok := meta[key]
	if !ok || raw == nil {
		return ""
	}
	switch value := raw.(type) {
	case string:
		return strings.TrimSpace(value)
	case []byte:
		return strings.TrimSpace(string(value))
	default:
		return ""
	}
}

func codexSessionIDFromHeaders(headers http.Header) string {
	if headers == nil {
		return ""
	}
	for _, key := range []string{"X-Session-ID", "Session-Id", "Session_id", "session_id"} {
		if value := firstHeaderValue(headers, key); value != "" {
			return "header:" + value
		}
	}
	if value := firstHeaderValue(headers, "Conversation_id"); value != "" {
		return "conversation:" + value
	}
	return ""
}

func firstHeaderValue(headers http.Header, key string) string {
	if headers == nil {
		return ""
	}
	if value := strings.TrimSpace(headers.Get(key)); value != "" {
		return value
	}
	for headerKey, values := range headers {
		if !strings.EqualFold(strings.TrimSpace(headerKey), key) {
			continue
		}
		for _, value := range values {
			if value = strings.TrimSpace(value); value != "" {
				return value
			}
		}
	}
	return ""
}

func codexSessionIDFromPayload(payload []byte) string {
	if len(payload) == 0 || !gjson.ValidBytes(payload) {
		return ""
	}
	if userID := strings.TrimSpace(gjson.GetBytes(payload, "metadata.user_id").String()); userID != "" {
		if strings.HasPrefix(userID, "{") {
			if sid := strings.TrimSpace(gjson.Get(userID, "session_id").String()); sid != "" {
				return "metadata-session:" + sid
			}
		}
		if matches := claudeSessionPattern.FindStringSubmatch(userID); len(matches) >= 2 {
			return "metadata-session:" + matches[1]
		}
	}
	if value := strings.TrimSpace(gjson.GetBytes(payload, "prompt_cache_key").String()); value != "" {
		return "prompt-cache:" + value
	}
	if value := strings.TrimSpace(gjson.GetBytes(payload, "client_metadata.x-codex-window-id").String()); value != "" {
		return "window:" + value
	}
	if value := strings.TrimSpace(gjson.GetBytes(payload, "conversation_id").String()); value != "" {
		return "conversation:" + value
	}
	return ""
}

func headersFromGinContext(ctx context.Context) http.Header {
	if ctx == nil {
		return nil
	}
	type ginContext interface {
		GetHeader(string) string
	}
	if ginCtx, ok := ctx.Value("gin").(ginContext); ok && ginCtx != nil {
		headers := make(http.Header)
		for _, key := range []string{"X-Session-ID", "Session-Id", "Session_id", "session_id", "Conversation_id"} {
			if value := strings.TrimSpace(ginCtx.GetHeader(key)); value != "" {
				headers.Set(key, value)
			}
		}
		return headers
	}
	return nil
}
