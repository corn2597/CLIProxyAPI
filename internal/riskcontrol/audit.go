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
	if _, ok, err := DefaultOverrideStore().Match(input.Hash, sessionID, now); err == nil && ok {
		return nil
	} else if err != nil {
		log.WithError(err).WithField("session_id", sessionID).Warn("risk control: failed to load manual override")
	}
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
		BlockedAt:         now,
		Provider:          "codex",
		SessionID:         sessionID,
		RequestedModel:    requestedModel,
		UpstreamModel:     strings.TrimSpace(req.Model),
		AuditModel:        settings.model,
		AuditEndpoint:     settings.endpoint,
		Mode:              settings.mode,
		SourceFormat:      strings.TrimSpace(opts.SourceFormat.String()),
		RequestPath:       requestPath,
		MessageCount:      input.MessageCount,
		InputHash:         input.Hash,
		UserTextPreview:   input.Text,
		ImageReferences:   input.Images,
		DecisionSource:    decisionSource,
		Reason:            decision.Reason,
		AuditError:        decision.Error,
		BlockMessage:      blockMessage,
		PolicyCode:        decision.PolicyCode,
		SubcategoryCode:   decision.SubcategoryCode,
		Confidence:        decision.Confidence,
		AuthorizedContext: decision.AuthorizedContext,
		MaliciousIntent:   decision.MaliciousIntent,
		Evidence:          cloneStrings(decision.Evidence),
		RawAuditResponse:  decision.RawResponse,
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
		return Decision{Blocked: true, Reason: "audit unavailable", Error: message, FailureClass: "audit_failed"}
	}
	return Decision{Blocked: false, Reason: "audit failed open", Error: message, FailureClass: "audit_failed"}
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
		if decision, ok := decisionFromAuditHTTPError(settings, raw); ok {
			return decision, nil
		}
		return Decision{}, fmt.Errorf("risk control audit HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return parseAuditDecision(settings, raw)
}

func decisionFromAuditHTTPError(settings settings, raw []byte) (Decision, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || !gjson.ValidBytes(trimmed) {
		return Decision{}, false
	}
	if code := strings.TrimSpace(gjson.GetBytes(trimmed, "error.code").String()); code != "risk_control_blocked" {
		return Decision{}, false
	}
	message := strings.TrimSpace(gjson.GetBytes(trimmed, "error.message").String())
	return Decision{
		Blocked: true,
		Reason:  normalizeBlockedReason(settings, message),
	}, true
}

func normalizeBlockedReason(settings settings, message string) string {
	trimmed := strings.TrimSpace(message)
	if trimmed == "" {
		return ""
	}
	for _, prefix := range []string{strings.TrimSpace(settings.blockMessage), defaultBlockMessage} {
		if prefix == "" || !strings.HasPrefix(trimmed, prefix) {
			continue
		}
		reason := strings.TrimSpace(strings.TrimPrefix(trimmed, prefix))
		reason = strings.TrimSpace(strings.TrimPrefix(reason, ":"))
		return reason
	}
	return trimmed
}

func auditRequestBody(settings settings, sessionID string, model string, input AuditInput) ([]byte, error) {
	switch settings.endpoint {
	case EndpointModerations:
		return json.Marshal(map[string]any{
			"model": settings.model,
			"input": auditInputText(sessionID, model, input),
		})
	case EndpointResponses:
		return json.Marshal(map[string]any{
			"model":        settings.model,
			"store":        false,
			"instructions": defaultAuditPrompt(),
			"input": []map[string]any{
				{
					"type": "message",
					"role": "user",
					"content": []map[string]any{
						{
							"type": "input_text",
							"text": auditInputText(sessionID, model, input),
						},
					},
				},
			},
			"text": map[string]any{
				"format": map[string]any{
					"type":   "json_schema",
					"name":   "risk_control_decision",
					"strict": true,
					"schema": auditDecisionSchema(),
				},
			},
		})
	default:
		return json.Marshal(map[string]any{
			"model":       settings.model,
			"temperature": 0,
			"stream":      false,
			"messages": []map[string]string{
				{"role": "system", "content": defaultAuditPrompt()},
				{"role": "user", "content": auditInputText(sessionID, model, input)},
			},
		})
	}
}

func auditInputText(sessionID string, model string, input AuditInput) string {
	var builder strings.Builder
	_ = sessionID
	_ = model
	builder.WriteString("<user_input>\n")
	builder.WriteString(strings.TrimSpace(input.Text))
	if len(input.Images) > 0 {
		if strings.TrimSpace(input.Text) != "" {
			builder.WriteString("\n\n")
		}
		builder.WriteString("[image_references]\n")
		for i, image := range input.Images {
			builder.WriteString(fmt.Sprintf("%d. %s\n", i+1, image))
		}
	}
	if !strings.HasSuffix(builder.String(), "\n") {
		builder.WriteString("\n")
	}
	builder.WriteString("</user_input>")
	return builder.String()
}

func auditURL(settings settings) string {
	base := strings.TrimRight(settings.baseURL, "/")
	if base == "" {
		return ""
	}
	lowerBase := strings.ToLower(base)
	if strings.HasSuffix(lowerBase, "/chat/completions") || strings.HasSuffix(lowerBase, "/moderations") || strings.HasSuffix(lowerBase, "/responses") {
		return base
	}
	path := "/responses"
	switch settings.endpoint {
	case EndpointModerations:
		path = "/moderations"
	case EndpointChatCompletions:
		path = "/chat/completions"
	case EndpointResponses:
		path = "/responses"
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
		policyCode := moderationPolicyCodeFromResponse(raw)
		if policyCode == "" {
			return Decision{Blocked: false}, nil
		}
		return Decision{Blocked: true, Reason: policyCode, PolicyCode: policyCode}, nil
	}
	content := strings.TrimSpace(extractResponsesOutputText(raw))
	if content == "" {
		content = strings.TrimSpace(gjson.GetBytes(raw, "choices.0.message.content").String())
	}
	if content == "" {
		if gjson.GetBytes(raw, "decision").Exists() || gjson.GetBytes(raw, "action").Exists() || gjson.GetBytes(raw, "policy_code").Exists() || gjson.GetBytes(raw, "policyCode").Exists() {
			content = string(raw)
		} else {
			return Decision{}, fmt.Errorf("risk control: audit response missing decision content")
		}
	}
	jsonContent := extractJSONObject(content)
	if jsonContent == "" {
		return Decision{}, fmt.Errorf("risk control: audit decision is not JSON")
	}
	action := normalizeAuditAction(gjson.Get(jsonContent, "decision").String())
	if action == "" {
		action = normalizeAuditAction(gjson.Get(jsonContent, "action").String())
	}
	flagged := gjson.Get(jsonContent, "flagged")
	switch action {
	case "allow":
		if flagged.Exists() && flagged.Bool() {
			return Decision{}, fmt.Errorf("risk control: inconsistent allow decision with flagged=true")
		}
		return Decision{Blocked: false}, nil
	case "block":
		if flagged.Exists() && !flagged.Bool() {
			return Decision{}, fmt.Errorf("risk control: inconsistent block decision with flagged=false")
		}
		policyCode := extractAuditPolicyCode(jsonContent)
		if !isOpenAIHardStopPolicyCode(policyCode) {
			return Decision{}, fmt.Errorf("risk control: unsupported policy_code %q", policyCode)
		}
		subcategoryCode := extractAuditSubcategoryCode(jsonContent)
		if !isOpenAIHardStopSubcategoryCode(subcategoryCode) {
			return Decision{}, fmt.Errorf("risk control: unsupported subcategory_code %q", subcategoryCode)
		}
		confidence, err := extractAuditConfidence(jsonContent)
		if err != nil {
			return Decision{}, err
		}
		reason := strings.TrimSpace(gjson.Get(jsonContent, "reason").String())
		if reason == "" {
			reason = normalizePolicyCode(policyCode)
		}
		decision := Decision{
			Blocked:           confidence >= settings.blockThreshold,
			Reason:            reason,
			PolicyCode:        policyCode,
			SubcategoryCode:   subcategoryCode,
			Confidence:        confidence,
			AuthorizedContext: normalizeAuthorizedContext(gjson.Get(jsonContent, "authorized_context").String()),
			MaliciousIntent:   gjson.Get(jsonContent, "malicious_intent").Bool(),
			Evidence:          extractAuditEvidence(jsonContent),
			RawResponse:       strings.TrimSpace(content),
		}
		return decision, nil
	default:
		return Decision{}, fmt.Errorf("risk control: audit response missing valid action")
	}
}

func moderationPolicyCodeFromResponse(raw []byte) string {
	categories := gjson.GetBytes(raw, "results.0.categories")
	if !categories.IsObject() {
		return ""
	}
	for _, key := range []string{
		"sexual/minors",
		"self-harm/instructions",
		"illicit/violent",
	} {
		if categories.Get(key).Bool() {
			return moderationCategoryPolicyCode(key)
		}
	}
	return ""
}

func normalizeAuditAction(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "allow", "allowed", "ok":
		return "allow"
	case "block", "blocked", "deny", "denied":
		return "block"
	default:
		return ""
	}
}

func extractAuditPolicyCode(jsonContent string) string {
	for _, path := range []string{"policy_code", "policyCode", "category", "categories.0"} {
		if value := strings.TrimSpace(gjson.Get(jsonContent, path).String()); value != "" {
			return normalizePolicyCode(value)
		}
	}
	return ""
}

func extractAuditSubcategoryCode(jsonContent string) string {
	for _, path := range []string{"subcategory_code", "subcategoryCode", "subcategory", "subcategories.0"} {
		if value := strings.TrimSpace(gjson.Get(jsonContent, path).String()); value != "" {
			return normalizeSubcategoryCode(value)
		}
	}
	return ""
}

func extractAuditConfidence(jsonContent string) (float64, error) {
	if value := gjson.Get(jsonContent, "confidence"); value.Exists() {
		switch value.Type {
		case gjson.Number:
			confidence := value.Float()
			if confidence <= 0 || confidence > 1 {
				return 0, fmt.Errorf("risk control: invalid confidence %v", confidence)
			}
			return confidence, nil
		case gjson.String:
			switch strings.ToLower(strings.TrimSpace(value.String())) {
			case "high":
				return 0.99, nil
			case "medium", "med":
				return 0.75, nil
			case "low":
				return 0.25, nil
			}
		}
	}
	return 0, fmt.Errorf("risk control: audit response missing valid confidence")
}

func extractAuditEvidence(jsonContent string) []string {
	evidence := gjson.Get(jsonContent, "evidence")
	if !evidence.IsArray() {
		return nil
	}
	values := make([]string, 0, 2)
	evidence.ForEach(func(_, item gjson.Result) bool {
		if len(values) >= 2 {
			return false
		}
		text := strings.TrimSpace(item.String())
		if text != "" {
			values = append(values, text)
		}
		return true
	})
	return values
}

func normalizeAuthorizedContext(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "authorized":
		return "authorized"
	case "unauthorized":
		return "unauthorized"
	default:
		return "unknown"
	}
}

func extractResponsesOutputText(raw []byte) string {
	for _, path := range []string{"output_text", "response.output_text"} {
		if value := strings.TrimSpace(gjson.GetBytes(raw, path).String()); value != "" {
			return value
		}
	}

	for _, path := range []string{"output", "response.output"} {
		output := gjson.GetBytes(raw, path)
		if !output.IsArray() {
			continue
		}
		parts := make([]string, 0, 4)
		output.ForEach(func(_, item gjson.Result) bool {
			itemType := strings.ToLower(strings.TrimSpace(item.Get("type").String()))
			if itemType != "" && itemType != "message" {
				return true
			}
			content := item.Get("content")
			if !content.IsArray() {
				return true
			}
			content.ForEach(func(_, part gjson.Result) bool {
				partType := strings.ToLower(strings.TrimSpace(part.Get("type").String()))
				if partType != "" && partType != "output_text" && partType != "text" {
					return true
				}
				text := strings.TrimSpace(part.Get("text").String())
				if text != "" {
					parts = append(parts, text)
				}
				return true
			})
			return true
		})
		if len(parts) > 0 {
			return strings.Join(parts, "\n")
		}
	}

	return ""
}

func auditDecisionSchema() map[string]any {
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"properties": map[string]any{
			"flagged": map[string]any{
				"type": "boolean",
			},
			"decision": map[string]any{
				"type": "string",
				"enum": []string{"allow", "block"},
			},
			"policy_code": map[string]any{
				"type": "string",
				"enum": openAIHardStopPolicyCodeValues,
			},
			"subcategory_code": map[string]any{
				"type": "string",
				"enum": openAIHardStopSubcategoryCodeValues,
			},
			"confidence": map[string]any{
				"type":    "number",
				"minimum": 0,
				"maximum": 1,
			},
			"authorized_context": map[string]any{
				"type": "string",
				"enum": []string{"authorized", "unauthorized", "unknown"},
			},
			"malicious_intent": map[string]any{
				"type": "boolean",
			},
			"evidence": map[string]any{
				"type":     "array",
				"maxItems": 2,
				"items": map[string]any{
					"type": "string",
				},
			},
			"reason": map[string]any{
				"type": "string",
			},
		},
		"required": []string{
			"flagged",
			"decision",
			"policy_code",
			"subcategory_code",
			"confidence",
			"authorized_context",
			"malicious_intent",
			"evidence",
			"reason",
		},
	}
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
