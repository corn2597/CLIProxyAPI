package riskcontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
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
	summaryInput := summarizeAuditInput(input)
	meta := newAuditRecordMeta(req, opts)

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
	if settings.auditsAsynchronously() {
		decision, decisionSource, scheduled := defaultTracker.admitAsync(sessionID, now, settings.sessionAuditInterval, settings.sessionTTL, settings.usesBlockedBans())
		if decisionSource == DecisionSourceBlockedBan && decision.Blocked {
			return blockedDecisionError(settings, decision)
		}
		if scheduled {
			task, err := newAsyncCodexAuditTask(cfg, settings, sessionID, meta, input)
			if err != nil {
				log.WithError(err).WithField("session_id", sessionID).Warn("risk control: failed to stage async audit")
				queueDecision := asyncAuditEnqueueFailureDecision(err)
				recordCodexAuditLog(now, 0, settings, sessionID, meta, summaryInput, queueDecision)
				defaultTracker.completeAsyncAudit(sessionID, now, settings.sessionTTL, settings.blockedSessionTTL, settings.asyncRetryDelay, settings.usesBlockedBans(), queueDecision)
			} else if err := defaultAsyncAuditDispatcher.Enqueue(task); err != nil {
				defaultAuditSpoolStore.Remove(task.inputRef)
				log.WithError(err).WithField("session_id", sessionID).Warn("risk control: failed to enqueue async audit")
				queueDecision := asyncAuditEnqueueFailureDecision(err)
				recordCodexAuditLog(now, 0, settings, sessionID, meta, summaryInput, queueDecision)
				defaultTracker.completeAsyncAudit(sessionID, now, settings.sessionTTL, settings.blockedSessionTTL, settings.asyncRetryDelay, settings.usesBlockedBans(), queueDecision)
			}
		}
		return nil
	}
	audit := func() Decision {
		auditStartedAt := time.Now()
		auditDecision := performAudit(ctx, cfg, settings, sessionID, req.Model, input)
		recordCodexAuditLog(auditStartedAt, time.Since(auditStartedAt), settings, sessionID, meta, summaryInput, auditDecision)
		return auditDecision
	}
	var decision Decision
	var decisionSource string
	if settings.usesBlockedBans() {
		decision, decisionSource = defaultTracker.evaluate(sessionID, now, settings.sessionAuditInterval, settings.sessionTTL, settings.blockedSessionTTL, audit)
	} else {
		decision, decisionSource = defaultTracker.evaluateWithoutBlockedBans(sessionID, now, settings.sessionAuditInterval, settings.sessionTTL, audit)
	}
	if decisionSource == DecisionSourceFreshAudit {
		log.WithFields(log.Fields{
			"provider":        "codex",
			"session_id":      sessionID,
			"blocked":         decision.Blocked,
			"observe_only":    decision.ObserveOnly,
			"error":           decision.Error,
			"decision_source": decisionSource,
		}).Debug("risk control: audited codex session")
	}
	if decisionSource == DecisionSourceFreshAudit && shouldRecordObserveEvent(settings, decision) {
		recordCodexObserveEvent(now, settings, sessionID, meta, summaryInput, decision, decisionSource)
	}
	if decisionSource == DecisionSourceFreshAudit && decision.Blocked && shouldRecordBlockedEvent(settings, decision) {
		recordCodexBlockedEvent(now, settings, sessionID, meta, summaryInput, decision, decisionSource, riskControlBlockMessage(settings, decision))
	}
	if settings.enforcesCurrentRequest() && decision.Blocked {
		return blockedDecisionError(settings, decision)
	}
	return nil
}

func shouldRecordBlockedEvent(settings settings, decision Decision) bool {
	if !decision.Blocked || decision.Error != "" {
		return false
	}
	switch settings.mode {
	case ModePreBlock, ModeAsyncBlock:
		return true
	default:
		return false
	}
}

func shouldRecordObserveEvent(settings settings, decision Decision) bool {
	if decision.Error != "" {
		return false
	}
	if decision.ObserveOnly {
		return true
	}
	return settings.mode == ModeObserve && decision.Blocked
}

func blockedDecisionError(settings settings, decision Decision) error {
	message := riskControlBlockMessage(settings, decision)
	status := settings.blockStatus
	if status <= 0 {
		status = defaultBlockStatus
	}
	return RiskError{status: status, code: "risk_control_blocked", message: message}
}

func riskControlBlockMessage(settings settings, decision Decision) string {
	message := settings.blockMessage
	if decision.Reason != "" {
		message = message + ": " + decision.Reason
	}
	return message
}

func recordCodexBlockedEvent(now time.Time, settings settings, sessionID string, meta auditRecordMeta, input AuditInput, decision Decision, decisionSource string, blockMessage string) {
	event := codexRiskControlEvent(now, settings, sessionID, meta, input, decision, decisionSource)
	event.BlockMessage = blockMessage
	DefaultBlockedEventStore().RecordBlockedEvent(event)
}

func recordCodexObserveEvent(now time.Time, settings settings, sessionID string, meta auditRecordMeta, input AuditInput, decision Decision, decisionSource string) {
	event := codexRiskControlEvent(now, settings, sessionID, meta, input, decision, decisionSource)
	event.DecisionSource = DecisionSourceObserveOnly
	event.BlockMessage = ""
	DefaultObserveEventStore().RecordBlockedEvent(event)
}

func recordCodexAuditLog(auditedAt time.Time, duration time.Duration, settings settings, sessionID string, meta auditRecordMeta, input AuditInput, decision Decision) {
	entry := codexAuditLogEntry(auditedAt, duration, settings, sessionID, meta, input, decision)
	DefaultAuditLogStore().RecordAuditLog(entry)
}

func codexAuditLogEntry(auditedAt time.Time, duration time.Duration, settings settings, sessionID string, meta auditRecordMeta, input AuditInput, decision Decision) AuditLogEntry {
	return AuditLogEntry{
		AuditedAt:         auditedAt,
		DurationMS:        duration.Milliseconds(),
		Provider:          "codex",
		SessionID:         sessionID,
		RequestedModel:    meta.RequestedModel,
		UpstreamModel:     meta.UpstreamModel,
		AuditModel:        settings.model,
		AuditEndpoint:     settings.endpoint,
		Mode:              settings.mode,
		Threshold:         settings.blockThreshold,
		SourceFormat:      meta.SourceFormat,
		RequestPath:       meta.RequestPath,
		MessageCount:      input.MessageCount,
		InputHash:         input.Hash,
		UserTextPreview:   input.Text,
		ImageReferences:   input.Images,
		Decision:          auditLogDecision(decision),
		Debug:             settings.debug,
		Enforced:          settings.enforcesCurrentRequest() && decision.Blocked,
		BanApplied:        settings.usesBlockedBans() && decision.Blocked && decision.Error == "",
		Blocked:           decision.Blocked,
		ObserveOnly:       decision.ObserveOnly,
		PolicyCode:        decision.PolicyCode,
		SubcategoryCode:   decision.SubcategoryCode,
		Confidence:        decision.Confidence,
		AuthorizedContext: decision.AuthorizedContext,
		MaliciousIntent:   decision.MaliciousIntent,
		Evidence:          cloneStrings(decision.Evidence),
		Reason:            decision.Reason,
		AuditError:        decision.Error,
		FailureClass:      decision.FailureClass,
		RawAuditResponse:  decision.RawResponse,
	}
}

func auditLogDecision(decision Decision) string {
	if decision.Error != "" || decision.FailureClass != "" {
		return "error"
	}
	if decision.Blocked {
		return "block"
	}
	if decision.ObserveOnly {
		return "observe"
	}
	return "allow"
}

func codexRiskControlEvent(now time.Time, settings settings, sessionID string, meta auditRecordMeta, input AuditInput, decision Decision, decisionSource string) BlockEvent {
	if decisionSource == "" {
		decisionSource = DecisionSourceFreshAudit
	}

	return BlockEvent{
		BlockedAt:         now,
		Provider:          "codex",
		SessionID:         sessionID,
		RequestedModel:    meta.RequestedModel,
		UpstreamModel:     meta.UpstreamModel,
		AuditModel:        settings.model,
		AuditEndpoint:     settings.endpoint,
		Mode:              settings.mode,
		SourceFormat:      meta.SourceFormat,
		RequestPath:       meta.RequestPath,
		MessageCount:      input.MessageCount,
		InputHash:         input.Hash,
		UserTextPreview:   input.Text,
		ImageReferences:   input.Images,
		DecisionSource:    decisionSource,
		Debug:             settings.debug,
		BanApplied:        settings.usesBlockedBans() && decision.Blocked && decision.Error == "",
		Reason:            decision.Reason,
		AuditError:        decision.Error,
		PolicyCode:        decision.PolicyCode,
		SubcategoryCode:   decision.SubcategoryCode,
		Confidence:        decision.Confidence,
		AuthorizedContext: decision.AuthorizedContext,
		MaliciousIntent:   decision.MaliciousIntent,
		Evidence:          cloneStrings(decision.Evidence),
		RawAuditResponse:  decision.RawResponse,
	}
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
	rawResponse := decision.RawResponse
	if isModerationRawResponse(rawResponse) {
		decision.RawResponse = ""
	}
	decision = applyAuditInputGuard(input, decision)
	if decision.RawResponse == "" {
		decision.RawResponse = rawResponse
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
	_ = sessionID
	_ = model
	switch settings.endpoint {
	case EndpointModerations:
		return json.Marshal(map[string]any{
			"model": settings.model,
			"input": moderationInputText(input),
		})
	case EndpointResponses:
		return json.Marshal(map[string]any{
			"model":        settings.model,
			"store":        false,
			"temperature":  0,
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

func moderationInputText(input AuditInput) string {
	var builder strings.Builder

	text := strings.TrimSpace(input.Text)
	if strings.TrimSpace(input.FocusStatus) == auditFocusExtracted && strings.TrimSpace(input.FocusText) != "" {
		text = strings.TrimSpace(input.FocusText)
	}
	builder.WriteString(text)

	if len(input.Images) > 0 {
		if builder.Len() > 0 {
			builder.WriteString("\n\n")
		}
		builder.WriteString("[image_references]\n")
		for i, image := range input.Images {
			builder.WriteString(fmt.Sprintf("%d. %s\n", i+1, image))
		}
	}

	return strings.TrimSpace(builder.String())
}

func auditInputText(sessionID string, model string, input AuditInput) string {
	var builder strings.Builder
	_ = sessionID
	_ = model
	focusStatus := strings.TrimSpace(input.FocusStatus)
	if focusStatus == "" {
		focusStatus = auditFocusAmbiguous
	}
	builder.WriteString("<gateway_current_user_request status=\"")
	builder.WriteString(focusStatus)
	builder.WriteString("\"")
	if reason := strings.TrimSpace(input.FocusReason); reason != "" {
		builder.WriteString(" reason=\"")
		builder.WriteString(escapeAuditAttribute(reason))
		builder.WriteString("\"")
	}
	builder.WriteString(">\n")
	builder.WriteString(strings.TrimSpace(input.FocusText))
	if !strings.HasSuffix(builder.String(), "\n") {
		builder.WriteString("\n")
	}
	builder.WriteString("</gateway_current_user_request>\n\n")
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

func escapeAuditAttribute(value string) string {
	value = strings.ReplaceAll(value, "&", "&amp;")
	value = strings.ReplaceAll(value, `"`, "&quot;")
	value = strings.ReplaceAll(value, "<", "&lt;")
	value = strings.ReplaceAll(value, ">", "&gt;")
	return value
}

func applyAuditInputGuard(input AuditInput, decision Decision) Decision {
	if !decision.Blocked && !decision.ObserveOnly {
		return decision
	}
	if strings.TrimSpace(decision.RawResponse) == "" {
		return decision
	}
	focus := strings.TrimSpace(input.FocusText)
	if strings.TrimSpace(input.FocusStatus) != auditFocusExtracted || focus == "" {
		return downgradeDecisionForFocus(decision, "当前请求不明确")
	}
	if matchesMandatoryAllowFocus(focus) {
		return downgradeDecisionForFocus(decision, "强制放行场景")
	}
	if len(decision.Evidence) == 0 {
		return downgradeDecisionForFocus(decision, "缺少当前请求证据")
	}
	focusNorm := normalizeEvidenceComparable(focus)
	for _, evidence := range decision.Evidence {
		evidenceNorm := normalizeEvidenceComparable(evidence)
		if evidenceNorm != "" && strings.Contains(focusNorm, evidenceNorm) {
			return decision
		}
	}
	return downgradeDecisionForFocus(decision, "证据不在当前请求")
}

func downgradeDecisionForFocus(decision Decision, reason string) Decision {
	decision.Blocked = false
	decision.ObserveOnly = false
	decision.Reason = reason
	decision.PolicyCode = "none"
	decision.SubcategoryCode = "none"
	decision.Confidence = 0
	decision.AuthorizedContext = "unknown"
	decision.MaliciousIntent = false
	decision.Evidence = nil
	return decision
}

func normalizeEvidenceComparable(text string) string {
	text = strings.ToLower(strings.TrimSpace(text))
	text = strings.Join(strings.Fields(text), "")
	return text
}

func matchesMandatoryAllowFocus(text string) bool {
	lower := strings.ToLower(strings.TrimSpace(text))
	if lower == "" || containsHardStopIndicator(lower) {
		return false
	}
	for _, group := range [][]string{
		{"risk-control", "audit", "审计", "误杀", "样本", "打标", "blocked log", "prompt", "policy"},
		{"ssh", "root@", "服务器", "容器", "日志", "监控", "部署", "排查", "健康检查", "curl", "pip install", "权限"},
		{"合法 api", "api.tikhub", "get /api", "报表", "数据整理", "业务测试", "测试村点", "测试数据", "虚拟货量", "无视距离核查"},
		{"报错", "修 bug", "修复", "生产地址", "生产机", "数据库问题", "账号", "密码", "页面", "组件", "element-plus", "资金流水", "chrome", "完成以下任务"},
		{"小说", "角色设定", "架构agent", "subagent", "视频脚本", "文案", "创意写作"},
		{"数据底座", "选股", "交易机会", "btc", "eth", "a-share"},
	} {
		if containsAny(lower, group) {
			return true
		}
	}
	return false
}

func containsHardStopIndicator(lower string) bool {
	phrases := []string{
		"儿童色情",
		"未成年情色",
		"未成年人性",
		"绕过 cloudflare",
		"绕过验证码",
		"自动登录撞库",
		"凭据填充",
		"密码爆破",
		"窃取",
		"盗取",
		"收集账号密码",
		"导出密码",
		"cookie窃取",
		"credential theft",
		"webshell",
		"反弹 shell",
		"免杀",
		"keygen",
		"license bypass",
		"drm bypass",
		"逆向抖音",
		"逆向 tiktok",
		"逆向第三方app",
		"反编译微信",
		"小红书签名算法",
		"钓鱼邮件",
		"phishing",
	}
	if containsAny(lower, phrases) {
		return true
	}
	toolTerms := []string{"hydra", "sqlmap", "metasploit", "cobalt strike"}
	if containsAny(lower, toolTerms) && containsAny(lower, []string{"攻击", "入侵", "爆破", "真实目标", "实战"}) {
		return true
	}
	return false
}

func containsAny(text string, needles []string) bool {
	for _, needle := range needles {
		if strings.Contains(text, needle) {
			return true
		}
	}
	return false
}

func auditURL(settings settings) string {
	base := strings.TrimRight(settings.baseURL, "/")
	if base == "" {
		return ""
	}
	lowerBase := strings.ToLower(base)
	for _, suffix := range []string{"/chat/completions", "/moderations", "/responses"} {
		if strings.HasSuffix(lowerBase, suffix) {
			base = base[:len(base)-len(suffix)]
			break
		}
	}
	path := "/moderations"
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

func isModerationRawResponse(raw string) bool {
	raw = strings.TrimSpace(raw)
	return raw != "" && gjson.Valid(raw) && gjson.Get(raw, "results.0.flagged").Exists()
}

func parseAuditDecision(settings settings, raw []byte) (Decision, error) {
	_ = settings

	result := gjson.GetBytes(raw, "results.0")
	if !result.Exists() {
		return Decision{}, fmt.Errorf("risk control: moderation response missing results[0]")
	}
	flagged := result.Get("flagged")
	if !flagged.Exists() {
		return Decision{}, fmt.Errorf("risk control: moderation response missing flagged")
	}

	matches := moderationMatches(result)
	rawResponse := strings.TrimSpace(string(raw))
	if len(matches) == 0 {
		if flagged.Bool() {
			return Decision{
				ObserveOnly:       true,
				Reason:            "flagged by moderation",
				PolicyCode:        "moderation_flagged",
				SubcategoryCode:   "flagged",
				RawResponse:       rawResponse,
				AuthorizedContext: "unknown",
			}, nil
		}
		return Decision{
			Blocked:           false,
			Reason:            "",
			PolicyCode:        "none",
			SubcategoryCode:   "none",
			AuthorizedContext: "unknown",
			RawResponse:       rawResponse,
		}, nil
	}

	primary := matches[0]
	hardBlocked := false
	confidence := 0.0
	for _, match := range matches {
		if match.Score > confidence {
			confidence = match.Score
		}
		if match.HardBlock {
			hardBlocked = true
		}
	}
	if confidence <= 0 {
		confidence = primary.Score
	}
	if confidence <= 0 {
		confidence = 1
	}

	decision := Decision{
		Blocked:           hardBlocked,
		ObserveOnly:       !hardBlocked,
		Reason:            primary.Reason,
		PolicyCode:        primary.PolicyCode,
		SubcategoryCode:   primary.SubcategoryCode,
		Confidence:        confidence,
		AuthorizedContext: "unknown",
		MaliciousIntent:   primary.MaliciousIntent,
		Evidence:          cloneStrings(primary.Evidence),
		RawResponse:       rawResponse,
	}
	if decision.Reason == "" {
		if decision.Blocked {
			decision.Reason = "blocked by moderation"
		} else {
			decision.Reason = "observe only"
		}
	}
	return decision, nil
}

type moderationMatch struct {
	Category        string
	PolicyCode      string
	SubcategoryCode string
	Reason          string
	Score           float64
	HardBlock       bool
	MaliciousIntent bool
	Evidence        []string
}

func moderationMatches(result gjson.Result) []moderationMatch {
	categories := result.Get("categories")
	if !categories.IsObject() {
		return nil
	}

	matches := make([]moderationMatch, 0, 4)
	categories.ForEach(func(key, value gjson.Result) bool {
		if !value.Bool() {
			return true
		}
		category := strings.TrimSpace(key.String())
		if category == "" {
			return true
		}
		matches = append(matches, moderationMatchForCategory(result, category))
		return true
	})

	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].HardBlock != matches[j].HardBlock {
			return matches[i].HardBlock
		}
		if matches[i].Score == matches[j].Score {
			return matches[i].Category < matches[j].Category
		}
		return matches[i].Score > matches[j].Score
	})

	return matches
}

func moderationMatchForCategory(result gjson.Result, category string) moderationMatch {
	score := result.Get("category_scores").Get(category).Float()
	subcategory := normalizeModerationCategoryCode(category)

	match := moderationMatch{
		Category:        category,
		PolicyCode:      "moderation_flagged",
		SubcategoryCode: subcategory,
		Reason:          "moderation flagged category: " + category,
		Score:           score,
		HardBlock:       false,
		MaliciousIntent: false,
		Evidence:        []string{category},
	}

	switch category {
	case "sexual/minors":
		match.PolicyCode = "child_sexual_abuse_or_grooming"
		match.SubcategoryCode = "child_sexual_content"
		match.Reason = "moderation blocked category: sexual/minors"
		match.HardBlock = true
		match.MaliciousIntent = true
	case "self-harm/instructions":
		match.PolicyCode = "self_harm_facilitation"
		match.SubcategoryCode = "self_harm_instruction"
		match.Reason = "moderation blocked category: self-harm/instructions"
		match.HardBlock = true
	case "illicit/violent":
		match.PolicyCode = "terror_or_violent_harm"
		match.SubcategoryCode = "illicit_violent"
		match.Reason = "moderation blocked category: illicit/violent"
		match.HardBlock = true
		match.MaliciousIntent = true
	}

	return match
}

func normalizeModerationCategoryCode(raw string) string {
	value := strings.ToLower(strings.TrimSpace(raw))
	value = strings.NewReplacer("-", "_", "/", "_", " ", "_").Replace(value)
	for strings.Contains(value, "__") {
		value = strings.ReplaceAll(value, "__", "_")
	}
	return strings.Trim(value, "_")
}

func applyHardStopEnforcement(decision Decision) Decision {
	if !decision.Blocked {
		return decision
	}
	if isEnforcedHardStop(decision.PolicyCode, decision.SubcategoryCode) {
		return decision
	}
	decision.Blocked = false
	decision.ObserveOnly = true
	if decision.Reason == "" {
		decision.Reason = "observe only"
	}
	return decision
}

func isEnforcedHardStop(policyCode string, subcategoryCode string) bool {
	policyCode = normalizePolicyCode(policyCode)
	subcategoryCode = normalizeSubcategoryCode(subcategoryCode)
	if policyCode == "malicious_cyber_abuse" {
		switch subcategoryCode {
		case "exploit_or_intrusion_code",
			"malware_or_evasion",
			"attack_tool_operational_guidance",
			"reverse_cracking_or_drm_bypass",
			"anti_bot_evasion_or_mass_scraping",
			"captcha_bypass_or_credential_attack",
			"bulk_account_abuse_or_spam_fraud",
			"bulk_fake_engagement_or_order_manipulation":
			return true
		default:
			return false
		}
	}
	switch policyCode {
	case "child_sexual_abuse_or_grooming",
		"nonconsensual_intimate_or_sexual_violence",
		"self_harm_facilitation",
		"terror_or_violent_harm",
		"weapons_assistance",
		"fraud_scam_impersonation",
		"safeguard_bypass_for_disallowed_content":
		return true
	default:
		return false
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
	case "observe", "observed", "review", "manual_review", "manual-review":
		return "observe"
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
				"enum": []string{"allow", "block", "observe"},
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
	if value := strings.TrimSpace(gjson.GetBytes(payload, "metadata.session_id").String()); value != "" {
		return "metadata-session:" + value
	}
	if value := strings.TrimSpace(gjson.GetBytes(payload, "metadata.conversation_id").String()); value != "" {
		return "conversation:" + value
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
