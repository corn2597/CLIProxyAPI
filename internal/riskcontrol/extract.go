package riskcontrol

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	"github.com/tidwall/gjson"
)

// AuditInput is the sanitized user-authored content sent to the audit model.
type AuditInput struct {
	Text         string
	Images       []string
	MessageCount int
	Hash         string
	FocusText    string
	FocusStatus  string
	FocusReason  string
}

type auditTurn struct {
	Text   string
	Images []string
}

const defaultAuditContextBackfillTurns = 2

const (
	auditFocusExtracted = "extracted"
	auditFocusAmbiguous = "ambiguous"
)

func (i AuditInput) Empty() bool {
	return strings.TrimSpace(i.Text) == "" && len(i.Images) == 0
}

// ExtractLatestEffectiveUserInput collects the latest user intent, with small user-only backfill for continuation prompts.
func ExtractLatestEffectiveUserInput(format sdktranslator.Format, payload []byte, maxRunes int, maxImages int) AuditInput {
	if len(payload) == 0 || !gjson.ValidBytes(payload) {
		return AuditInput{}
	}
	turns := collectUserTurns(format, payload)
	turns = sanitizeAuditTurns(turns)
	selected := selectEffectiveAuditTurns(turns, defaultAuditContextBackfillTurns)
	if len(selected) == 0 {
		return AuditInput{}
	}

	parts := make([]string, 0, len(selected))
	images := make([]string, 0, maxImages)
	messages := 0
	for _, turn := range selected {
		if strings.TrimSpace(turn.Text) == "" && len(turn.Images) == 0 {
			continue
		}
		if turn.Text != "" {
			parts = append(parts, turn.Text)
		}
		for _, image := range turn.Images {
			addImageURL(&images, image, maxImages)
		}
		messages++
	}
	text := truncateRunes(normalizeAuditText(strings.Join(parts, "\n\n")), maxRunes)
	hash := sha256.Sum256([]byte(text + "\n" + strings.Join(images, "\n")))
	focusText, focusStatus, focusReason := deriveAuditFocusFromText(text)
	return AuditInput{
		Text:         text,
		Images:       images,
		MessageCount: messages,
		Hash:         hex.EncodeToString(hash[:]),
		FocusText:    focusText,
		FocusStatus:  focusStatus,
		FocusReason:  focusReason,
	}
}

// ExtractFullUserInput collects all user-role content from the request payload.
func ExtractFullUserInput(format sdktranslator.Format, payload []byte, maxRunes int, maxImages int) AuditInput {
	if len(payload) == 0 || !gjson.ValidBytes(payload) {
		return AuditInput{}
	}
	turns := collectUserTurns(format, payload)
	var parts []string
	var images []string
	messages := 0
	for _, turn := range turns {
		beforeParts := len(parts)
		beforeImages := len(images)
		addAuditText(&parts, turn.Text)
		for _, image := range turn.Images {
			addImageURL(&images, image, maxImages)
		}
		if len(parts) > beforeParts || len(images) > beforeImages {
			messages++
		}
	}
	text := normalizeAuditText(strings.Join(parts, "\n\n"))
	hash := sha256.Sum256([]byte(text + "\n" + strings.Join(images, "\n")))
	focusText, focusStatus, focusReason := deriveAuditFocusFromTurns(turns)
	return AuditInput{
		Text:         text,
		Images:       images,
		MessageCount: messages,
		Hash:         hex.EncodeToString(hash[:]),
		FocusText:    focusText,
		FocusStatus:  focusStatus,
		FocusReason:  focusReason,
	}
}

func collectUserTurns(format sdktranslator.Format, payload []byte) []auditTurn {
	switch strings.ToLower(strings.TrimSpace(format.String())) {
	case sdktranslator.FormatOpenAI.String():
		return collectRoleMessageTurns(gjson.GetBytes(payload, "messages"), "user")
	case sdktranslator.FormatOpenAIResponse.String(), "responses", "openai-responses":
		return collectResponsesUserTurns(gjson.GetBytes(payload, "input"))
	case sdktranslator.FormatClaude.String():
		return collectRoleMessageTurns(gjson.GetBytes(payload, "messages"), "user")
	case sdktranslator.FormatGemini.String(), "gemini-cli":
		return collectGeminiUserTurns(gjson.GetBytes(payload, "contents"))
	default:
		var turns []auditTurn
		turns = append(turns, collectRoleMessageTurns(gjson.GetBytes(payload, "messages"), "user")...)
		turns = append(turns, collectResponsesUserTurns(gjson.GetBytes(payload, "input"))...)
		turns = append(turns, collectGeminiUserTurns(gjson.GetBytes(payload, "contents"))...)
		return turns
	}
}

func collectRoleMessageTurns(messages gjson.Result, role string) []auditTurn {
	if !messages.IsArray() {
		return nil
	}
	turns := make([]auditTurn, 0, 4)
	messages.ForEach(func(_, item gjson.Result) bool {
		if strings.ToLower(strings.TrimSpace(item.Get("role").String())) != role {
			return true
		}
		var parts []string
		var images []string
		collectContentValue(item.Get("content"), &parts, &images, 0)
		if len(parts) == 0 && len(images) == 0 {
			return true
		}
		turns = append(turns, auditTurn{
			Text:   strings.Join(parts, "\n"),
			Images: images,
		})
		return true
	})
	return turns
}

func collectOpenAIChatUsers(messages gjson.Result, parts *[]string, images *[]string, maxImages int) int {
	return collectRoleMessages(messages, "user", parts, images, maxImages)
}

func collectRoleMessages(messages gjson.Result, role string, parts *[]string, images *[]string, maxImages int) int {
	if !messages.IsArray() {
		return 0
	}
	count := 0
	messages.ForEach(func(_, item gjson.Result) bool {
		if strings.ToLower(strings.TrimSpace(item.Get("role").String())) != role {
			return true
		}
		beforeParts := len(*parts)
		beforeImages := len(*images)
		collectContentValue(item.Get("content"), parts, images, maxImages)
		if len(*parts) > beforeParts || len(*images) > beforeImages {
			count++
		}
		return true
	})
	return count
}

func collectResponsesUserTurns(input gjson.Result) []auditTurn {
	if !input.Exists() {
		return nil
	}
	switch {
	case input.Type == gjson.String:
		return []auditTurn{{Text: input.String()}}
	case input.IsArray():
		turns := make([]auditTurn, 0, 4)
		input.ForEach(func(_, item gjson.Result) bool {
			if turn, ok := collectResponsesUserTurn(item); ok {
				turns = append(turns, turn)
			}
			return true
		})
		return turns
	case input.IsObject():
		if turn, ok := collectResponsesUserTurn(input); ok {
			return []auditTurn{turn}
		}
	}
	return nil
}

func collectResponsesUsers(input gjson.Result, parts *[]string, images *[]string, maxImages int) int {
	if !input.Exists() {
		return 0
	}
	switch {
	case input.Type == gjson.String:
		addAuditText(parts, input.String())
		return 1
	case input.IsArray():
		count := 0
		input.ForEach(func(_, item gjson.Result) bool {
			if collectResponsesUserItem(item, parts, images, maxImages) {
				count++
			}
			return true
		})
		return count
	case input.IsObject():
		if collectResponsesUserItem(input, parts, images, maxImages) {
			return 1
		}
	}
	return 0
}

func collectResponsesUserTurn(item gjson.Result) (auditTurn, bool) {
	if item.Type == gjson.String {
		if strings.TrimSpace(item.String()) == "" {
			return auditTurn{}, false
		}
		return auditTurn{Text: item.String()}, true
	}
	if !item.IsObject() {
		return auditTurn{}, false
	}
	role := strings.ToLower(strings.TrimSpace(item.Get("role").String()))
	itemType := strings.ToLower(strings.TrimSpace(item.Get("type").String()))
	if role != "" && role != "user" {
		return auditTurn{}, false
	}
	if role == "" && itemType != "input_text" && itemType != "text" {
		return auditTurn{}, false
	}
	var parts []string
	var images []string
	if item.Get("content").Exists() {
		collectContentValue(item.Get("content"), &parts, &images, 0)
	}
	if itemType == "input_text" || itemType == "text" || item.Get("text").Exists() {
		collectContentValue(item, &parts, &images, 0)
	}
	if len(parts) == 0 && len(images) == 0 {
		return auditTurn{}, false
	}
	return auditTurn{
		Text:   strings.Join(parts, "\n"),
		Images: images,
	}, true
}

func collectResponsesUserItem(item gjson.Result, parts *[]string, images *[]string, maxImages int) bool {
	if item.Type == gjson.String {
		addAuditText(parts, item.String())
		return strings.TrimSpace(item.String()) != ""
	}
	if !item.IsObject() {
		return false
	}
	role := strings.ToLower(strings.TrimSpace(item.Get("role").String()))
	itemType := strings.ToLower(strings.TrimSpace(item.Get("type").String()))
	if role != "" && role != "user" {
		return false
	}
	if role == "" && itemType != "input_text" && itemType != "text" {
		return false
	}
	beforeParts := len(*parts)
	beforeImages := len(*images)
	if item.Get("content").Exists() {
		collectContentValue(item.Get("content"), parts, images, maxImages)
	}
	if itemType == "input_text" || itemType == "text" || item.Get("text").Exists() {
		collectContentValue(item, parts, images, maxImages)
	}
	return len(*parts) > beforeParts || len(*images) > beforeImages
}

func collectGeminiUserTurns(contents gjson.Result) []auditTurn {
	if !contents.IsArray() {
		return nil
	}
	turns := make([]auditTurn, 0, 4)
	contents.ForEach(func(_, item gjson.Result) bool {
		role := strings.ToLower(strings.TrimSpace(item.Get("role").String()))
		if role != "" && role != "user" {
			return true
		}
		var parts []string
		var images []string
		if arr := item.Get("parts"); arr.IsArray() {
			arr.ForEach(func(_, part gjson.Result) bool {
				collectGeminiPart(part, &parts, &images, 0)
				return true
			})
		}
		if len(parts) == 0 && len(images) == 0 {
			return true
		}
		turns = append(turns, auditTurn{
			Text:   strings.Join(parts, "\n"),
			Images: images,
		})
		return true
	})
	return turns
}

func collectGeminiUsers(contents gjson.Result, parts *[]string, images *[]string, maxImages int) int {
	if !contents.IsArray() {
		return 0
	}
	count := 0
	contents.ForEach(func(_, item gjson.Result) bool {
		role := strings.ToLower(strings.TrimSpace(item.Get("role").String()))
		if role != "" && role != "user" {
			return true
		}
		beforeParts := len(*parts)
		beforeImages := len(*images)
		if arr := item.Get("parts"); arr.IsArray() {
			arr.ForEach(func(_, part gjson.Result) bool {
				collectGeminiPart(part, parts, images, maxImages)
				return true
			})
		}
		if len(*parts) > beforeParts || len(*images) > beforeImages {
			count++
		}
		return true
	})
	return count
}

func collectGeminiPart(part gjson.Result, parts *[]string, images *[]string, maxImages int) {
	addAuditText(parts, part.Get("text").String())
	addImageResult(images, part.Get("inline_data.data"), part.Get("inline_data.mime_type").String(), maxImages)
	addImageResult(images, part.Get("inlineData.data"), part.Get("inlineData.mimeType").String(), maxImages)
	addImageURL(images, part.Get("file_data.file_uri").String(), maxImages)
	addImageURL(images, part.Get("fileData.fileUri").String(), maxImages)
}

func collectContentValue(value gjson.Result, parts *[]string, images *[]string, maxImages int) {
	switch {
	case !value.Exists():
		return
	case value.Type == gjson.String:
		addAuditText(parts, value.String())
	case value.IsArray():
		value.ForEach(func(_, item gjson.Result) bool {
			collectContentValue(item, parts, images, maxImages)
			return true
		})
	case value.IsObject():
		itemType := strings.ToLower(strings.TrimSpace(value.Get("type").String()))
		switch itemType {
		case "tool_result", "function_call_output", "computer_call_output":
			return
		case "image_url", "input_image", "image":
			addImageURL(images, value.Get("image_url.url").String(), maxImages)
			addImageURLResult(images, value.Get("image_url"), maxImages)
			addImageURL(images, value.Get("url").String(), maxImages)
			addImageResult(images, value.Get("source.data"), value.Get("source.media_type").String(), maxImages)
			addImageResult(images, value.Get("source.data"), value.Get("source.mediaType").String(), maxImages)
		case "text", "input_text", "output_text":
			addAuditText(parts, value.Get("text").String())
		}
		if value.Get("text").Exists() && itemType == "" {
			addAuditText(parts, value.Get("text").String())
		}
		if value.Get("content").Exists() && itemType != "tool_result" {
			collectContentValue(value.Get("content"), parts, images, maxImages)
		}
	}
}

func addImageURLResult(images *[]string, value gjson.Result, maxImages int) {
	if value.Type != gjson.String {
		return
	}
	addImageURL(images, value.String(), maxImages)
}

func addAuditText(parts *[]string, text string) {
	text = strings.TrimSpace(text)
	if text == "" {
		return
	}
	*parts = append(*parts, text)
}

func sanitizeAuditTurns(turns []auditTurn) []auditTurn {
	out := make([]auditTurn, 0, len(turns))
	for _, turn := range turns {
		turn.Text = normalizeAuditText(stripHostScaffolding(turn.Text))
		if strings.TrimSpace(turn.Text) == "" && len(turn.Images) == 0 {
			continue
		}
		out = append(out, turn)
	}
	return out
}

func selectEffectiveAuditTurns(turns []auditTurn, maxBackfill int) []auditTurn {
	if len(turns) == 0 {
		return nil
	}
	latestIdx := -1
	for i := len(turns) - 1; i >= 0; i-- {
		if strings.TrimSpace(turns[i].Text) != "" || len(turns[i].Images) > 0 {
			latestIdx = i
			break
		}
	}
	if latestIdx < 0 {
		return nil
	}
	selected := []auditTurn{turns[latestIdx]}
	if !shouldBackfillReferencedContext(turns[latestIdx].Text) || maxBackfill <= 0 {
		return selected
	}
	for i, used := latestIdx-1, 0; i >= 0 && used < maxBackfill; i-- {
		if strings.TrimSpace(turns[i].Text) == "" && len(turns[i].Images) == 0 {
			continue
		}
		selected = append([]auditTurn{turns[i]}, selected...)
		used++
	}
	return selected
}

func shouldBackfillReferencedContext(text string) bool {
	trimmed := strings.TrimSpace(strings.ToLower(text))
	if trimmed == "" {
		return false
	}
	if len([]rune(trimmed)) > 160 {
		return false
	}
	for _, marker := range []string{
		"continue",
		"go on",
		"keep going",
		"same as above",
		"based on above",
		"as above",
		"continue with",
		"finish it",
		"complete it",
		"turn that into",
		"convert that to",
		"继续",
		"接着",
		"按上面",
		"照上面",
		"基于上面",
		"按前面",
		"接上",
		"补全",
		"细化",
		"展开",
		"继续写",
		"改成脚本",
		"改成 bash",
		"改成 python",
	} {
		if strings.Contains(trimmed, marker) {
			return true
		}
	}
	return false
}

func stripHostScaffolding(text string) string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}

	if extracted := extractLastTaggedContent(text, "user_query"); extracted != "" {
		return normalizeAuditText(extracted)
	}

	if extracted := extractAfterLastMarker(text, []string{
		"User prompt:\n",
		"User prompt:",
		"## My request for Codex:\n",
		"My request for Codex:\n",
		"[新消息]\n",
	}); extracted != "" && extracted != text {
		text = extracted
	}

	for _, tag := range [][2]string{
		{"<INSTRUCTIONS>", "</INSTRUCTIONS>"},
		{"<environment_context>", "</environment_context>"},
		{"<permissions instructions>", "</permissions instructions>"},
		{"<app-context>", "</app-context>"},
		{"<collaboration_mode>", "</collaboration_mode>"},
		{"<skills_instructions>", "</skills_instructions>"},
		{"<plugins_instructions>", "</plugins_instructions>"},
		{"<system-reminder>", "</system-reminder>"},
		{"<transcript>", "</transcript>"},
		{"<codex_internal_context>", "</codex_internal_context>"},
		{"<open_and_recently_viewed_files>", "</open_and_recently_viewed_files>"},
		{"<timestamp>", "</timestamp>"},
		{"<skill>", "</skill>"},
	} {
		text = removeTaggedBlock(text, tag[0], tag[1])
	}

	lines := strings.Split(text, "\n")
	filtered := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "# AGENTS.md instructions for ") {
			continue
		}
		filtered = append(filtered, line)
	}
	return strings.TrimSpace(strings.Join(filtered, "\n"))
}

func deriveAuditFocusFromTurns(turns []auditTurn) (string, string, string) {
	if len(turns) == 0 {
		return "", auditFocusAmbiguous, "no_user_turn"
	}
	sanitized := sanitizeAuditTurns(turns)
	selected := selectEffectiveAuditTurns(sanitized, defaultAuditContextBackfillTurns)
	if len(selected) == 0 {
		return "", auditFocusAmbiguous, "no_effective_turn"
	}
	parts := make([]string, 0, len(selected))
	for _, turn := range selected {
		addAuditText(&parts, turn.Text)
	}
	return deriveAuditFocusFromText(strings.Join(parts, "\n\n"))
}

func deriveAuditFocusFromText(text string) (string, string, string) {
	text = normalizeAuditText(strings.TrimSpace(text))
	if text == "" {
		return "", auditFocusAmbiguous, "empty"
	}
	candidate := normalizeAuditText(stripHostScaffolding(text))
	if candidate == "" {
		return "", auditFocusAmbiguous, "empty_after_scaffold"
	}
	if looksLikePolicyOrAgentScaffold(candidate) {
		return "", auditFocusAmbiguous, "policy_or_agent_scaffold"
	}
	if len([]rune(candidate)) > 6000 {
		if startsLikeContinuationTask(candidate) {
			head := leadingAuditWindow(candidate, 1400)
			if head != "" && !looksLikePolicyOrAgentScaffold(head) {
				return head, auditFocusExtracted, "long_context_head"
			}
		}
		tail := trailingAuditWindow(candidate, 1400)
		if tail == "" || looksLikePolicyOrAgentScaffold(tail) || looksLikeHandoffSummary(tail) {
			return "", auditFocusAmbiguous, "long_context_scaffold"
		}
		return tail, auditFocusExtracted, "long_context_tail"
	}
	return candidate, auditFocusExtracted, "current_turn"
}

func leadingAuditWindow(text string, maxRunes int) string {
	text = normalizeAuditText(text)
	if maxRunes <= 0 {
		return text
	}
	runes := []rune(text)
	if len(runes) <= maxRunes {
		return text
	}
	head := string(runes[:maxRunes])
	if idx := strings.LastIndex(head, "\n\n"); idx > 0 {
		head = head[:idx]
	}
	return normalizeAuditText(head)
}

func trailingAuditWindow(text string, maxRunes int) string {
	text = normalizeAuditText(text)
	if maxRunes <= 0 {
		return text
	}
	runes := []rune(text)
	if len(runes) <= maxRunes {
		return text
	}
	tail := string(runes[len(runes)-maxRunes:])
	for _, sep := range []string{"\n\n", "\n", "。", "！", "？"} {
		if idx := strings.Index(tail, sep); idx >= 0 && idx+len(sep) < len(tail) {
			return normalizeAuditText(tail[idx+len(sep):])
		}
	}
	return normalizeAuditText(tail)
}

func looksLikePolicyOrAgentScaffold(text string) bool {
	lower := strings.ToLower(strings.TrimSpace(text))
	if lower == "" {
		return false
	}
	markers := []string{
		"system - immutable",
		"system — immutable",
		"non_negotiable_rules",
		"decision_algorithm",
		"final_output_invariants",
		"output_schema",
		"block if any rule could apply",
		"err on the side of blocking",
		"<block> immediately",
		"stage 1 does not apply user intent",
		"allow exceptions",
		"judge the action by its full effect",
		"must not output any other text",
		"only output the json object",
		"execution-mode hard rule",
		"tool calls",
		"you are an ai gateway",
		"你是 ai 网关",
		"只输出 json",
		"违规类型",
		"判定原则",
	}
	hits := 0
	for _, marker := range markers {
		if strings.Contains(lower, marker) {
			hits++
		}
	}
	if hits >= 2 {
		return true
	}
	if len([]rune(lower)) > 3000 && hits >= 1 {
		return true
	}
	return false
}

func startsLikeContinuationTask(text string) bool {
	lower := strings.ToLower(strings.TrimSpace(text))
	if lower == "" {
		return false
	}
	if strings.HasPrefix(lower, "请继续 ") || strings.HasPrefix(lower, "继续 ") || strings.HasPrefix(lower, "continue from where you left off") {
		return true
	}
	head := leadingAuditWindow(lower, 1200)
	return strings.Contains(head, "当前任务") || strings.Contains(head, "current task") || strings.Contains(head, "任务性质")
}

func looksLikeHandoffSummary(text string) bool {
	lower := strings.ToLower(strings.TrimSpace(text))
	if lower == "" {
		return false
	}
	markers := []string{
		"another language model started",
		"handoff",
		"交接摘要",
		"earlier also passed",
		"important caveats",
		"pending tasks",
		"optional next step",
		"most recent user message",
		"pytest",
		"tests/",
		"当前任务",
	}
	hits := 0
	for _, marker := range markers {
		if strings.Contains(lower, marker) {
			hits++
		}
	}
	return hits >= 2
}

func extractLastTaggedContent(text string, tagName string) string {
	openTag := "<" + tagName + ">"
	closeTag := "</" + tagName + ">"
	start := strings.LastIndex(text, openTag)
	if start < 0 {
		return ""
	}
	start += len(openTag)
	endRel := strings.Index(text[start:], closeTag)
	if endRel < 0 {
		return ""
	}
	return strings.TrimSpace(text[start : start+endRel])
}

func extractAfterLastMarker(text string, markers []string) string {
	best := -1
	bestMarkerLen := 0
	for _, marker := range markers {
		if idx := strings.LastIndex(text, marker); idx >= 0 && idx >= best {
			best = idx
			bestMarkerLen = len(marker)
		}
	}
	if best < 0 {
		return text
	}
	return strings.TrimSpace(text[best+bestMarkerLen:])
}

func removeTaggedBlock(text string, startTag string, endTag string) string {
	for {
		start := strings.Index(text, startTag)
		if start < 0 {
			return text
		}
		end := strings.Index(text[start+len(startTag):], endTag)
		if end < 0 {
			return text
		}
		end += start + len(startTag) + len(endTag)
		text = text[:start] + text[end:]
	}
}

func addImageResult(images *[]string, data gjson.Result, mediaType string, maxImages int) {
	if data.Type != gjson.String {
		return
	}
	value := strings.TrimSpace(data.String())
	if value == "" {
		return
	}
	mediaType = strings.TrimSpace(mediaType)
	if mediaType == "" {
		mediaType = "image"
	}
	sum := sha256.Sum256([]byte(value))
	addImageURL(images, fmt.Sprintf("data:%s;sha256=%s;bytes=%d", mediaType, hex.EncodeToString(sum[:8]), len(value)), maxImages)
}

func addImageURL(images *[]string, raw string, maxImages int) {
	raw = strings.TrimSpace(raw)
	if raw == "" || (maxImages > 0 && len(*images) >= maxImages) {
		return
	}
	if strings.HasPrefix(raw, "data:") {
		sum := sha256.Sum256([]byte(raw))
		media := "image"
		if idx := strings.Index(raw, ";"); idx > len("data:") {
			media = raw[len("data:"):idx]
		}
		raw = fmt.Sprintf("data:%s;sha256=%s;bytes=%d", media, hex.EncodeToString(sum[:8]), len(raw))
	}
	if len(raw) > 256 {
		raw = raw[:256] + "..."
	}
	*images = append(*images, raw)
}

func normalizeAuditText(text string) string {
	lines := strings.Split(text, "\n")
	out := make([]string, 0, len(lines))
	previousBlank := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			if previousBlank {
				continue
			}
			previousBlank = true
			out = append(out, "")
			continue
		}
		previousBlank = false
		out = append(out, line)
	}
	return strings.TrimSpace(strings.Join(out, "\n"))
}

func truncateRunes(text string, maxRunes int) string {
	if maxRunes <= 0 {
		return text
	}
	runes := []rune(text)
	if len(runes) <= maxRunes {
		return text
	}
	return string(runes[:maxRunes]) + "\n[truncated]"
}
