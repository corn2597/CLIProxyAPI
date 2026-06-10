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
}

func (i AuditInput) Empty() bool {
	return strings.TrimSpace(i.Text) == "" && len(i.Images) == 0
}

// ExtractFullUserInput collects all user-role content from the request payload.
func ExtractFullUserInput(format sdktranslator.Format, payload []byte, maxRunes int, maxImages int) AuditInput {
	if len(payload) == 0 || !gjson.ValidBytes(payload) {
		return AuditInput{}
	}
	var parts []string
	var images []string
	var messages int
	switch strings.ToLower(strings.TrimSpace(format.String())) {
	case sdktranslator.FormatOpenAI.String():
		messages = collectOpenAIChatUsers(gjson.GetBytes(payload, "messages"), &parts, &images, maxImages)
	case sdktranslator.FormatOpenAIResponse.String(), "responses", "openai-responses":
		messages = collectResponsesUsers(gjson.GetBytes(payload, "input"), &parts, &images, maxImages)
	case sdktranslator.FormatClaude.String():
		messages = collectRoleMessages(gjson.GetBytes(payload, "messages"), "user", &parts, &images, maxImages)
	case sdktranslator.FormatGemini.String(), sdktranslator.FormatGeminiCLI.String():
		messages = collectGeminiUsers(gjson.GetBytes(payload, "contents"), &parts, &images, maxImages)
	default:
		messages += collectOpenAIChatUsers(gjson.GetBytes(payload, "messages"), &parts, &images, maxImages)
		messages += collectResponsesUsers(gjson.GetBytes(payload, "input"), &parts, &images, maxImages)
		messages += collectGeminiUsers(gjson.GetBytes(payload, "contents"), &parts, &images, maxImages)
	}
	text := truncateRunes(normalizeAuditText(strings.Join(parts, "\n")), maxRunes)
	hash := sha256.Sum256([]byte(text + "\n" + strings.Join(images, "\n")))
	return AuditInput{
		Text:         text,
		Images:       images,
		MessageCount: messages,
		Hash:         hex.EncodeToString(hash[:]),
	}
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
	if text == "" || strings.HasPrefix(text, "<system-reminder>") {
		return
	}
	*parts = append(*parts, text)
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
