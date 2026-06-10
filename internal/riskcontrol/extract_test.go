package riskcontrol

import (
	"strings"
	"testing"

	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

func TestExtractFullUserInputOpenAIChatCollectsAllUserMessages(t *testing.T) {
	payload := []byte(`{
		"messages": [
			{"role": "system", "content": "system prompt"},
			{"role": "user", "content": "first user"},
			{"role": "assistant", "content": "assistant text"},
			{"role": "user", "content": [
				{"type": "text", "text": "second user"},
				{"type": "tool_result", "content": "tool output"},
				{"type": "image_url", "image_url": {"url": "data:image/png;base64,AAAA"}}
			]}
		]
	}`)

	input := ExtractFullUserInput(sdktranslator.FormatOpenAI, payload, 1000, 2)
	if input.MessageCount != 2 {
		t.Fatalf("MessageCount = %d, want 2; input=%+v", input.MessageCount, input)
	}
	for _, want := range []string{"first user", "second user"} {
		if !strings.Contains(input.Text, want) {
			t.Fatalf("input text missing %q: %q", want, input.Text)
		}
	}
	for _, forbidden := range []string{"system prompt", "assistant text", "tool output"} {
		if strings.Contains(input.Text, forbidden) {
			t.Fatalf("input text contains non-user content %q: %q", forbidden, input.Text)
		}
	}
	if len(input.Images) != 1 || !strings.Contains(input.Images[0], "sha256=") {
		t.Fatalf("Images = %#v, want one summarized data image", input.Images)
	}
	if len(input.Hash) != 64 {
		t.Fatalf("Hash length = %d, want sha256 hex", len(input.Hash))
	}
}

func TestExtractFullUserInputResponsesCollectsUserInputOnly(t *testing.T) {
	payload := []byte(`{
		"input": [
			{"role": "user", "content": [{"type": "input_text", "text": "first response user"}]},
			{"role": "assistant", "content": [{"type": "output_text", "text": "assistant output"}]},
			{"type": "input_text", "text": "loose user text"},
			{"type": "function_call_output", "output": "tool output"},
			{"role": "user", "content": [{"type": "input_image", "image_url": "https://example.test/image.png"}]}
		]
	}`)

	input := ExtractFullUserInput(sdktranslator.FormatOpenAIResponse, payload, 1000, 2)
	if input.MessageCount != 3 {
		t.Fatalf("MessageCount = %d, want 3; input=%+v", input.MessageCount, input)
	}
	for _, want := range []string{"first response user", "loose user text"} {
		if !strings.Contains(input.Text, want) {
			t.Fatalf("input text missing %q: %q", want, input.Text)
		}
	}
	for _, forbidden := range []string{"assistant output", "tool output"} {
		if strings.Contains(input.Text, forbidden) {
			t.Fatalf("input text contains non-user content %q: %q", forbidden, input.Text)
		}
	}
	if got := len(input.Images); got != 1 {
		t.Fatalf("len(Images) = %d, want 1; images=%#v", got, input.Images)
	}
}

func TestExtractFullUserInputTruncatesText(t *testing.T) {
	payload := []byte(`{"messages":[{"role":"user","content":"abcdef"}]}`)

	input := ExtractFullUserInput(sdktranslator.FormatOpenAI, payload, 3, 1)
	if input.Text != "abc\n[truncated]" {
		t.Fatalf("Text = %q, want truncated marker", input.Text)
	}
}
