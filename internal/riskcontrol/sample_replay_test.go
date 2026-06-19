package riskcontrol

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

func TestRiskControlLabeledSampleReplay(t *testing.T) {
	sampleFile := strings.TrimSpace(os.Getenv("RISK_CONTROL_SAMPLE_REPLAY_FILE"))
	baseURL := strings.TrimSpace(os.Getenv("RISK_CONTROL_AUDIT_BASE_URL"))
	apiKey := strings.TrimSpace(os.Getenv("RISK_CONTROL_AUDIT_API_KEY"))
	model := strings.TrimSpace(os.Getenv("RISK_CONTROL_AUDIT_MODEL"))
	if sampleFile == "" || baseURL == "" || apiKey == "" || model == "" {
		t.Skip("set RISK_CONTROL_SAMPLE_REPLAY_FILE, RISK_CONTROL_AUDIT_BASE_URL, RISK_CONTROL_AUDIT_API_KEY, and RISK_CONTROL_AUDIT_MODEL to replay labeled samples")
	}

	file, err := os.Open(sampleFile)
	if err != nil {
		t.Fatalf("open sample replay file: %v", err)
	}
	defer file.Close()

	cfg := &config.Config{RiskControl: config.RiskControlConfig{
		Enabled:        true,
		Mode:           ModePreBlock,
		BaseURL:        baseURL,
		Endpoint:       EndpointModerations,
		Model:          model,
		APIKey:         apiKey,
		TimeoutMS:      90000,
		BlockThreshold: 0.97,
		FailPolicy:     FailOpen,
	}}
	settings := normalizeSettings(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	var total, allowOK, blockOK, failures int
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var sample SampleRecord
		if err := json.Unmarshal([]byte(line), &sample); err != nil {
			t.Fatalf("decode sample line %d: %v", total+1, err)
		}
		if strings.TrimSpace(sample.UserText) == "" {
			continue
		}
		input := auditInputFromSample(sample)
		decision := performAudit(ctx, cfg, settings, sample.SessionID, "sample-replay", input)
		total++
		if decision.Error != "" || decision.FailureClass != "" {
			t.Errorf("sample %d audit failed: error=%q failure_class=%q focus_status=%s focus=%q",
				sample.ID, decision.Error, decision.FailureClass, input.FocusStatus, previewForTest(input.FocusText))
			failures++
			continue
		}
		switch sample.Label {
		case SampleShouldBlock:
			if !decision.Blocked {
				t.Errorf("sample %d should block, got allow/observe: policy=%s/%s confidence=%.3f reason=%q focus_status=%s focus=%q raw=%s",
					sample.ID, decision.PolicyCode, decision.SubcategoryCode, decision.Confidence, decision.Reason, input.FocusStatus, previewForTest(input.FocusText), previewForTest(decision.RawResponse))
				failures++
				continue
			}
			blockOK++
		case SampleShouldAllow:
			if decision.Blocked || decision.ObserveOnly {
				t.Errorf("sample %d should allow, got blocked=%v observe=%v policy=%s/%s confidence=%.3f reason=%q focus_status=%s focus=%q raw=%s",
					sample.ID, decision.Blocked, decision.ObserveOnly, decision.PolicyCode, decision.SubcategoryCode, decision.Confidence, decision.Reason, input.FocusStatus, previewForTest(input.FocusText), previewForTest(decision.RawResponse))
				failures++
				continue
			}
			allowOK++
		default:
			t.Fatalf("sample %d has unsupported label %q", sample.ID, sample.Label)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan sample replay file: %v", err)
	}
	if total == 0 {
		t.Fatalf("no replayable samples found in %s", sampleFile)
	}
	if failures > 0 {
		t.Fatalf("sample replay failed: total=%d failures=%d should_allow_ok=%d should_block_ok=%d", total, failures, allowOK, blockOK)
	}
	t.Logf("sample replay passed: total=%d should_allow=%d should_block=%d", total, allowOK, blockOK)
}

func auditInputFromSample(sample SampleRecord) AuditInput {
	text := normalizeAuditText(sample.UserText)
	images := cloneStrings(sample.ImageReferences)
	hash := strings.TrimSpace(sample.InputHash)
	if hash == "" {
		sum := sha256.Sum256([]byte(text + "\n" + strings.Join(images, "\n")))
		hash = hex.EncodeToString(sum[:])
	}
	focusText, focusStatus, focusReason := deriveAuditFocusFromText(text)
	return AuditInput{
		Text:         text,
		Images:       images,
		MessageCount: 1,
		Hash:         hash,
		FocusText:    focusText,
		FocusStatus:  focusStatus,
		FocusReason:  focusReason,
	}
}

func previewForTest(text string) string {
	text = strings.Join(strings.Fields(text), " ")
	runes := []rune(text)
	if len(runes) <= 180 {
		return text
	}
	return string(runes[:180]) + "..."
}
