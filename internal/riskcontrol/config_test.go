package riskcontrol

import (
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

func TestNormalizeSettingsDefaultsBlockThresholdToHighPrecision(t *testing.T) {
	t.Parallel()

	settings := normalizeSettings(&config.Config{RiskControl: config.RiskControlConfig{
		Enabled: true,
		Mode:    ModePreBlock,
		BaseURL: "http://audit.local/v1",
		Model:   "audit-model",
	}})

	if settings.blockThreshold != 0.99 {
		t.Fatalf("blockThreshold = %v, want 0.99", settings.blockThreshold)
	}
}

func TestNormalizeSettingsClampsLowBlockThresholdToHighPrecision(t *testing.T) {
	t.Parallel()

	settings := normalizeSettings(&config.Config{RiskControl: config.RiskControlConfig{
		Enabled:        true,
		Mode:           ModePreBlock,
		BaseURL:        "http://audit.local/v1",
		Model:          "audit-model",
		BlockThreshold: 0.97,
	}})

	if settings.blockThreshold != 0.99 {
		t.Fatalf("blockThreshold = %v, want 0.99", settings.blockThreshold)
	}
}
