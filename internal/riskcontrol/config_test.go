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

	if settings.blockThreshold != 0.97 {
		t.Fatalf("blockThreshold = %v, want 0.97", settings.blockThreshold)
	}
}

func TestNormalizeSettingsClampsLowBlockThresholdToHighPrecision(t *testing.T) {
	t.Parallel()

	settings := normalizeSettings(&config.Config{RiskControl: config.RiskControlConfig{
		Enabled:        true,
		Mode:           ModePreBlock,
		BaseURL:        "http://audit.local/v1",
		Model:          "audit-model",
		BlockThreshold: 0.96,
	}})

	if settings.blockThreshold != 0.97 {
		t.Fatalf("blockThreshold = %v, want 0.97", settings.blockThreshold)
	}
}

func TestNormalizeSettingsKeepsHigherBlockThreshold(t *testing.T) {
	t.Parallel()

	settings := normalizeSettings(&config.Config{RiskControl: config.RiskControlConfig{
		Enabled:        true,
		Mode:           ModePreBlock,
		BaseURL:        "http://audit.local/v1",
		Model:          "audit-model",
		BlockThreshold: 0.99,
	}})

	if settings.blockThreshold != 0.99 {
		t.Fatalf("blockThreshold = %v, want 0.99", settings.blockThreshold)
	}
}

func TestNormalizeSettingsAcceptsDebugMode(t *testing.T) {
	t.Parallel()

	settings := normalizeSettings(&config.Config{RiskControl: config.RiskControlConfig{
		Enabled: true,
		Mode:    "debug",
		BaseURL: "http://audit.local/v1",
		Model:   "audit-model",
	}})

	if settings.mode != ModeDebug {
		t.Fatalf("mode = %q, want %q", settings.mode, ModeDebug)
	}
}
