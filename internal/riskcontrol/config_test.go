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

func TestNormalizeSettingsMapsLegacyDebugModeToShadowPreBlock(t *testing.T) {
	t.Parallel()

	settings := normalizeSettings(&config.Config{RiskControl: config.RiskControlConfig{
		Enabled: true,
		Mode:    "debug",
		BaseURL: "http://audit.local/v1",
		Model:   "audit-model",
	}})

	if settings.mode != ModePreBlock {
		t.Fatalf("mode = %q, want %q", settings.mode, ModePreBlock)
	}
	if !settings.debug {
		t.Fatal("debug = false, want true")
	}
}

func TestNormalizeSettingsAcceptsAsyncBlockModeAndDebugFlag(t *testing.T) {
	t.Parallel()

	settings := normalizeSettings(&config.Config{RiskControl: config.RiskControlConfig{
		Enabled:         true,
		Mode:            ModeAsyncBlock,
		Debug:           true,
		BaseURL:         "http://audit.local/v1",
		Model:           "audit-model",
		AsyncWorkers:    2,
		AsyncQueueSize:  8,
		AsyncRetryDelay: "45s",
	}})

	if settings.mode != ModeAsyncBlock {
		t.Fatalf("mode = %q, want %q", settings.mode, ModeAsyncBlock)
	}
	if !settings.debug {
		t.Fatal("debug = false, want true")
	}
	if settings.asyncWorkers != 2 {
		t.Fatalf("asyncWorkers = %d, want 2", settings.asyncWorkers)
	}
	if settings.asyncQueueSize != 8 {
		t.Fatalf("asyncQueueSize = %d, want 8", settings.asyncQueueSize)
	}
	if settings.asyncRetryDelay.Seconds() != 45 {
		t.Fatalf("asyncRetryDelay = %v, want 45s", settings.asyncRetryDelay)
	}
}
