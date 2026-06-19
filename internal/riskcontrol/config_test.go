package riskcontrol

import (
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

func TestNormalizeSettingsDefaultsToModerationsEndpoint(t *testing.T) {
	t.Parallel()

	settings := normalizeSettings(&config.Config{RiskControl: config.RiskControlConfig{
		Enabled: true,
		Mode:    ModePreBlock,
		BaseURL: "http://audit.local/v1",
		Model:   "omni-moderation-latest",
	}})

	if settings.endpoint != EndpointModerations {
		t.Fatalf("endpoint = %q, want %q", settings.endpoint, EndpointModerations)
	}
}

func TestNormalizeSettingsMapsLegacyEndpointsToModerations(t *testing.T) {
	t.Parallel()

	for _, endpoint := range []string{"responses", "chat-completions", "/responses", "/chat/completions"} {
		settings := normalizeSettings(&config.Config{RiskControl: config.RiskControlConfig{
			Enabled:  true,
			Mode:     ModePreBlock,
			BaseURL:  "http://audit.local/v1",
			Model:    "omni-moderation-latest",
			Endpoint: endpoint,
		}})

		if settings.endpoint != EndpointModerations {
			t.Fatalf("endpoint %q normalized to %q, want %q", endpoint, settings.endpoint, EndpointModerations)
		}
	}
}

func TestNormalizeSettingsMapsLegacyDebugModeToShadowPreBlock(t *testing.T) {
	t.Parallel()

	settings := normalizeSettings(&config.Config{RiskControl: config.RiskControlConfig{
		Enabled: true,
		Mode:    "debug",
		BaseURL: "http://audit.local/v1",
		Model:   "omni-moderation-latest",
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
		Model:           "omni-moderation-latest",
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
