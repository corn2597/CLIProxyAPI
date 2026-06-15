package riskcontrol

import (
	"net/http"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

const (
	ModeOff      = "off"
	ModeObserve  = "observe"
	ModePreBlock = "pre_block"

	FailOpen   = "open"
	FailClosed = "closed"

	EndpointResponses       = "responses"
	EndpointChatCompletions = "chat-completions"
	EndpointModerations     = "moderations"

	defaultTimeoutMS            = 3000
	maxTimeoutMS                = 30000
	defaultSessionAuditInterval = 5 * time.Minute
	defaultSessionTTL           = 24 * time.Hour
	defaultBlockedSessionTTL    = 7 * 24 * time.Hour
	defaultBlockThreshold       = 0.99
	defaultMaxInputRunes        = 0
	defaultMaxInputImages       = 0
	defaultBlockStatus          = http.StatusForbidden
	defaultBlockMessage         = "risk control audit blocked this request"
)

type settings struct {
	enabled              bool
	mode                 string
	baseURL              string
	endpoint             string
	model                string
	apiKeys              []string
	timeout              time.Duration
	failPolicy           string
	sessionAuditInterval time.Duration
	sessionTTL           time.Duration
	blockedSessionTTL    time.Duration
	blockThreshold       float64
	maxInputRunes        int
	maxInputImages       int
	blockStatus          int
	blockMessage         string
}

func normalizeSettings(cfg *config.Config) settings {
	if cfg == nil || !cfg.RiskControl.Enabled {
		return settings{mode: ModeOff}
	}
	raw := cfg.RiskControl
	mode := strings.ToLower(strings.TrimSpace(raw.Mode))
	switch mode {
	case "", ModeObserve:
		mode = ModeObserve
	case "pre-block", "preblock", ModePreBlock:
		mode = ModePreBlock
	case ModeOff:
		mode = ModeOff
	default:
		mode = ModeObserve
	}
	if mode == ModeOff {
		return settings{mode: ModeOff}
	}

	endpoint := normalizeEndpoint(raw.Endpoint)
	keys := make([]string, 0, 1+len(raw.APIKeys))
	if key := strings.TrimSpace(raw.APIKey); key != "" {
		keys = append(keys, key)
	}
	for _, key := range raw.APIKeys {
		if key = strings.TrimSpace(key); key != "" {
			keys = append(keys, key)
		}
	}

	timeoutMS := raw.TimeoutMS
	if timeoutMS <= 0 {
		timeoutMS = defaultTimeoutMS
	}
	if timeoutMS > maxTimeoutMS {
		timeoutMS = maxTimeoutMS
	}

	failPolicy := strings.ToLower(strings.TrimSpace(raw.FailPolicy))
	if failPolicy != FailClosed {
		failPolicy = FailOpen
	}

	blockStatus := raw.BlockStatus
	if blockStatus <= 0 {
		blockStatus = defaultBlockStatus
	}
	blockMessage := strings.TrimSpace(raw.BlockMessage)
	if blockMessage == "" {
		blockMessage = defaultBlockMessage
	}

	blockThreshold := raw.BlockThreshold
	if blockThreshold <= 0 || blockThreshold > 1 {
		blockThreshold = defaultBlockThreshold
	}
	if blockThreshold < defaultBlockThreshold {
		blockThreshold = defaultBlockThreshold
	}

	maxRunes := raw.MaxInputRunes
	if maxRunes <= 0 {
		maxRunes = defaultMaxInputRunes
	}
	maxImages := raw.MaxInputImages
	if maxImages <= 0 {
		maxImages = defaultMaxInputImages
	}

	return settings{
		enabled:              true,
		mode:                 mode,
		baseURL:              strings.TrimSpace(raw.BaseURL),
		endpoint:             endpoint,
		model:                strings.TrimSpace(raw.Model),
		apiKeys:              keys,
		timeout:              time.Duration(timeoutMS) * time.Millisecond,
		failPolicy:           failPolicy,
		sessionAuditInterval: parsePositiveDuration(raw.SessionAuditInterval, defaultSessionAuditInterval),
		sessionTTL:           parsePositiveDuration(raw.SessionTTL, defaultSessionTTL),
		blockedSessionTTL:    parsePositiveDuration(raw.BlockedSessionTTL, defaultBlockedSessionTTL),
		blockThreshold:       blockThreshold,
		maxInputRunes:        maxRunes,
		maxInputImages:       maxImages,
		blockStatus:          blockStatus,
		blockMessage:         blockMessage,
	}
}

func normalizeEndpoint(raw string) string {
	value := strings.ToLower(strings.TrimSpace(raw))
	switch value {
	case "", "responses", "response", "openai-responses", "/responses":
		return EndpointResponses
	case "chat", "chat_completion", "chat-completions", "chat/completions", "/chat/completions":
		return EndpointChatCompletions
	case "moderation", "moderations", "/moderations":
		return EndpointModerations
	default:
		if strings.HasPrefix(strings.TrimSpace(raw), "/") {
			return strings.TrimSpace(raw)
		}
		return EndpointResponses
	}
}

func parsePositiveDuration(raw string, fallback time.Duration) time.Duration {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	value, errParse := time.ParseDuration(raw)
	if errParse != nil || value <= 0 {
		return fallback
	}
	return value
}
