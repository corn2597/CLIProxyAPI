package management

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/riskcontrol"
)

func TestGetRiskControlBlocksReturnsPaginatedEvents(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	store := riskcontrol.NewBlockEventStore(8)
	store.RecordBlockedEvent(riskcontrol.BlockEvent{
		BlockedAt:      time.Date(2026, 6, 10, 10, 0, 0, 0, time.UTC),
		SessionID:      "execution:session-one",
		Reason:         "reason-one",
		DecisionSource: riskcontrol.DecisionSourceFreshAudit,
	})
	store.RecordBlockedEvent(riskcontrol.BlockEvent{
		BlockedAt:      time.Date(2026, 6, 10, 10, 1, 0, 0, time.UTC),
		SessionID:      "execution:session-two",
		Reason:         "reason-two",
		DecisionSource: riskcontrol.DecisionSourceCache,
	})

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/v0/management/risk-control/blocks?session_id=session-two&limit=1", nil)

	h := &Handler{riskBlockReader: store}
	h.GetRiskControlBlocks(c)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var payload struct {
		Items    []riskcontrol.BlockEvent `json:"items"`
		Returned int                      `json:"returned"`
		Total    int                      `json:"total"`
		HasMore  bool                     `json:"has_more"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rec.Body.String())
	}
	if payload.Returned != 1 || payload.Total != 1 {
		t.Fatalf("Returned/Total = %d/%d, want 1/1", payload.Returned, payload.Total)
	}
	if payload.HasMore {
		t.Fatal("HasMore = true, want false")
	}
	if len(payload.Items) != 1 || payload.Items[0].SessionID != "execution:session-two" {
		t.Fatalf("items = %#v, want filtered latest session-two event", payload.Items)
	}
}

func TestGetRiskControlPageServesStandaloneHTML(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/v0/management/risk-control/page", nil)

	h := &Handler{}
	h.GetRiskControlPage(c)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if contentType := rec.Header().Get("Content-Type"); !strings.Contains(contentType, "text/html") {
		t.Fatalf("Content-Type = %q, want text/html", contentType)
	}
	body := rec.Body.String()
	for _, want := range []string{"Risk Control Blocks", "/v0/management/risk-control/blocks", "Load older"} {
		if !strings.Contains(body, want) {
			t.Fatalf("page body missing %q", want)
		}
	}
}
