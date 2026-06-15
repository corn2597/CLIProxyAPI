package management

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/riskcontrol"
)

// GetRiskControlBlocks lists persisted risk-control block events.
func (h *Handler) GetRiskControlBlocks(c *gin.Context) {
	h.listRiskControlEvents(c, h.riskBlockEvents(), "risk control block log unavailable")
}

// GetRiskControlObservations lists persisted observe-only audit events.
func (h *Handler) GetRiskControlObservations(c *gin.Context) {
	h.listRiskControlEvents(c, h.riskObserveEvents(), "risk control observe log unavailable")
}

// PostRiskControlAllowOnce creates an input-hash-based allow-once override and labels a should_allow sample.
func (h *Handler) PostRiskControlAllowOnce(c *gin.Context) {
	event, ok := h.lookupRiskControlEvent(c)
	if !ok {
		return
	}
	if strings.TrimSpace(event.InputHash) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "selected block event does not contain input_hash"})
		return
	}
	now := time.Now().UTC()
	override, err := h.riskOverrides().AllowOnce(event.InputHash, event.SessionID, event.ID, now)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	sample, err := h.riskSamples().Append(riskcontrol.NewSampleRecordFromBlockEvent(event, riskcontrol.SampleShouldAllow, riskcontrol.OverrideAllowOnce, now))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"override": override, "sample": sample})
}

// PostRiskControlAllowSession creates a session-scoped allow override and labels a should_allow sample.
func (h *Handler) PostRiskControlAllowSession(c *gin.Context) {
	event, ok := h.lookupRiskControlEvent(c)
	if !ok {
		return
	}
	if strings.TrimSpace(event.SessionID) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "selected block event does not contain session_id"})
		return
	}
	now := time.Now().UTC()
	override, err := h.riskOverrides().AllowSession(event.SessionID, event.InputHash, event.ID, now.Add(h.sessionOverrideTTL()), now)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	sample, err := h.riskSamples().Append(riskcontrol.NewSampleRecordFromBlockEvent(event, riskcontrol.SampleShouldAllow, riskcontrol.OverrideAllowSession, now))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"override": override, "sample": sample})
}

// PostRiskControlConfirmBlock labels a blocked event as a correct should_block sample.
func (h *Handler) PostRiskControlConfirmBlock(c *gin.Context) {
	event, ok := h.lookupRiskControlEvent(c)
	if !ok {
		return
	}
	sample, err := h.riskSamples().Append(riskcontrol.NewSampleRecordFromBlockEvent(event, riskcontrol.SampleShouldBlock, "confirm_block", time.Now().UTC()))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"sample": sample})
}

// PostRiskControlObservationAllow labels an observe-only event as a should_allow sample.
func (h *Handler) PostRiskControlObservationAllow(c *gin.Context) {
	event, ok := h.lookupRiskControlObserveEvent(c)
	if !ok {
		return
	}
	sample, err := h.riskSamples().Append(riskcontrol.NewSampleRecordFromBlockEvent(event, riskcontrol.SampleShouldAllow, "observe_allow", time.Now().UTC()))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"sample": sample})
}

// PostRiskControlObservationBlock labels an observe-only event as a should_block sample.
func (h *Handler) PostRiskControlObservationBlock(c *gin.Context) {
	event, ok := h.lookupRiskControlObserveEvent(c)
	if !ok {
		return
	}
	sample, err := h.riskSamples().Append(riskcontrol.NewSampleRecordFromBlockEvent(event, riskcontrol.SampleShouldBlock, "observe_block", time.Now().UTC()))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"sample": sample})
}

// GetRiskControlPage serves a standalone management page for blocked-session inspection.
func (h *Handler) GetRiskControlPage(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(riskControlPageHTML))
}

func (h *Handler) listRiskControlEvents(c *gin.Context, store *riskcontrol.BlockEventStore, unavailableMessage string) {
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": unavailableMessage})
		return
	}

	limit, errLimit := parseLimit(c.Query("limit"))
	if errLimit != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid limit: %v", errLimit)})
		return
	}

	beforeID, errBeforeID := parseUintQuery(c.Query("before_id"))
	if errBeforeID != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid before_id: %v", errBeforeID)})
		return
	}

	page := store.ListBlockedEvents(riskcontrol.BlockEventListOptions{
		SessionID: c.Query("session_id"),
		BeforeID:  beforeID,
		Limit:     limit,
	})
	c.JSON(http.StatusOK, page)
}

func (h *Handler) lookupRiskControlEvent(c *gin.Context) (riskcontrol.BlockEvent, bool) {
	return h.lookupRiskControlEventFromStore(c, h.riskBlockEvents(), "risk control block log unavailable", "block event not found")
}

func (h *Handler) lookupRiskControlObserveEvent(c *gin.Context) (riskcontrol.BlockEvent, bool) {
	return h.lookupRiskControlEventFromStore(c, h.riskObserveEvents(), "risk control observe log unavailable", "observe event not found")
}

func (h *Handler) lookupRiskControlEventFromStore(c *gin.Context, store *riskcontrol.BlockEventStore, unavailableMessage string, notFoundMessage string) (riskcontrol.BlockEvent, bool) {
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": unavailableMessage})
		return riskcontrol.BlockEvent{}, false
	}
	id, err := parseUintQuery(c.Param("id"))
	if err != nil || id == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid block id"})
		return riskcontrol.BlockEvent{}, false
	}
	event, ok := store.GetBlockedEventByID(id)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": notFoundMessage})
		return riskcontrol.BlockEvent{}, false
	}
	return event, true
}

func (h *Handler) riskBlockEvents() *riskcontrol.BlockEventStore {
	if h != nil && h.riskBlockStore != nil {
		return h.riskBlockStore
	}
	return riskcontrol.DefaultBlockedEventStore()
}

func (h *Handler) riskObserveEvents() *riskcontrol.BlockEventStore {
	if h != nil && h.riskObserveStore != nil {
		return h.riskObserveStore
	}
	return riskcontrol.DefaultObserveEventStore()
}

func (h *Handler) riskOverrides() *riskcontrol.OverrideStore {
	if h != nil && h.riskOverrideStore != nil {
		return h.riskOverrideStore
	}
	return riskcontrol.DefaultOverrideStore()
}

func (h *Handler) riskSamples() *riskcontrol.SampleStore {
	if h != nil && h.riskSampleStore != nil {
		return h.riskSampleStore
	}
	return riskcontrol.DefaultSampleStore()
}

func (h *Handler) sessionOverrideTTL() time.Duration {
	const fallback = time.Hour
	if h == nil || h.cfg == nil {
		return fallback
	}
	raw := strings.TrimSpace(h.cfg.RiskControl.AllowSessionTTL)
	if raw == "" {
		return fallback
	}
	value, err := time.ParseDuration(raw)
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func parseUintQuery(raw string) (uint64, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return 0, nil
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("must be a positive integer")
	}
	return parsed, nil
}

const riskControlPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Risk Control Blocks</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #0d1117;
      --panel: #161b22;
      --muted: #8b949e;
      --border: #30363d;
      --text: #e6edf3;
      --accent: #58a6ff;
      --danger: #ff7b72;
      --ok: #3fb950;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font: 14px/1.45 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      color: var(--text);
      background: radial-gradient(circle at top, #131b26, var(--bg) 55%);
    }
    main {
      max-width: 1440px;
      margin: 0 auto;
      padding: 20px;
    }
    h1 { margin: 0 0 6px; font-size: 28px; }
    .subtle { color: var(--muted); }
    .toolbar, .panel {
      background: rgba(22, 27, 34, 0.92);
      border: 1px solid var(--border);
      border-radius: 16px;
      box-shadow: 0 18px 48px rgba(0, 0, 0, 0.24);
    }
    .toolbar {
      display: grid;
      grid-template-columns: minmax(180px, 1fr) minmax(180px, 1fr) minmax(180px, 1.4fr) auto auto;
      gap: 12px;
      align-items: end;
      padding: 16px;
      margin: 18px 0;
    }
    .tabs {
      display: flex;
      gap: 10px;
      margin: 0 0 14px;
    }
    .tab-button {
      min-width: 120px;
    }
    .tab-button.active {
      border-color: rgba(88,166,255,0.8);
      background: rgba(88,166,255,0.2);
      color: var(--text);
    }
    .field {
      display: flex;
      flex-direction: column;
      gap: 6px;
    }
    .field label {
      color: var(--muted);
      font-size: 12px;
    }
    input, button, textarea {
      border: 1px solid var(--border);
      background: #0f141a;
      color: var(--text);
      border-radius: 10px;
      padding: 10px 12px;
      font: inherit;
    }
    button {
      cursor: pointer;
      min-height: 40px;
    }
    button.primary { background: rgba(88,166,255,0.18); }
    button.warn { background: rgba(255,123,114,0.14); }
    button.ok { background: rgba(63,185,80,0.16); }
    button:disabled { opacity: 0.45; cursor: default; }
    .hidden { display: none !important; }
    .layout {
      display: grid;
      grid-template-columns: minmax(0, 1.5fr) minmax(340px, 0.95fr);
      gap: 16px;
    }
    .panel-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      padding: 14px 16px;
      border-bottom: 1px solid var(--border);
    }
    .table-wrap {
      overflow: auto;
      max-height: calc(100vh - 250px);
    }
    table {
      width: 100%;
      border-collapse: collapse;
    }
    th, td {
      text-align: left;
      vertical-align: top;
      padding: 10px 12px;
      border-bottom: 1px solid rgba(48,54,61,0.7);
    }
    th {
      position: sticky;
      top: 0;
      background: #11161d;
      color: var(--muted);
      z-index: 1;
    }
    tbody tr { cursor: pointer; }
    tbody tr:hover { background: rgba(88,166,255,0.08); }
    tbody tr.selected { background: rgba(88,166,255,0.14); }
    .chip {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      border: 1px solid var(--border);
      border-radius: 999px;
      padding: 2px 10px;
      font-size: 12px;
      white-space: nowrap;
    }
    .chip.warn { color: var(--danger); }
    .chip.ok { color: var(--ok); }
    .detail {
      padding: 16px;
      display: grid;
      gap: 14px;
    }
    .detail-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 12px;
    }
    .detail-grid div { min-width: 0; }
    .detail-grid strong, .section strong {
      display: block;
      margin-bottom: 6px;
      color: var(--muted);
      font-size: 12px;
      font-weight: 500;
    }
    pre {
      margin: 0;
      padding: 12px;
      overflow: auto;
      background: #0f141a;
      border: 1px solid var(--border);
      border-radius: 10px;
      white-space: pre-wrap;
      word-break: break-word;
    }
    .actions {
      display: grid;
      gap: 10px;
    }
    .status {
      min-height: 20px;
      color: var(--muted);
      margin: 0 0 16px;
    }
    .status:not(:empty) {
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 10px 12px;
      background: rgba(22, 27, 34, 0.92);
    }
    .status-success:not(:empty) {
      border-color: rgba(63, 185, 80, 0.45);
      background: rgba(63, 185, 80, 0.12);
      color: var(--ok);
    }
    .status-error:not(:empty) {
      border-color: rgba(255, 123, 114, 0.5);
      background: rgba(255, 123, 114, 0.12);
      color: var(--danger);
    }
    .status-pending:not(:empty) {
      border-color: rgba(88, 166, 255, 0.45);
      background: rgba(88, 166, 255, 0.12);
      color: var(--accent);
    }
    @media (max-width: 1100px) {
      .toolbar, .layout { grid-template-columns: 1fr; }
      .detail-grid { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <main>
    <h1>Risk Control Blocks</h1>
    <div class="subtle">Path: <code>/management-risk-control.html</code> · API: <code>/v0/management/risk-control/blocks</code></div>

    <section class="toolbar">
      <div class="field">
        <label for="sessionFilter">Session filter</label>
        <input id="sessionFilter" placeholder="execution:..., prompt-cache:..., request:...">
      </div>
      <div class="field">
        <label for="limit">Batch size</label>
        <input id="limit" type="number" value="20" min="1" max="100">
      </div>
      <div class="field">
        <label for="managementKey">Management key</label>
        <input id="managementKey" type="password" placeholder="Bearer or X-Management-Key">
      </div>
      <button id="loadBtn" class="primary">Load</button>
      <button id="loadOlderBtn">Load older</button>
    </section>

    <div class="status" id="status" role="status" aria-live="polite"></div>

    <div class="tabs" role="tablist" aria-label="Risk control event type">
      <button id="blockedTabBtn" class="tab-button active" role="tab" aria-selected="true">Blocked</button>
      <button id="observeTabBtn" class="tab-button" role="tab" aria-selected="false">Observe</button>
    </div>

    <section class="layout">
      <section class="panel">
        <div class="panel-header">
          <div id="tableTitle">Recent blocked events</div>
          <div class="subtle" id="countLabel">0 rows</div>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th id="timeHeader">Blocked At</th>
                <th>Session</th>
                <th>Policy</th>
                <th>Confidence</th>
                <th>Reason</th>
              </tr>
            </thead>
            <tbody id="rows">
              <tr><td colspan="6" class="subtle">No data loaded yet.</td></tr>
            </tbody>
          </table>
        </div>
      </section>

      <aside class="panel">
        <div class="panel-header">
          <div>Selected event</div>
          <div id="selectedID" class="subtle">none</div>
        </div>
        <div class="detail">
          <div class="detail-grid">
            <div><strong>Session ID</strong><div id="detailSession">-</div></div>
            <div><strong>Decision source</strong><div id="detailDecisionSource">-</div></div>
            <div><strong>Policy code</strong><div id="detailPolicy">-</div></div>
            <div><strong>Subcategory</strong><div id="detailSubcategory">-</div></div>
            <div><strong>Confidence</strong><div id="detailConfidence">-</div></div>
            <div><strong>Authorized context</strong><div id="detailAuthorized">-</div></div>
          </div>

          <div class="section">
            <strong>Evidence</strong>
            <pre id="detailEvidence">-</pre>
          </div>

          <div class="section">
            <strong>User input</strong>
            <pre id="detailInput">-</pre>
          </div>

          <div class="section">
            <strong>Raw audit response</strong>
            <pre id="detailRaw">-</pre>
          </div>

          <div class="actions">
            <button id="allowOnceBtn" class="ok" disabled>Allow once</button>
            <button id="allowSessionBtn" class="primary" disabled>Allow session</button>
            <button id="confirmBlockBtn" class="warn" disabled>Confirm block</button>
            <button id="observeAllowBtn" class="ok hidden" disabled>ALLOW</button>
            <button id="observeBlockBtn" class="warn hidden" disabled>BLOCK</button>
          </div>
        </div>
      </aside>
    </section>
  </main>

  <script>
    var rowsEl = document.getElementById('rows');
    var statusEl = document.getElementById('status');
    var countLabelEl = document.getElementById('countLabel');
    var selectedIDEl = document.getElementById('selectedID');
    var detailSessionEl = document.getElementById('detailSession');
    var detailDecisionSourceEl = document.getElementById('detailDecisionSource');
    var detailPolicyEl = document.getElementById('detailPolicy');
    var detailSubcategoryEl = document.getElementById('detailSubcategory');
    var detailConfidenceEl = document.getElementById('detailConfidence');
    var detailAuthorizedEl = document.getElementById('detailAuthorized');
    var detailEvidenceEl = document.getElementById('detailEvidence');
    var detailInputEl = document.getElementById('detailInput');
    var detailRawEl = document.getElementById('detailRaw');
    var managementKeyEl = document.getElementById('managementKey');
    var sessionFilterEl = document.getElementById('sessionFilter');
    var limitEl = document.getElementById('limit');
    var allowOnceBtn = document.getElementById('allowOnceBtn');
    var allowSessionBtn = document.getElementById('allowSessionBtn');
    var confirmBlockBtn = document.getElementById('confirmBlockBtn');
    var observeAllowBtn = document.getElementById('observeAllowBtn');
    var observeBlockBtn = document.getElementById('observeBlockBtn');
    var loadOlderBtn = document.getElementById('loadOlderBtn');
    var blockedTabBtn = document.getElementById('blockedTabBtn');
    var observeTabBtn = document.getElementById('observeTabBtn');
    var tableTitleEl = document.getElementById('tableTitle');
    var timeHeaderEl = document.getElementById('timeHeader');

    var activeView = 'blocks';
    var selected = null;
    var nextBeforeID = 0;
    var hasMore = false;
    var items = [];

    function currentKey() {
      return (managementKeyEl.value || '').trim();
    }

    function setStatus(message, state) {
      var tone = state === true ? 'error' : (state || 'neutral');
      statusEl.textContent = message || '';
      statusEl.className = 'status';
      if (message) {
        statusEl.classList.add('status-' + tone);
      }
    }

    function headers() {
      var hdr = {};
      var key = currentKey();
      if (key) {
        hdr['X-Management-Key'] = key;
        window.sessionStorage.setItem('risk-control-management-key', key);
      }
      return hdr;
    }

    function renderRows() {
      if (!items.length) {
        rowsEl.innerHTML = '<tr><td colspan="6" class="subtle">No events matched.</td></tr>';
      } else {
        rowsEl.innerHTML = items.map(function(item) {
          var selectedClass = selected && selected.id === item.id ? ' class="selected"' : '';
          return '<tr data-id="' + item.id + '"' + selectedClass + '>' +
            '<td>' + item.id + '</td>' +
            '<td>' + escapeHTML(item.observed_at || item.blocked_at || '') + '</td>' +
            '<td>' + escapeHTML(item.session_id || '') + '</td>' +
            '<td>' + escapeHTML(item.policy_code || '-') + '</td>' +
            '<td>' + escapeHTML(formatConfidence(item.confidence)) + '</td>' +
            '<td>' + escapeHTML(item.reason || item.audit_error || '-') + '</td>' +
          '</tr>';
        }).join('');
      }
      countLabelEl.textContent = items.length + ' rows';
      loadOlderBtn.disabled = !hasMore;
    }

    function renderDetail() {
      var item = selected;
      selectedIDEl.textContent = item ? String(item.id) : 'none';
      detailSessionEl.textContent = item ? (item.session_id || '-') : '-';
      detailDecisionSourceEl.textContent = item ? (item.decision_source || '-') : '-';
      detailPolicyEl.textContent = item ? (item.policy_code || '-') : '-';
      detailSubcategoryEl.textContent = item ? (item.subcategory_code || '-') : '-';
      detailConfidenceEl.textContent = item ? formatConfidence(item.confidence) : '-';
      detailAuthorizedEl.textContent = item ? (item.authorized_context || '-') : '-';
      detailEvidenceEl.textContent = item && item.evidence && item.evidence.length ? item.evidence.join('\n') : '-';
      detailInputEl.textContent = item ? (item.user_text_preview || '-') : '-';
      detailRawEl.textContent = item ? (item.raw_audit_response || '-') : '-';
      var isObserve = activeView === 'observe';
      allowOnceBtn.classList.toggle('hidden', isObserve);
      allowSessionBtn.classList.toggle('hidden', isObserve);
      confirmBlockBtn.classList.toggle('hidden', isObserve);
      observeAllowBtn.classList.toggle('hidden', !isObserve);
      observeBlockBtn.classList.toggle('hidden', !isObserve);
      allowOnceBtn.disabled = isObserve || !item || !item.input_hash;
      allowSessionBtn.disabled = isObserve || !item || !item.session_id;
      confirmBlockBtn.disabled = isObserve || !item;
      observeAllowBtn.disabled = !isObserve || !item;
      observeBlockBtn.disabled = !isObserve || !item;
      renderRows();
    }

    function formatConfidence(value) {
      if (typeof value !== 'number') {
        return '-';
      }
      return value.toFixed(2);
    }

    function escapeHTML(value) {
      return String(value || '')
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;');
    }

    async function loadBlocks(append) {
      var params = new URLSearchParams();
      var sessionID = (sessionFilterEl.value || '').trim();
      if (sessionID) params.set('session_id', sessionID);
      var limit = Math.max(1, Math.min(100, Number(limitEl.value || 20)));
      params.set('limit', String(limit));
      if (append && nextBeforeID) params.set('before_id', String(nextBeforeID));

      var endpoint = activeView === 'observe' ? '/v0/management/risk-control/observations' : '/v0/management/risk-control/blocks';
      setStatus('Loading ' + activeView + ' events...', 'pending');
      var resp = await fetch(endpoint + '?' + params.toString(), { headers: headers() });
      var payload = await readResponsePayload(resp);
      if (!resp.ok) {
        throw new Error(responseErrorMessage(resp, payload));
      }

      nextBeforeID = payload.next_before_id || 0;
      hasMore = !!payload.has_more;
      items = append ? items.concat(payload.items || []) : (payload.items || []);
      if (!selected && items.length) {
        selected = items[0];
      } else if (selected) {
        selected = items.find(function(item) { return item.id === selected.id; }) || null;
      }
      renderDetail();
      setStatus('Loaded ' + (payload.returned || 0) + ' rows.');
    }

    function switchView(view) {
      activeView = view;
      selected = null;
      nextBeforeID = 0;
      hasMore = false;
      items = [];
      blockedTabBtn.classList.toggle('active', view === 'blocks');
      observeTabBtn.classList.toggle('active', view === 'observe');
      blockedTabBtn.setAttribute('aria-selected', view === 'blocks' ? 'true' : 'false');
      observeTabBtn.setAttribute('aria-selected', view === 'observe' ? 'true' : 'false');
      tableTitleEl.textContent = view === 'observe' ? 'Observe-only audit events' : 'Recent blocked events';
      timeHeaderEl.textContent = view === 'observe' ? 'Observed At' : 'Blocked At';
      rowsEl.innerHTML = '<tr><td colspan="6" class="subtle">No data loaded yet.</td></tr>';
      renderDetail();
      loadBlocks(false).catch(function(err) { setStatus(err.message, true); });
    }

    async function readResponsePayload(resp) {
      var text = await resp.text();
      if (!text) return {};
      try {
        return JSON.parse(text);
      } catch (_) {
        return { _raw: text };
      }
    }

    function responseErrorMessage(resp, payload) {
      var detail = '';
      if (payload) {
        detail = payload.error || payload.message || payload.status || payload._raw || '';
      }
      detail = String(detail || '').trim();
      return detail ? ('HTTP ' + resp.status + ': ' + detail) : ('HTTP ' + resp.status);
    }

    function setActionButtonsBusy(isBusy) {
      allowOnceBtn.disabled = true;
      allowSessionBtn.disabled = true;
      confirmBlockBtn.disabled = true;
      observeAllowBtn.disabled = true;
      observeBlockBtn.disabled = true;
      if (!isBusy) {
        renderDetail();
      }
    }

    async function postAction(path, successMessage) {
      if (!selected) {
        setStatus('Action failed: no event selected.', 'error');
        return;
      }
      var eventID = selected.id;
      setStatus('Submitting action for event #' + eventID + '...', 'pending');
      setActionButtonsBusy(true);
      try {
        var resp = await fetch(path, { method: 'POST', headers: headers() });
        var payload = await readResponsePayload(resp);
        if (!resp.ok) {
          setStatus('Action failed for event #' + eventID + ': ' + responseErrorMessage(resp, payload), 'error');
          return;
        }
        var expires = payload && payload.override && payload.override.expires_at ? (' Expires at ' + payload.override.expires_at + '.') : '';
        setStatus(successMessage + ' Event #' + eventID + '.' + expires, 'success');
      } catch (err) {
        var message = err && err.message ? err.message : String(err);
        setStatus('Action failed for event #' + eventID + ': ' + message, 'error');
      } finally {
        setActionButtonsBusy(false);
      }
    }

    rowsEl.addEventListener('click', function(event) {
      var row = event.target.closest('tr[data-id]');
      if (!row) return;
      var id = Number(row.getAttribute('data-id'));
      selected = items.find(function(item) { return item.id === id; }) || null;
      renderDetail();
    });

    document.getElementById('loadBtn').addEventListener('click', function() {
      selected = null;
      nextBeforeID = 0;
      hasMore = false;
      loadBlocks(false).catch(function(err) { setStatus(err.message, true); });
    });

    loadOlderBtn.addEventListener('click', function() {
      loadBlocks(true).catch(function(err) { setStatus(err.message, true); });
    });

    allowOnceBtn.addEventListener('click', function() {
      postAction('/v0/management/risk-control/blocks/' + selected.id + '/allow-once', 'Allow once succeeded; API call completed.');
    });

    allowSessionBtn.addEventListener('click', function() {
      postAction('/v0/management/risk-control/blocks/' + selected.id + '/allow-session', 'Allow session succeeded; API call completed.');
    });

    confirmBlockBtn.addEventListener('click', function() {
      postAction('/v0/management/risk-control/blocks/' + selected.id + '/confirm-block', 'Confirm block succeeded; API call completed.');
    });

    observeAllowBtn.addEventListener('click', function() {
      postAction('/v0/management/risk-control/observations/' + selected.id + '/allow', 'Observe ALLOW label saved; sample added.');
    });

    observeBlockBtn.addEventListener('click', function() {
      postAction('/v0/management/risk-control/observations/' + selected.id + '/block', 'Observe BLOCK label saved; sample added.');
    });

    blockedTabBtn.addEventListener('click', function() {
      if (activeView !== 'blocks') switchView('blocks');
    });

    observeTabBtn.addEventListener('click', function() {
      if (activeView !== 'observe') switchView('observe');
    });

    window.addEventListener('load', function() {
      var savedKey = window.sessionStorage.getItem('risk-control-management-key');
      if (savedKey) managementKeyEl.value = savedKey;
    });
  </script>
</body>
</html>`
