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
	store := h.riskBlockEvents()
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "risk control block log unavailable"})
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

// GetRiskControlPage serves a standalone management page for blocked-session inspection.
func (h *Handler) GetRiskControlPage(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(riskControlPageHTML))
}

func (h *Handler) lookupRiskControlEvent(c *gin.Context) (riskcontrol.BlockEvent, bool) {
	store := h.riskBlockEvents()
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "risk control block log unavailable"})
		return riskcontrol.BlockEvent{}, false
	}
	id, err := parseUintQuery(c.Param("id"))
	if err != nil || id == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid block id"})
		return riskcontrol.BlockEvent{}, false
	}
	event, ok := store.GetBlockedEventByID(id)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "block event not found"})
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

    <div class="status" id="status"></div>

    <section class="layout">
      <section class="panel">
        <div class="panel-header">
          <div>Recent blocked events</div>
          <div class="subtle" id="countLabel">0 rows</div>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Blocked At</th>
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
    var loadOlderBtn = document.getElementById('loadOlderBtn');

    var selected = null;
    var nextBeforeID = 0;
    var hasMore = false;
    var items = [];

    function currentKey() {
      return (managementKeyEl.value || '').trim();
    }

    function setStatus(message, isError) {
      statusEl.textContent = message || '';
      statusEl.style.color = isError ? 'var(--danger)' : 'var(--muted)';
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
            '<td>' + escapeHTML(item.blocked_at || '') + '</td>' +
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
      allowOnceBtn.disabled = !item || !item.input_hash;
      allowSessionBtn.disabled = !item || !item.session_id;
      confirmBlockBtn.disabled = !item;
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

      setStatus('Loading...');
      var resp = await fetch('/v0/management/risk-control/blocks?' + params.toString(), { headers: headers() });
      var payload = await resp.json();
      if (!resp.ok) {
        throw new Error(payload.error || ('HTTP ' + resp.status));
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

    async function postAction(path, successMessage) {
      if (!selected) return;
      setStatus('Submitting...');
      var resp = await fetch(path, { method: 'POST', headers: headers() });
      var payload = await resp.json();
      if (!resp.ok) {
        throw new Error(payload.error || ('HTTP ' + resp.status));
      }
      setStatus(successMessage);
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
      postAction('/v0/management/risk-control/blocks/' + selected.id + '/allow-once', 'Allow-once override created and sample labeled.')
        .catch(function(err) { setStatus(err.message, true); });
    });

    allowSessionBtn.addEventListener('click', function() {
      postAction('/v0/management/risk-control/blocks/' + selected.id + '/allow-session', 'Session override created and sample labeled.')
        .catch(function(err) { setStatus(err.message, true); });
    });

    confirmBlockBtn.addEventListener('click', function() {
      postAction('/v0/management/risk-control/blocks/' + selected.id + '/confirm-block', 'Block sample confirmed.')
        .catch(function(err) { setStatus(err.message, true); });
    });

    window.addEventListener('load', function() {
      var savedKey = window.sessionStorage.getItem('risk-control-management-key');
      if (savedKey) managementKeyEl.value = savedKey;
    });
  </script>
</body>
</html>`
