package management

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/riskcontrol"
)

// GetRiskControlBlocks lists persisted risk-control block events.
func (h *Handler) GetRiskControlBlocks(c *gin.Context) {
	reader := h.riskBlockEvents()
	if reader == nil {
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

	page := reader.ListBlockedEvents(riskcontrol.BlockEventListOptions{
		SessionID: c.Query("session_id"),
		BeforeID:  beforeID,
		Limit:     limit,
	})
	c.JSON(http.StatusOK, page)
}

// GetRiskControlPage serves a standalone management page for blocked-session inspection.
func (h *Handler) GetRiskControlPage(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(riskControlPageHTML))
}

func (h *Handler) riskBlockEvents() riskcontrol.BlockEventReader {
	if h != nil && h.riskBlockReader != nil {
		return h.riskBlockReader
	}
	return riskcontrol.DefaultBlockedEventStore()
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
      --panel-alt: #0f141a;
      --border: #30363d;
      --text: #e6edf3;
      --muted: #8b949e;
      --danger: #ff7b72;
      --accent: #58a6ff;
      --ok: #3fb950;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font: 14px/1.45 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    a { color: var(--accent); }
    main {
      max-width: 1480px;
      margin: 0 auto;
      padding: 20px;
    }
    header {
      display: flex;
      justify-content: space-between;
      gap: 16px;
      align-items: flex-end;
      margin-bottom: 16px;
      flex-wrap: wrap;
    }
    h1 {
      margin: 0;
      font-size: 24px;
      font-weight: 600;
    }
    .subtle {
      color: var(--muted);
      font-size: 13px;
    }
    .toolbar, .layout > section, .layout > aside {
      border: 1px solid var(--border);
      background: var(--panel);
    }
    .toolbar {
      display: grid;
      grid-template-columns: minmax(220px, 1.3fr) minmax(220px, 1.6fr) 120px auto 1fr;
      gap: 12px;
      padding: 12px;
      margin-bottom: 16px;
      align-items: end;
    }
    .field {
      display: flex;
      flex-direction: column;
      gap: 6px;
    }
    .field span {
      color: var(--muted);
      font-size: 12px;
    }
    input, select, button {
      height: 36px;
      border: 1px solid var(--border);
      background: var(--panel-alt);
      color: var(--text);
      padding: 0 10px;
      font: inherit;
    }
    button {
      cursor: pointer;
      min-width: 96px;
    }
    button:disabled {
      opacity: 0.45;
      cursor: default;
    }
    .toolbar-actions {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
    }
    #status {
      text-align: right;
      color: var(--muted);
      min-height: 20px;
      align-self: center;
    }
    .layout {
      display: grid;
      grid-template-columns: minmax(0, 1.45fr) minmax(320px, 0.95fr);
      gap: 16px;
      align-items: start;
    }
    .list-panel {
      overflow: hidden;
    }
    .panel-title {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      padding: 12px 14px;
      border-bottom: 1px solid var(--border);
      background: #11161d;
      font-weight: 600;
    }
    .table-wrap {
      overflow: auto;
      max-height: calc(100vh - 230px);
    }
    table {
      width: 100%;
      border-collapse: collapse;
    }
    th, td {
      padding: 10px 12px;
      border-bottom: 1px solid rgba(48, 54, 61, 0.7);
      text-align: left;
      vertical-align: top;
    }
    th {
      position: sticky;
      top: 0;
      background: #11161d;
      z-index: 1;
      color: var(--muted);
      font-weight: 500;
    }
    tbody tr {
      cursor: pointer;
    }
    tbody tr:hover {
      background: rgba(88, 166, 255, 0.08);
    }
    tbody tr.selected {
      background: rgba(88, 166, 255, 0.14);
    }
    .reason {
      color: var(--danger);
      font-weight: 600;
    }
    .chip {
      display: inline-flex;
      align-items: center;
      border: 1px solid var(--border);
      padding: 2px 8px;
      height: 24px;
      background: var(--panel-alt);
      font-size: 12px;
      white-space: nowrap;
    }
    .chip.ok {
      color: var(--ok);
    }
    .chip.warn {
      color: var(--danger);
    }
    .empty {
      padding: 24px;
      color: var(--muted);
    }
    .detail-panel {
      min-height: 540px;
    }
    .detail-body {
      padding: 14px;
      display: grid;
      gap: 14px;
    }
    .detail-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 10px 14px;
    }
    .detail-item {
      min-width: 0;
    }
    .detail-item .label {
      display: block;
      color: var(--muted);
      font-size: 12px;
      margin-bottom: 4px;
    }
    .detail-item .value {
      word-break: break-word;
    }
    pre {
      margin: 0;
      padding: 12px;
      border: 1px solid var(--border);
      background: var(--panel-alt);
      overflow: auto;
      white-space: pre-wrap;
      word-break: break-word;
      font: 12px/1.5 ui-monospace, SFMono-Regular, Consolas, monospace;
    }
    ul {
      margin: 0;
      padding-left: 18px;
    }
    .footer-row {
      padding: 12px 14px;
      border-top: 1px solid var(--border);
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      color: var(--muted);
    }
    @media (max-width: 1100px) {
      .toolbar {
        grid-template-columns: 1fr 120px;
      }
      #status {
        text-align: left;
        grid-column: 1 / -1;
      }
      .layout {
        grid-template-columns: 1fr;
      }
      .table-wrap {
        max-height: none;
      }
      .detail-grid {
        grid-template-columns: 1fr;
      }
    }
  </style>
</head>
<body>
  <main>
    <header>
      <div>
        <h1>Risk Control Blocks</h1>
        <div class="subtle">Persisted to a local file. Only the latest 20 blocked requests are retained, including cached session decisions reused within the audit sampling window.</div>
      </div>
      <div class="subtle">Path: <code>/management-risk-control.html</code></div>
    </header>

    <section class="toolbar">
      <label class="field">
        <span>Management key</span>
        <input id="managementKey" type="password" autocomplete="off" placeholder="Bearer key or X-Management-Key">
      </label>
      <label class="field">
        <span>Session filter</span>
        <input id="sessionFilter" type="text" placeholder="execution:..., header:..., raw session fragment">
      </label>
      <label class="field">
        <span>Page size</span>
        <select id="limitSelect">
          <option value="5">5</option>
          <option value="10">10</option>
          <option value="20" selected>20</option>
        </select>
      </label>
      <div class="toolbar-actions">
        <button id="applyBtn" type="button">Apply</button>
        <button id="refreshBtn" type="button">Refresh</button>
        <button id="loadMoreBtn" type="button" disabled>Load older</button>
      </div>
      <div id="status"></div>
    </section>

    <div class="layout">
      <section class="list-panel">
        <div class="panel-title">
          <span>Blocked requests</span>
          <span id="countBadge" class="subtle">0 loaded</span>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th style="width: 188px;">Blocked at</th>
                <th style="width: 220px;">Session</th>
                <th style="width: 160px;">Reason</th>
                <th style="width: 130px;">Decision</th>
                <th style="width: 170px;">Model</th>
                <th>Preview</th>
              </tr>
            </thead>
            <tbody id="rows"></tbody>
          </table>
          <div id="emptyState" class="empty" hidden>No blocked requests recorded in the retained 20-entry history for the current filter.</div>
        </div>
        <div class="footer-row">
          <span>Newest entries first, latest 20 retained</span>
          <span id="paginationHint"></span>
        </div>
      </section>

      <aside class="detail-panel">
        <div class="panel-title">
          <span>Block details</span>
          <span id="detailHint" class="subtle">Select a row</span>
        </div>
        <div id="detailBody" class="detail-body">
          <div class="empty">Select a blocked request to inspect why the session was intercepted.</div>
        </div>
      </aside>
    </div>
  </main>

  <script>
    (function () {
      var endpoint = '/v0/management/risk-control/blocks';
      var state = {
        items: [],
        selectedID: 0,
        nextBeforeID: 0,
        hasMore: false,
        total: 0,
        loading: false
      };

      var managementKeyInput = document.getElementById('managementKey');
      var sessionFilter = document.getElementById('sessionFilter');
      var limitSelect = document.getElementById('limitSelect');
      var applyBtn = document.getElementById('applyBtn');
      var refreshBtn = document.getElementById('refreshBtn');
      var loadMoreBtn = document.getElementById('loadMoreBtn');
      var statusNode = document.getElementById('status');
      var countBadge = document.getElementById('countBadge');
      var paginationHint = document.getElementById('paginationHint');
      var rowsNode = document.getElementById('rows');
      var emptyState = document.getElementById('emptyState');
      var detailBody = document.getElementById('detailBody');
      var detailHint = document.getElementById('detailHint');

      function escapeHTML(value) {
        return String(value || '')
          .replace(/&/g, '&amp;')
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;')
          .replace(/"/g, '&quot;')
          .replace(/'/g, '&#39;');
      }

      function formatTime(value) {
        if (!value) {
          return '-';
        }
        var date = new Date(value);
        if (Number.isNaN(date.getTime())) {
          return value;
        }
        return date.toLocaleString();
      }

      function previewText(value) {
        var text = String(value || '').replace(/\s+/g, ' ').trim();
        if (!text) {
          return '-';
        }
        if (text.length > 120) {
          return text.slice(0, 120) + '...';
        }
        return text;
      }

      function decisionLabel(item) {
        return item && item.decision_source === 'session_cache' ? 'session cache' : 'fresh audit';
      }

      function setStatus(text, isError) {
        statusNode.textContent = text || '';
        statusNode.style.color = isError ? 'var(--danger)' : 'var(--muted)';
      }

      function buildURL(reset) {
        var url = new URL(endpoint, window.location.href);
        var sessionID = sessionFilter.value.trim();
        var limit = limitSelect.value;
        if (sessionID) {
          url.searchParams.set('session_id', sessionID);
        }
        if (limit) {
          url.searchParams.set('limit', limit);
        }
        if (!reset && state.nextBeforeID) {
          url.searchParams.set('before_id', String(state.nextBeforeID));
        }
        return url;
      }

      function currentManagementKey() {
        return managementKeyInput.value.trim();
      }

      function selectedItem() {
        for (var i = 0; i < state.items.length; i++) {
          if (state.items[i].id === state.selectedID) {
            return state.items[i];
          }
        }
        return state.items.length > 0 ? state.items[0] : null;
      }

      function renderRows() {
        if (!state.items.length) {
          rowsNode.innerHTML = '';
          emptyState.hidden = false;
          countBadge.textContent = '0 loaded';
          paginationHint.textContent = '';
          return;
        }

        emptyState.hidden = true;
        countBadge.textContent = String(state.items.length) + ' loaded';
        paginationHint.textContent = state.hasMore ? 'More history available' : 'No more older entries';

        var html = '';
        for (var i = 0; i < state.items.length; i++) {
          var item = state.items[i];
          var selected = item.id === state.selectedID ? ' selected' : '';
          html += '<tr class="' + selected + '" data-id="' + item.id + '">';
          html += '<td>' + escapeHTML(formatTime(item.blocked_at)) + '</td>';
          html += '<td><div>' + escapeHTML(item.session_id || '-') + '</div><div class="subtle">' + escapeHTML(item.request_path || '-') + '</div></td>';
          html += '<td><span class="reason">' + escapeHTML(item.reason || 'blocked') + '</span></td>';
          html += '<td><span class="chip ' + (item.decision_source === 'session_cache' ? 'warn' : 'ok') + '">' + escapeHTML(decisionLabel(item)) + '</span></td>';
          html += '<td><div>' + escapeHTML(item.requested_model || item.upstream_model || '-') + '</div><div class="subtle">' + escapeHTML(item.upstream_model || '-') + '</div></td>';
          html += '<td>' + escapeHTML(previewText(item.user_text_preview)) + '</td>';
          html += '</tr>';
        }
        rowsNode.innerHTML = html;
      }

      function renderDetail() {
        var item = selectedItem();
        if (!item) {
          detailHint.textContent = 'Select a row';
          detailBody.innerHTML = '<div class="empty">Select a blocked request to inspect why the session was intercepted.</div>';
          return;
        }

        state.selectedID = item.id;
        detailHint.textContent = 'Event #' + item.id;

        var imagesHTML = '<div class="subtle">None</div>';
        if (Array.isArray(item.image_references) && item.image_references.length) {
          imagesHTML = '<ul>';
          for (var i = 0; i < item.image_references.length; i++) {
            imagesHTML += '<li><code>' + escapeHTML(item.image_references[i]) + '</code></li>';
          }
          imagesHTML += '</ul>';
        }

        detailBody.innerHTML =
          '<div class="detail-grid">' +
            detailItem('Blocked at', formatTime(item.blocked_at)) +
            detailItem('Session ID', item.session_id || '-') +
            detailItem('Requested model', item.requested_model || '-') +
            detailItem('Upstream model', item.upstream_model || '-') +
            detailItem('Audit model', item.audit_model || '-') +
            detailItem('Audit endpoint', item.audit_endpoint || '-') +
            detailItem('Decision source', decisionLabel(item)) +
            detailItem('Reason', item.reason || '-') +
            detailItem('Block message', item.block_message || '-') +
            detailItem('Audit error', item.audit_error || '-') +
            detailItem('Source format', item.source_format || '-') +
            detailItem('Request path', item.request_path || '-') +
            detailItem('Message count', String(item.message_count || 0)) +
            detailItem('Input hash', item.input_hash || '-') +
          '</div>' +
          '<div>' +
            '<div class="subtle" style="margin-bottom:6px;">User text preview</div>' +
            '<pre>' + escapeHTML(item.user_text_preview || '-') + '</pre>' +
          '</div>' +
          '<div>' +
            '<div class="subtle" style="margin-bottom:6px;">Image references</div>' +
            imagesHTML +
          '</div>';
      }

      function detailItem(label, value) {
        return '<div class="detail-item"><span class="label">' + escapeHTML(label) + '</span><div class="value">' + escapeHTML(value || '-') + '</div></div>';
      }

      async function load(reset) {
        if (state.loading) {
          return;
        }
        if (!currentManagementKey()) {
          setStatus('Enter management key to load blocked events.', true);
          return;
        }
        state.loading = true;
        applyBtn.disabled = true;
        refreshBtn.disabled = true;
        loadMoreBtn.disabled = true;
        setStatus(reset ? 'Loading...' : 'Loading older entries...', false);

        try {
          var response = await fetch(buildURL(reset), {
            headers: {
              'Accept': 'application/json',
              'X-Management-Key': currentManagementKey()
            }
          });
          var payload = await response.json();
          if (!response.ok) {
            throw new Error(payload && payload.error ? payload.error : 'request failed');
          }

          if (reset) {
            state.items = Array.isArray(payload.items) ? payload.items : [];
          } else if (Array.isArray(payload.items) && payload.items.length) {
            state.items = state.items.concat(payload.items);
          }

          state.total = payload.total || 0;
          state.hasMore = !!payload.has_more;
          state.nextBeforeID = payload.next_before_id || 0;

          if (!selectedItem() && state.items.length) {
            state.selectedID = state.items[0].id;
          }

          renderRows();
          renderDetail();

          var loadedText = String(state.items.length) + ' loaded';
          if (state.total) {
            loadedText += ' / ' + String(state.total) + ' matched';
          }
          setStatus(loadedText, false);
        } catch (error) {
          setStatus(String(error && error.message ? error.message : error), true);
        } finally {
          state.loading = false;
          applyBtn.disabled = false;
          refreshBtn.disabled = false;
          loadMoreBtn.disabled = !state.hasMore;
        }
      }

      function syncFilterFromURL() {
        var url = new URL(window.location.href);
        try {
          var savedKey = window.sessionStorage.getItem('risk-control-management-key');
          if (savedKey) {
            managementKeyInput.value = savedKey;
          }
        } catch (error) {
        }
        var sessionID = url.searchParams.get('session_id');
        if (sessionID) {
          sessionFilter.value = sessionID;
        }
        var limit = url.searchParams.get('limit');
        if (limit) {
          limitSelect.value = limit;
        }
      }

      function persistManagementKey() {
        try {
          if (currentManagementKey()) {
            window.sessionStorage.setItem('risk-control-management-key', currentManagementKey());
          } else {
            window.sessionStorage.removeItem('risk-control-management-key');
          }
        } catch (error) {
        }
      }

      function updateURL() {
        var url = new URL(window.location.href);
        var sessionID = sessionFilter.value.trim();
        if (sessionID) {
          url.searchParams.set('session_id', sessionID);
        } else {
          url.searchParams.delete('session_id');
        }
        url.searchParams.set('limit', limitSelect.value);
        window.history.replaceState({}, '', url.toString());
      }

      applyBtn.addEventListener('click', function () {
        updateURL();
        state.selectedID = 0;
        load(true);
      });
      refreshBtn.addEventListener('click', function () {
        updateURL();
        load(true);
      });
      managementKeyInput.addEventListener('change', function () {
        persistManagementKey();
      });
      managementKeyInput.addEventListener('blur', function () {
        persistManagementKey();
      });
      loadMoreBtn.addEventListener('click', function () {
        load(false);
      });
      sessionFilter.addEventListener('keydown', function (event) {
        if (event.key === 'Enter') {
          event.preventDefault();
          updateURL();
          state.selectedID = 0;
          load(true);
        }
      });
      rowsNode.addEventListener('click', function (event) {
        var row = event.target.closest('tr[data-id]');
        if (!row) {
          return;
        }
        state.selectedID = Number(row.getAttribute('data-id'));
        renderRows();
        renderDetail();
      });

      syncFilterFromURL();
      load(true);
    }());
  </script>
</body>
</html>`
