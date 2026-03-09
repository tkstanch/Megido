/**
 * MegidoProcessTracker — cross-page background-process tracking.
 *
 * Any tool that runs a long-running backend task can call:
 *   MegidoProcessTracker.registerProcess(toolName, processId, statusEndpoint, cancelEndpoint)
 *
 * The tracker persists process state in sessionStorage so the global
 * notification bar (active-process-bar) and navigation-interception dialog
 * continue to work after the user navigates away from the tool's page.
 *
 * Public API (window.MegidoProcessTracker):
 *   registerProcess(toolName, processId, statusEndpoint, cancelEndpoint)
 *   unregisterProcess(toolName)
 *   getActiveProcesses()        → array of process descriptors
 *   isAnyProcessRunning()       → boolean
 *   getProcessForTool(toolName) → descriptor or null
 *
 * Custom events dispatched on document:
 *   megido:process-completed  { detail: { toolName, processId, data } }
 *   megido:process-failed     { detail: { toolName, processId, data } }
 *   megido:process-registered { detail: { toolName, processId } }
 *   megido:process-unregistered { detail: { toolName } }
 */
(function (global) {
    'use strict';

    var STORAGE_KEY = 'megidoActiveProcesses';
    var POLL_INTERVAL_MS = 5000;

    var _pollTimer = null;

    /* ── Persistence helpers ─────────────────────────────────────── */

    function _load() {
        try {
            var raw = sessionStorage.getItem(STORAGE_KEY);
            return raw ? JSON.parse(raw) : {};
        } catch (e) {
            return {};
        }
    }

    function _save(registry) {
        try {
            sessionStorage.setItem(STORAGE_KEY, JSON.stringify(registry));
        } catch (e) { /* storage full – ignore */ }
    }

    /* ── CSRF helper ─────────────────────────────────────────────── */

    function _getCsrf() {
        var el = document.querySelector('[name=csrfmiddlewaretoken]');
        if (el) return el.value;
        var m = document.cookie.match(/csrftoken=([^;]+)/);
        return m ? m[1] : '';
    }

    /* ── Event helpers ───────────────────────────────────────────── */

    function _dispatch(name, detail) {
        try {
            document.dispatchEvent(new CustomEvent(name, { detail: detail, bubbles: true }));
        } catch (e) { /* IE fallback — no-op */ }
    }

    /* ── Polling ─────────────────────────────────────────────────── */

    function _startPolling() {
        if (_pollTimer) return;
        _pollTimer = setInterval(_pollAll, POLL_INTERVAL_MS);
    }

    function _stopPolling() {
        if (_pollTimer) {
            clearInterval(_pollTimer);
            _pollTimer = null;
        }
    }

    function _pollAll() {
        var registry = _load();
        var keys = Object.keys(registry);
        if (keys.length === 0) {
            _stopPolling();
            return;
        }
        keys.forEach(function (toolName) {
            var proc = registry[toolName];
            if (!proc || !proc.statusEndpoint) return;
            fetch(proc.statusEndpoint, { credentials: 'same-origin' })
                .then(function (r) { return r.ok ? r.json() : null; })
                .then(function (data) {
                    if (!data) return;
                    var status = data.status;
                    if (status === 'completed' || status === 'failed') {
                        _removeFromRegistry(toolName);
                        if (status === 'completed') {
                            _dispatch('megido:process-completed', { toolName: toolName, processId: proc.processId, data: data });
                        } else {
                            _dispatch('megido:process-failed', { toolName: toolName, processId: proc.processId, data: data });
                        }
                    }
                })
                .catch(function () { /* network error — retry next tick */ });
        });
    }

    function _removeFromRegistry(toolName) {
        var registry = _load();
        delete registry[toolName];
        _save(registry);
        if (Object.keys(registry).length === 0) {
            _stopPolling();
        }
    }

    /* ── Public API ──────────────────────────────────────────────── */

    /**
     * Register a running process.
     * @param {string} toolName         Human-readable tool name (e.g. "Scanner")
     * @param {string} processId        Unique task/process ID
     * @param {string} statusEndpoint   URL that returns { status: "running"|"completed"|"failed", ... }
     * @param {string} [cancelEndpoint] Optional URL for a POST cancel request
     * @param {string} [viewUrl]        Optional URL to link to for "View Progress"
     */
    function registerProcess(toolName, processId, statusEndpoint, cancelEndpoint, viewUrl) {
        var registry = _load();
        registry[toolName] = {
            toolName: toolName,
            processId: processId,
            statusEndpoint: statusEndpoint,
            cancelEndpoint: cancelEndpoint || null,
            viewUrl: viewUrl || null,
            startTime: Date.now()
        };
        _save(registry);
        _dispatch('megido:process-registered', { toolName: toolName, processId: processId });
        _startPolling();
    }

    /**
     * Unregister a process (call when you know it has finished on the page itself).
     * @param {string} toolName
     */
    function unregisterProcess(toolName) {
        _removeFromRegistry(toolName);
        _dispatch('megido:process-unregistered', { toolName: toolName });
    }

    /**
     * Returns an array of all currently tracked process descriptors.
     * @returns {Array}
     */
    function getActiveProcesses() {
        var registry = _load();
        return Object.keys(registry).map(function (k) { return registry[k]; });
    }

    /**
     * Returns true if at least one process is currently tracked.
     * @returns {boolean}
     */
    function isAnyProcessRunning() {
        return getActiveProcesses().length > 0;
    }

    /**
     * Returns the descriptor for a specific tool, or null.
     * @param {string} toolName
     * @returns {Object|null}
     */
    function getProcessForTool(toolName) {
        var registry = _load();
        return registry[toolName] || null;
    }

    /* ── Bootstrap on load ───────────────────────────────────────── */

    // Backwards-compat: if legacy activeScanId is present but the new tracker
    // doesn't know about Scanner yet, migrate it so the bar still shows.
    function _migrateLegacyScanStorage() {
        var legacyId = sessionStorage.getItem('activeScanId');
        if (!legacyId) return;
        var registry = _load();
        if (!registry['Scanner']) {
            registry['Scanner'] = {
                toolName: 'Scanner',
                processId: legacyId,
                statusEndpoint: '/scanner/api/scans/' + legacyId + '/results/',
                cancelEndpoint: '/scanner/api/scans/' + legacyId + '/cancel/',
                viewUrl: '/scanner/',
                startTime: parseInt(sessionStorage.getItem('activeScanStartTime') || '0', 10) || Date.now()
            };
            _save(registry);
        }
    }

    _migrateLegacyScanStorage();

    // Start polling if processes exist on page load (e.g. after navigation)
    if (isAnyProcessRunning()) {
        _startPolling();
    }

    /* ── Shared UI initialisation ────────────────────────────────── */

    var TOOL_ICONS = {
        'Scanner': '🔍',
        'SQL Attacker': '💉',
        'Discover': '🎯',
        'Manipulator': '🔧',
        'Bypasser': '🚧',
        'Spider': '🕷️'
    };

    function _getIcon(toolName) {
        return TOOL_ICONS[toolName] || '⚙️';
    }

    /**
     * Initialise the active-process notification bar and sidebar nav-interception
     * dialog. Both base templates call this once — keeping the logic in one place.
     *
     * Expected DOM elements (IDs):
     *   active-scan-bar, active-scan-bar-msg, active-scan-view-btn,
     *   active-scan-cancel-btn, scan-nav-dialog, scan-nav-stay-btn,
     *   scan-nav-continue-btn, sidebar
     */
    function initUI() {
        /* ── Active-process bar ─────────────────────────────────── */
        var bar     = document.getElementById('active-scan-bar');
        var barMsg  = document.getElementById('active-scan-bar-msg');
        var viewBtn = document.getElementById('active-scan-view-btn');
        var cancelBtn = document.getElementById('active-scan-cancel-btn');

        if (bar) {
            function refreshBar() {
                var processes = getActiveProcesses();
                if (processes.length === 0) {
                    bar.style.display = 'none';
                    return;
                }
                bar.style.display = 'flex';
                var first = processes[0];
                if (barMsg) {
                    barMsg.textContent = _getIcon(first.toolName) + ' ' + first.toolName + ' is running...';
                }
                if (viewBtn) {
                    viewBtn.href = first.viewUrl || '#';
                }
                if (cancelBtn) {
                    cancelBtn.dataset.toolName = first.toolName;
                    cancelBtn.dataset.cancelEndpoint = first.cancelEndpoint || '';
                }
            }

            refreshBar();

            document.addEventListener('megido:process-registered',   refreshBar);
            document.addEventListener('megido:process-unregistered', refreshBar);

            document.addEventListener('megido:process-completed', function(e) {
                if (window.MegidoToast) {
                    var detail    = e.detail || {};
                    var data      = detail.data || {};
                    var vulnCount = (data.vulnerabilities || []).length;
                    window.MegidoToast.success(
                        (detail.toolName || 'Process') + ' completed!' +
                        (vulnCount > 0 ? ' Found ' + vulnCount + ' vulnerabilities.' : '')
                    );
                }
                refreshBar();
            });

            document.addEventListener('megido:process-failed', function(e) {
                if (window.MegidoToast) {
                    var detail    = e.detail || {};
                    var data      = detail.data || {};
                    var vulnCount = (data.vulnerabilities || []).length;
                    window.MegidoToast.error(
                        (detail.toolName || 'Process') + ' failed.' +
                        (vulnCount > 0 ? ' ' + vulnCount + ' result(s) found.' : '')
                    );
                }
                refreshBar();
            });

            if (cancelBtn) {
                cancelBtn.addEventListener('click', function() {
                    var toolName       = cancelBtn.dataset.toolName;
                    var cancelEndpoint = cancelBtn.dataset.cancelEndpoint;
                    unregisterProcess(toolName);
                    // Legacy cleanup
                    sessionStorage.removeItem('activeScanId');
                    sessionStorage.removeItem('activeScanStartTime');
                    bar.style.display = 'none';
                    if (cancelEndpoint) {
                        var csrf = (function() {
                            var el = document.querySelector('[name=csrfmiddlewaretoken]');
                            if (el) return el.value;
                            var m = document.cookie.match(/csrftoken=([^;]+)/);
                            return m ? m[1] : '';
                        })();
                        fetch(cancelEndpoint, {
                            method: 'POST',
                            credentials: 'same-origin',
                            headers: { 'X-CSRFToken': csrf, 'Content-Type': 'application/json' }
                        }).catch(function() {});
                    }
                });
            }
        }

        /* ── Sidebar nav interception ───────────────────────────── */
        var dialog     = document.getElementById('scan-nav-dialog');
        var stayBtn    = document.getElementById('scan-nav-stay-btn');
        var continueBtn = document.getElementById('scan-nav-continue-btn');

        if (dialog) {
            var pendingNavUrl = null;

            function showDialog(url) {
                pendingNavUrl = url;
                dialog.style.display = 'flex';
                if (stayBtn) stayBtn.focus();
            }

            function hideDialog() {
                dialog.style.display = 'none';
                pendingNavUrl = null;
            }

            if (stayBtn)    stayBtn.addEventListener('click', function() { hideDialog(); });
            if (continueBtn) {
                continueBtn.addEventListener('click', function() {
                    var url = pendingNavUrl;
                    hideDialog();
                    if (url) window.location.href = url;
                });
            }

            var sidebar = document.getElementById('sidebar');
            if (sidebar) {
                sidebar.addEventListener('click', function(e) {
                    if (!isAnyProcessRunning()) return;
                    var link = e.target.closest('a[href]');
                    if (!link) return;
                    var href = link.getAttribute('href');
                    if (!href || href.startsWith('#')) return;
                    // Don't intercept if the destination is within the same tool section
                    // as an active process's viewUrl (avoids friction within a single tool).
                    var processes = getActiveProcesses();
                    for (var i = 0; i < processes.length; i++) {
                        var vUrl = processes[i].viewUrl;
                        if (vUrl && href.startsWith(vUrl) &&
                            window.location.pathname.startsWith(vUrl)) {
                            return;
                        }
                    }
                    e.preventDefault();
                    showDialog(href);
                });
            }

            dialog.addEventListener('click', function(e) {
                if (e.target === dialog) hideDialog();
            });
        }
    }

    /* ── Expose ──────────────────────────────────────────────────── */

    global.MegidoProcessTracker = {
        registerProcess: registerProcess,
        unregisterProcess: unregisterProcess,
        getActiveProcesses: getActiveProcesses,
        isAnyProcessRunning: isAnyProcessRunning,
        getProcessForTool: getProcessForTool,
        initUI: initUI
    };

}(window));
