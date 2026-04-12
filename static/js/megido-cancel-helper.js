/**
 * MegidoCancelHelper — reusable helper for registering long-running tasks with
 * MegidoProcessTracker and providing a per-tool cancel button.
 *
 * Usage (from any tool's JS, after MegidoProcessTracker has loaded):
 *
 *   MegidoCancelHelper.startTask(
 *       'Scanner',                              // toolName
 *       taskId,                                 // Celery task ID
 *       '/scanner/api/scans/' + scanId + '/results/',   // statusUrl
 *       '/scanner/api/scans/' + scanId + '/cancel/',    // cancelUrl
 *       document.getElementById('scan-controls')        // optional DOM container
 *   );
 *
 * The helper also listens for the megido:process-completed and
 * megido:process-failed events on the current tool so it can remove the
 * cancel button automatically when the task finishes.
 *
 * Public API (window.MegidoCancelHelper):
 *   startTask(toolName, taskId, statusUrl, cancelUrl, container)
 *   cancelTask(toolName, cancelUrl, btn)
 */
(function (global) {
    'use strict';

    /* ── CSRF helper ──────────────────────────────────────────────── */
    function _getCsrf() {
        var el = document.querySelector('[name=csrfmiddlewaretoken]');
        if (el) return el.value;
        var m = document.cookie.match(/csrftoken=([^;]+)/);
        return m ? m[1] : '';
    }

    /**
     * Register a task with MegidoProcessTracker and optionally insert a
     * cancel button into *container*.
     *
     * @param {string}  toolName  Human-readable name, e.g. "Scanner"
     * @param {string}  taskId    Celery task ID returned by the backend
     * @param {string}  statusUrl URL polled for { status: "running"|"completed"|... }
     * @param {string}  cancelUrl URL to POST to cancel the task
     * @param {Element} [container] Optional DOM element to insert the cancel button into
     */
    function startTask(toolName, taskId, statusUrl, cancelUrl, container) {
        if (global.MegidoProcessTracker) {
            global.MegidoProcessTracker.registerProcess(
                toolName, taskId, statusUrl, cancelUrl
            );
        }

        if (container) {
            // Remove any existing cancel button for this tool first
            var old = container.querySelector('.megido-cancel-btn[data-tool-name="' + toolName + '"]');
            if (old) old.remove();

            var btn = document.createElement('button');
            btn.className = 'btn btn-danger megido-cancel-btn';
            btn.style.cssText = 'margin-left:8px;padding:6px 14px;background:#dc3545;color:#fff;border:none;border-radius:6px;cursor:pointer;font-size:0.875rem;';
            btn.innerHTML = '&#9940; Cancel ' + toolName;
            btn.dataset.toolName = toolName;
            btn.dataset.cancelUrl = cancelUrl;
            btn.onclick = function () { cancelTask(toolName, cancelUrl, btn); };
            container.appendChild(btn);

            // Auto-remove the button when the task completes or fails
            function _onDone(e) {
                if (e.detail && e.detail.toolName === toolName) {
                    btn.remove();
                    document.removeEventListener('megido:process-completed', _onDone);
                    document.removeEventListener('megido:process-failed', _onDone);
                    document.removeEventListener('megido:process-unregistered', _onDone);
                }
            }
            document.addEventListener('megido:process-completed', _onDone);
            document.addEventListener('megido:process-failed', _onDone);
            document.addEventListener('megido:process-unregistered', _onDone);
        }
    }

    /**
     * Send a cancel request and update the UI.
     *
     * @param {string}  toolName  Tool name used when registering the process
     * @param {string}  cancelUrl URL to POST
     * @param {Element} [btn]     Optional button element to show feedback on
     */
    function cancelTask(toolName, cancelUrl, btn) {
        if (btn) {
            btn.disabled = true;
            btn.innerHTML = '&#9203; Cancelling...';
        }

        fetch(cancelUrl, {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': _getCsrf(),
            },
        })
        .then(function (resp) { return resp.json(); })
        .then(function (data) {
            if (data.success) {
                if (global.MegidoProcessTracker) {
                    global.MegidoProcessTracker.unregisterProcess(toolName);
                }
                if (global.MegidoToast) {
                    global.MegidoToast.success(toolName + ' cancelled successfully.');
                }
                if (btn) {
                    btn.innerHTML = '&#10003; Cancelled';
                    btn.style.background = '#6c757d';
                }
            } else {
                if (global.MegidoToast) {
                    global.MegidoToast.error('Cancel failed: ' + (data.error || 'Unknown error'));
                }
                if (btn) {
                    btn.disabled = false;
                    btn.innerHTML = '&#9940; Cancel ' + toolName;
                }
            }
        })
        .catch(function (err) {
            console.error('[MegidoCancelHelper] Cancel request failed:', err);
            if (global.MegidoToast) {
                global.MegidoToast.error('Cancel request failed. Please try again.');
            }
            if (btn) {
                btn.disabled = false;
                btn.innerHTML = '&#9940; Cancel ' + toolName;
            }
        });
    }

    /* ── Expose ───────────────────────────────────────────────────── */
    global.MegidoCancelHelper = {
        startTask: startTask,
        cancelTask: cancelTask,
    };

}(window));
