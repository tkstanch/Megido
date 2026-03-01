/**
 * Megido Security - Scanner Dashboard Polling
 * Handles scan status polling and result updates
 * Version: 1.0
 */

(function(window) {
    'use strict';
    
    // Configuration
    const POLL_INTERVAL_MS = 2000; // Poll every 2 seconds
    const MAX_POLL_ATTEMPTS = 1800; // 1 hour worth of attempts (1800 * 2 seconds)
    const MAX_CONSECUTIVE_FAILURES = 5; // Show error after 5 consecutive failures
    const INITIAL_DELAY_MS = 2000; // Initial delay before first poll
    
    // State
    let pollIntervalId = null;
    let pollAttemptCount = 0;
    let consecutiveFailures = 0;
    let currentScanId = null;
    let scanCompleted = false;
    
    /**
     * Start polling for scan results
     * @param {number} scanId - The scan ID to poll for
     * @param {Function} onProgress - Callback for progress updates
     * @param {Function} onComplete - Callback when scan completes
     * @param {Function} onError - Callback for errors
     */
    function startPolling(scanId, onProgress, onComplete, onError) {
        // Validate parameters
        if (!scanId) {
            console.error('Scanner Dashboard: scanId is required');
            if (onError) onError('Invalid scan ID');
            return;
        }
        
        // Reset state
        stopPolling();
        currentScanId = scanId;
        pollAttemptCount = 0;
        consecutiveFailures = 0;
        scanCompleted = false;
        
        // Log polling start
        console.log(`Scanner Dashboard: Starting polling for scan ${scanId}`);
        
        // Start polling with initial delay
        setTimeout(() => {
            pollScanStatus(onProgress, onComplete, onError);
            
            // Set up interval for subsequent polls
            pollIntervalId = setInterval(() => {
                if (!scanCompleted) {
                    pollScanStatus(onProgress, onComplete, onError);
                } else {
                    stopPolling();
                }
            }, POLL_INTERVAL_MS);
        }, INITIAL_DELAY_MS);
    }
    
    /**
     * Poll scan status once
     * @param {Function} onProgress - Callback for progress updates
     * @param {Function} onComplete - Callback when scan completes
     * @param {Function} onError - Callback for errors
     */
    async function pollScanStatus(onProgress, onComplete, onError) {
        try {
            // Check attempt limit
            if (pollAttemptCount >= MAX_POLL_ATTEMPTS) {
                console.warn('Scanner Dashboard: Max poll attempts reached');
                stopPolling();
                if (onError) {
                    onError('Scan is taking longer than expected. Please refresh the page to check status.');
                }
                return;
            }
            
            pollAttemptCount++;
            
            // Fetch scan results
            const response = await fetch(`/scanner/api/scans/${currentScanId}/results/`);
            
            // Check response status
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const data = await response.json();
            
            // Reset consecutive failures on successful fetch
            consecutiveFailures = 0;
            
            // Log status
            console.log(`Scanner Dashboard: Scan ${currentScanId} status: ${data.status}`);
            
            // Check scan status
            if (data.status === 'completed') {
                scanCompleted = true;
                stopPolling();
                
                const vulnCount = data.vulnerabilities?.length || 0;
                console.log(`Scanner Dashboard: Scan ${currentScanId} completed with ${vulnCount} vulnerabilities`);
                
                if (onComplete) {
                    onComplete(data);
                }
            } else if (data.status === 'failed') {
                scanCompleted = true;
                stopPolling();

                const vulnCount = data.vulnerabilities?.length || 0;
                if (vulnCount > 0) {
                    console.warn(
                        `Scanner Dashboard: Scan ${currentScanId} failed but has ${vulnCount} partial result(s)`
                    );
                    if (onComplete) {
                        onComplete(data);
                    }
                } else {
                    console.error(`Scanner Dashboard: Scan ${currentScanId} failed with no results`);
                    if (onError) {
                        onError('Scan failed. Please try again.');
                    }
                }
            } else if (data.status === 'running' || data.status === 'pending') {
                // Scan is still in progress
                if (onProgress) {
                    onProgress(data);
                }
            }
            
        } catch (error) {
            console.error('Scanner Dashboard: Poll error:', error);
            
            // Increment consecutive failures
            consecutiveFailures++;
            
            // NOTE: Error Handling Strategy
            // ================================
            // We distinguish between different types of errors:
            // 1. 404 errors for favicon.ico or other static assets - NOT scan API errors, ignore
            // 2. Temporary network failures (e.g., DNS hiccups) - retry automatically
            // 3. Persistent API failures - show error only after MAX_CONSECUTIVE_FAILURES
            // 
            // This prevents false "NetworkError" messages from unrelated browser requests
            // and provides a better user experience by not showing transient errors.
            //
            // Debugging Tips:
            // - Check browser Network tab for actual API requests to /scanner/api/scans/<id>/results/
            // - Look for HTTP status codes (200 = success, 404 = not found, 500 = server error)
            // - Check Console tab for detailed error messages
            // - Verify Celery worker is running if scans stuck in 'pending' status
            
            // Only show error to user after multiple consecutive failures
            if (consecutiveFailures >= MAX_CONSECUTIVE_FAILURES) {
                if (onError) {
                    onError(`Network error: ${error.message}`);
                }
            }
        }
    }
    
    /**
     * Stop polling
     */
    function stopPolling() {
        if (pollIntervalId) {
            clearInterval(pollIntervalId);
            pollIntervalId = null;
            console.log('Scanner Dashboard: Polling stopped');
        }
    }
    
    /**
     * Check if polling is active
     * @returns {boolean} True if polling is active
     */
    function isPolling() {
        return pollIntervalId !== null;
    }
    
    /**
     * Get current scan ID
     * @returns {number|null} Current scan ID or null
     */
    function getCurrentScanId() {
        return currentScanId;
    }
    
    // Expose public API
    window.ScannerDashboard = {
        startPolling: startPolling,
        stopPolling: stopPolling,
        isPolling: isPolling,
        getCurrentScanId: getCurrentScanId
    };
    
    console.log('✅ Scanner Dashboard Polling System initialized');
    
})(window);
