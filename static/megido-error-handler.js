/**
 * Megido Security - Centralized Error Handler
 * Provides consistent error handling for network requests across all dashboards
 */

(function(window) {
    'use strict';
    
    // Configuration
    const MegidoErrorHandler = {
        debugMode: false,  // Can be set from Django context
        retryConfig: {
            maxRetries: 3,
            initialDelay: 1000,
            maxDelay: 30000,
            backoffMultiplier: 2,
            retryableStatuses: [408, 429, 500, 502, 503, 504],
            retryableErrors: ['NetworkError', 'TypeError', 'TimeoutError']
        }
    };
    
    /**
     * Display user-facing error notification
     */
    function showErrorNotification(error, options = {}) {
        const {
            title = 'Network Error',
            actionable = true,
            retryCallback = null,
            containerId = 'megido-error-container'
        } = options;
        
        // Create or get error container
        let container = document.getElementById(containerId);
        if (!container) {
            container = document.createElement('div');
            container.id = containerId;
            container.style.cssText = `
                position: fixed;
                top: 20px;
                right: 20px;
                z-index: 10000;
                max-width: 500px;
            `;
            document.body.appendChild(container);
        }
        
        // Create error card
        const errorCard = document.createElement('div');
        errorCard.style.cssText = `
            background: #fff;
            border-left: 5px solid #dc3545;
            border-radius: 5px;
            padding: 20px;
            margin-bottom: 10px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
            animation: slideIn 0.3s ease-out;
        `;
        
        // Add animation keyframe
        if (!document.getElementById('megido-error-animations')) {
            const style = document.createElement('style');
            style.id = 'megido-error-animations';
            style.textContent = `
                @keyframes slideIn {
                    from { transform: translateX(100%); opacity: 0; }
                    to { transform: translateX(0); opacity: 1; }
                }
                @keyframes slideOut {
                    from { transform: translateX(0); opacity: 1; }
                    to { transform: translateX(100%); opacity: 0; }
                }
            `;
            document.head.appendChild(style);
        }
        
        // Build error message
        let errorMessage = `<strong>❌ ${title}</strong><br>`;
        errorMessage += `<div style="margin-top: 10px; color: #666;">`;
        errorMessage += error.message || 'An unknown error occurred.';
        errorMessage += `</div>`;
        
        // Add actionable advice
        if (actionable) {
            errorMessage += `<div style="margin-top: 15px; padding: 10px; background: #fff3cd; border-radius: 3px; font-size: 0.9em;">`;
            errorMessage += `<strong>💡 What to check:</strong><br>`;
            
            if (error.isNetworkError) {
                errorMessage += `• Is the backend server running?<br>`;
                errorMessage += `• Check network connectivity<br>`;
                errorMessage += `• Verify firewall settings<br>`;
            } else if (error.status >= 500) {
                errorMessage += `• Backend server may be experiencing issues<br>`;
                errorMessage += `• Check server logs for details<br>`;
            } else if (error.status === 404) {
                errorMessage += `• API endpoint may be misconfigured<br>`;
                errorMessage += `• Verify the API URL is correct<br>`;
            } else if (error.status === 403 || error.status === 401) {
                errorMessage += `• Authentication may have expired<br>`;
                errorMessage += `• Check permissions for this resource<br>`;
            } else if (error.isCORS) {
                errorMessage += `• CORS policy may be blocking the request<br>`;
                errorMessage += `• Check backend CORS configuration<br>`;
            }
            errorMessage += `</div>`;
        }
        
        // Add debug info if enabled
        if (MegidoErrorHandler.debugMode && error.debugInfo) {
            errorMessage += `<details style="margin-top: 15px; font-size: 0.85em; color: #666;">`;
            errorMessage += `<summary style="cursor: pointer; font-weight: bold;">🔍 Debug Information</summary>`;
            errorMessage += `<div style="margin-top: 10px; padding: 10px; background: #f8f9fa; border-radius: 3px; font-family: monospace; white-space: pre-wrap; max-height: 200px; overflow-y: auto;">`;
            errorMessage += `URL: ${error.debugInfo.url || 'N/A'}\n`;
            errorMessage += `Method: ${error.debugInfo.method || 'N/A'}\n`;
            errorMessage += `Status: ${error.status || 'N/A'}\n`;
            errorMessage += `Error Type: ${error.name || 'N/A'}\n`;
            if (error.debugInfo.stack) {
                errorMessage += `\nStack Trace:\n${error.debugInfo.stack}`;
            }
            errorMessage += `</div></details>`;
        }
        
        errorCard.innerHTML = errorMessage;
        
        // Add buttons
        const buttonContainer = document.createElement('div');
        buttonContainer.style.cssText = 'margin-top: 15px; display: flex; gap: 10px;';
        
        if (retryCallback) {
            const retryBtn = document.createElement('button');
            retryBtn.textContent = '🔄 Retry';
            retryBtn.style.cssText = `
                background: #007bff;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                cursor: pointer;
                font-size: 0.9em;
            `;
            retryBtn.onmouseover = () => retryBtn.style.opacity = '0.9';
            retryBtn.onmouseout = () => retryBtn.style.opacity = '1';
            retryBtn.onclick = () => {
                removeErrorCard(errorCard);
                retryCallback();
            };
            buttonContainer.appendChild(retryBtn);
        }
        
        const dismissBtn = document.createElement('button');
        dismissBtn.textContent = '✕ Dismiss';
        dismissBtn.style.cssText = `
            background: #6c757d;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.9em;
        `;
        dismissBtn.onmouseover = () => dismissBtn.style.opacity = '0.9';
        dismissBtn.onmouseout = () => dismissBtn.style.opacity = '1';
        dismissBtn.onclick = () => removeErrorCard(errorCard);
        buttonContainer.appendChild(dismissBtn);
        
        errorCard.appendChild(buttonContainer);
        container.appendChild(errorCard);
        
        // Auto-dismiss after 10 seconds if no retry button
        if (!retryCallback) {
            setTimeout(() => removeErrorCard(errorCard), 10000);
        }
    }
    
    function removeErrorCard(card) {
        card.style.animation = 'slideOut 0.3s ease-out';
        setTimeout(() => {
            if (card.parentNode) {
                card.parentNode.removeChild(card);
            }
        }, 300);
    }
    
    /**
     * Enhanced fetch with retry logic and better error handling
     */
    async function fetchWithRetry(url, options = {}) {
        const {
            retries = MegidoErrorHandler.retryConfig.maxRetries,
            onRetry = null,
            errorContext = 'Request',
            ...fetchOptions
        } = options;
        
        let lastError;
        let delay = MegidoErrorHandler.retryConfig.initialDelay;
        
        for (let attempt = 0; attempt <= retries; attempt++) {
            try {
                const controller = new AbortController();
                const timeoutId = setTimeout(
                    () => controller.abort(), 
                    fetchOptions.timeout || 30000
                );
                
                const response = await fetch(url, {
                    ...fetchOptions,
                    signal: controller.signal
                });
                
                clearTimeout(timeoutId);
                
                // Success
                if (response.ok) {
                    return response;
                }
                
                // Non-retryable client errors (except 429 Too Many Requests)
                if (response.status >= 400 && response.status < 500 && response.status !== 429) {
                    throw createError({
                        message: `${errorContext} failed: HTTP ${response.status}`,
                        status: response.status,
                        isRetryable: false,
                        debugInfo: { url, method: fetchOptions.method || 'GET' }
                    });
                }
                
                // Retryable server errors
                if (MegidoErrorHandler.retryConfig.retryableStatuses.includes(response.status)) {
                    throw createError({
                        message: `${errorContext} failed: HTTP ${response.status}`,
                        status: response.status,
                        isRetryable: true,
                        debugInfo: { url, method: fetchOptions.method || 'GET' }
                    });
                }
                
                // Other errors
                throw createError({
                    message: `${errorContext} failed: HTTP ${response.status}`,
                    status: response.status,
                    isRetryable: false,
                    debugInfo: { url, method: fetchOptions.method || 'GET' }
                });
                
            } catch (error) {
                lastError = error;
                
                // Handle abort/timeout
                if (error.name === 'AbortError') {
                    lastError = createError({
                        message: `${errorContext} timed out`,
                        isNetworkError: true,
                        isRetryable: true,
                        name: 'TimeoutError',
                        debugInfo: { url, method: fetchOptions.method || 'GET' }
                    });
                }
                
                // Handle network errors
                if (error instanceof TypeError && error.message.includes('fetch')) {
                    lastError = createError({
                        message: 'Network error: Unable to reach the server. Please check your connection and that the backend is running.',
                        isNetworkError: true,
                        isRetryable: true,
                        name: 'NetworkError',
                        debugInfo: { url, method: fetchOptions.method || 'GET', stack: error.stack }
                    });
                }
                
                // Check if error is retryable
                if (attempt < retries && lastError.isRetryable !== false) {
                    if (onRetry) {
                        onRetry(attempt + 1, retries + 1, delay);
                    }
                    await sleep(delay);
                    delay = Math.min(
                        delay * MegidoErrorHandler.retryConfig.backoffMultiplier,
                        MegidoErrorHandler.retryConfig.maxDelay
                    );
                    continue;
                }
                
                throw lastError;
            }
        }
        
        throw lastError;
    }
    
    /**
     * Create standardized error object
     */
    function createError(props) {
        const error = new Error(props.message || 'Unknown error');
        Object.assign(error, props);
        return error;
    }
    
    /**
     * Sleep utility for retry delays
     */
    function sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
    
    /**
     * Wrapper for easier use: fetch with automatic error notification
     */
    async function fetchWithNotification(url, options = {}) {
        const {
            showNotification = true,
            notificationOptions = {},
            ...fetchOptions
        } = options;
        
        try {
            return await fetchWithRetry(url, fetchOptions);
        } catch (error) {
            if (showNotification) {
                showErrorNotification(error, {
                    retryCallback: notificationOptions.retryCallback,
                    ...notificationOptions
                });
            }
            throw error;
        }
    }
    
    // Expose API
    window.MegidoErrorHandler = {
        config: MegidoErrorHandler,
        fetchWithRetry,
        fetchWithNotification,
        showErrorNotification,
        createError,
        setDebugMode: (enabled) => { MegidoErrorHandler.debugMode = enabled; }
    };
    
    // Log initialization
    console.log('✅ Megido Error Handler initialized');
    
})(window);
