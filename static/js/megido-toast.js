/**
 * Megido Security - Toast Notification System
 * Secure, accessible toast notifications with XSS prevention
 * Version: 2.0
 */

(function(window) {
    'use strict';
    
    // Toast container element
    let toastContainer = null;
    
    /**
     * Initialize toast container
     */
    function initToastContainer() {
        if (toastContainer) return;
        
        toastContainer = document.createElement('div');
        toastContainer.id = 'megido-toast-container';
        toastContainer.setAttribute('aria-live', 'polite');
        toastContainer.setAttribute('aria-atomic', 'true');
        toastContainer.style.cssText = `
            position: fixed;
            top: 1.5rem;
            right: 1.5rem;
            z-index: 10000;
            max-width: 420px;
            pointer-events: none;
        `;
        document.body.appendChild(toastContainer);
    }
    
    /**
     * Escape HTML to prevent XSS
     * @param {string} text - Text to escape
     * @returns {string} Escaped text
     */
    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    
    /**
     * Create a toast notification
     * @param {Object} options - Toast configuration
     * @param {string} options.message - Message to display (will be escaped)
     * @param {string} [options.type='info'] - Toast type: success, error, warning, info
     * @param {number} [options.duration=5000] - Duration in ms (0 for no auto-dismiss)
     * @param {string} [options.icon] - Icon to display (will be escaped)
     * @param {boolean} [options.dismissible=true] - Show dismiss button
     */
    function showToast(options) {
        if (!options || !options.message) {
            console.error('Toast message is required');
            return;
        }
        
        initToastContainer();
        
        const {
            message,
            type = 'info',
            duration = 5000,
            icon,
            dismissible = true
        } = options;
        
        // Validate type
        const validTypes = ['success', 'error', 'warning', 'info'];
        const toastType = validTypes.includes(type) ? type : 'info';
        
        // Create toast element
        const toast = document.createElement('div');
        toast.className = 'megido-toast';
        toast.setAttribute('role', 'alert');
        toast.style.cssText = `
            background: white;
            border-radius: 0.5rem;
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
            padding: 1rem;
            margin-bottom: 0.75rem;
            display: flex;
            align-items: flex-start;
            gap: 0.75rem;
            pointer-events: auto;
            animation: slideInRight 0.3s ease-out;
            min-width: 300px;
            border-left: 4px solid;
        `;
        
        // Set border color based on type
        const borderColors = {
            success: '#10b981',
            error: '#ef4444',
            warning: '#f59e0b',
            info: '#3b82f6'
        };
        toast.style.borderLeftColor = borderColors[toastType];
        
        // Icon element
        let iconHtml = '';
        if (icon) {
            const iconElement = document.createElement('div');
            iconElement.className = 'toast-icon';
            iconElement.style.cssText = `
                font-size: 1.25rem;
                flex-shrink: 0;
                margin-top: 0.125rem;
            `;
            // Set default icons by type if no custom icon provided
            const defaultIcons = {
                success: '✅',
                error: '❌',
                warning: '⚠️',
                info: 'ℹ️'
            };
            iconElement.textContent = icon === true ? defaultIcons[toastType] : icon;
            toast.appendChild(iconElement);
        }
        
        // Message content
        const contentElement = document.createElement('div');
        contentElement.className = 'toast-content';
        contentElement.style.cssText = `
            flex: 1;
            font-size: 0.9375rem;
            line-height: 1.5;
            color: #1f2937;
        `;
        contentElement.textContent = message; // Safe: uses textContent
        toast.appendChild(contentElement);
        
        // Dismiss button
        if (dismissible) {
            const dismissBtn = document.createElement('button');
            dismissBtn.className = 'toast-dismiss';
            dismissBtn.setAttribute('aria-label', 'Dismiss notification');
            dismissBtn.style.cssText = `
                background: none;
                border: none;
                color: #6b7280;
                cursor: pointer;
                font-size: 1.25rem;
                padding: 0;
                line-height: 1;
                flex-shrink: 0;
                margin-top: 0.125rem;
            `;
            dismissBtn.textContent = '×';
            dismissBtn.addEventListener('click', () => {
                dismissToast(toast);
            });
            toast.appendChild(dismissBtn);
        }
        
        // Add to container
        toastContainer.appendChild(toast);
        
        // Auto-dismiss after duration
        if (duration > 0) {
            setTimeout(() => {
                dismissToast(toast);
            }, duration);
        }
        
        return toast;
    }
    
    /**
     * Dismiss a toast notification
     * @param {HTMLElement} toast - Toast element to dismiss
     */
    function dismissToast(toast) {
        if (!toast || !toast.parentNode) return;
        
        toast.style.animation = 'slideOutRight 0.3s ease-out';
        toast.addEventListener('animationend', () => {
            if (toast.parentNode) {
                toast.parentNode.removeChild(toast);
            }
        });
    }
    
    /**
     * Show success toast
     * @param {string} message - Message to display
     * @param {Object} [options] - Additional options
     */
    function showSuccess(message, options = {}) {
        return showToast({
            message,
            type: 'success',
            icon: true,
            ...options
        });
    }
    
    /**
     * Show error toast
     * @param {string} message - Message to display
     * @param {Object} [options] - Additional options
     */
    function showError(message, options = {}) {
        return showToast({
            message,
            type: 'error',
            icon: true,
            duration: 7000, // Errors stay longer
            ...options
        });
    }
    
    /**
     * Show warning toast
     * @param {string} message - Message to display
     * @param {Object} [options] - Additional options
     */
    function showWarning(message, options = {}) {
        return showToast({
            message,
            type: 'warning',
            icon: true,
            ...options
        });
    }
    
    /**
     * Show info toast
     * @param {string} message - Message to display
     * @param {Object} [options] - Additional options
     */
    function showInfo(message, options = {}) {
        return showToast({
            message,
            type: 'info',
            icon: true,
            ...options
        });
    }
    
    /**
     * Clear all toasts
     */
    function clearAll() {
        if (!toastContainer) return;
        while (toastContainer.firstChild) {
            toastContainer.removeChild(toastContainer.firstChild);
        }
    }
    
    // Add animation keyframes
    if (!document.getElementById('megido-toast-animations')) {
        const style = document.createElement('style');
        style.id = 'megido-toast-animations';
        style.textContent = `
            @keyframes slideInRight {
                from {
                    transform: translateX(100%);
                    opacity: 0;
                }
                to {
                    transform: translateX(0);
                    opacity: 1;
                }
            }
            @keyframes slideOutRight {
                from {
                    transform: translateX(0);
                    opacity: 1;
                }
                to {
                    transform: translateX(100%);
                    opacity: 0;
                }
            }
            .megido-toast:hover .toast-dismiss {
                color: #1f2937;
            }
            [data-theme="dark"] .megido-toast {
                background: #1f2937;
                border-left-color: inherit;
            }
            [data-theme="dark"] .megido-toast .toast-content {
                color: #f9fafb;
            }
            [data-theme="dark"] .megido-toast .toast-dismiss {
                color: #d1d5db;
            }
            [data-theme="dark"] .megido-toast:hover .toast-dismiss {
                color: #f9fafb;
            }
        `;
        document.head.appendChild(style);
    }
    
    // Expose public API
    window.MegidoToast = {
        show: showToast,
        success: showSuccess,
        error: showError,
        warning: showWarning,
        info: showInfo,
        dismiss: dismissToast,
        clearAll: clearAll
    };
    
    // Log initialization
    console.log('✅ Megido Toast System initialized');
    
})(window);
