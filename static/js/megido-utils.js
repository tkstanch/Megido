/**
 * Megido Security - Core Utilities
 * Secure helper functions for client-side operations
 * Version: 2.0
 */

(function(window) {
    'use strict';
    
    /**
     * Security Utilities
     */
    const SecurityUtils = {
        /**
         * Escape HTML to prevent XSS
         * @param {string} text - Text to escape
         * @returns {string} Escaped text
         */
        escapeHtml(text) {
            if (typeof text !== 'string') return '';
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        },
        
        /**
         * Sanitize input value (remove potentially dangerous characters)
         * @param {string} value - Input value to sanitize
         * @returns {string} Sanitized value
         */
        sanitizeInput(value) {
            if (typeof value !== 'string') return '';
            // Remove null bytes and control characters except whitespace
            return value.replace(/[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F]/g, '');
        },
        
        /**
         * Get CSRF token from cookies
         * @returns {string|null} CSRF token or null
         */
        getCsrfToken() {
            const cookies = document.cookie.split(';');
            for (let i = 0; i < cookies.length; i++) {
                const cookie = cookies[i].trim();
                if (cookie.startsWith('csrftoken=')) {
                    return decodeURIComponent(cookie.substring(10));
                }
            }
            return null;
        },
        
        /**
         * Validate severity value (only allow known values)
         * @param {string} severity - Severity to validate
         * @returns {string} Valid severity value
         */
        validateSeverity(severity) {
            const validSeverities = ['low', 'medium', 'high', 'critical'];
            return validSeverities.includes(severity) ? severity : 'low';
        },
        
        /**
         * Validate URL (basic validation)
         * @param {string} url - URL to validate
         * @returns {boolean} True if valid
         */
        isValidUrl(url) {
            try {
                new URL(url);
                return true;
            } catch {
                return false;
            }
        }
    };
    
    /**
     * DOM Utilities
     */
    const DOMUtils = {
        /**
         * Safely set text content of an element
         * @param {HTMLElement} element - Target element
         * @param {string} text - Text to set
         */
        setText(element, text) {
            if (!element) return;
            element.textContent = text;
        },
        
        /**
         * Safely create element with text content
         * @param {string} tag - Element tag name
         * @param {string} text - Text content
         * @param {string} [className] - Optional class name
         * @returns {HTMLElement} Created element
         */
        createElement(tag, text, className) {
            const element = document.createElement(tag);
            if (text) element.textContent = text;
            if (className) element.className = className;
            return element;
        },
        
        /**
         * Add event listener safely (prevents inline event handlers)
         * @param {HTMLElement} element - Target element
         * @param {string} event - Event name
         * @param {Function} handler - Event handler
         * @param {Object} [options] - Event listener options
         */
        addListener(element, event, handler, options) {
            if (!element || typeof handler !== 'function') return;
            element.addEventListener(event, handler, options);
        },
        
        /**
         * Show/hide element
         * @param {HTMLElement} element - Target element
         * @param {boolean} show - True to show, false to hide
         */
        toggleVisibility(element, show) {
            if (!element) return;
            if (show) {
                element.classList.remove('hidden');
            } else {
                element.classList.add('hidden');
            }
        }
    };
    
    /**
     * Search and Filter Utilities
     */
    const SearchUtils = {
        /**
         * Filter items based on search query
         * @param {Array} items - Items to filter
         * @param {string} query - Search query
         * @param {Function} textExtractor - Function to extract searchable text from item
         * @returns {Array} Filtered items
         */
        filterItems(items, query, textExtractor) {
            if (!query || !query.trim()) return items;
            
            const searchQuery = query.toLowerCase().trim();
            return items.filter(item => {
                const text = textExtractor(item).toLowerCase();
                return text.includes(searchQuery);
            });
        },
        
        /**
         * Highlight search query in text (returns text with <mark> tags)
         * WARNING: Only use with escaped text, then set as innerHTML
         * @param {string} text - Text to highlight (must be pre-escaped)
         * @param {string} query - Query to highlight
         * @returns {string} Text with <mark> tags
         */
        highlightQuery(text, query) {
            if (!query || !query.trim()) return text;
            
            const escapedQuery = query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            const regex = new RegExp(`(${escapedQuery})`, 'gi');
            return text.replace(regex, '<mark>$1</mark>');
        },
        
        /**
         * Debounce function calls
         * @param {Function} func - Function to debounce
         * @param {number} wait - Debounce delay in ms
         * @returns {Function} Debounced function
         */
        debounce(func, wait) {
            let timeout;
            return function executedFunction(...args) {
                const later = () => {
                    clearTimeout(timeout);
                    func(...args);
                };
                clearTimeout(timeout);
                timeout = setTimeout(later, wait);
            };
        }
    };
    
    /**
     * HTTP Utilities
     */
    const HTTPUtils = {
        /**
         * Perform a secure fetch request with CSRF token
         * @param {string} url - Request URL
         * @param {Object} [options] - Fetch options
         * @returns {Promise<Response>} Fetch response
         */
        async secureFetch(url, options = {}) {
            const csrfToken = SecurityUtils.getCsrfToken();
            
            const defaultOptions = {
                headers: {
                    'X-CSRFToken': csrfToken,
                    ...options.headers
                },
                credentials: 'same-origin'
            };
            
            return fetch(url, { ...defaultOptions, ...options });
        },
        
        /**
         * Parse JSON response safely
         * @param {Response} response - Fetch response
         * @returns {Promise<Object>} Parsed JSON or error
         */
        async parseJSON(response) {
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            try {
                return await response.json();
            } catch (error) {
                throw new Error('Invalid JSON response');
            }
        },
        
        /**
         * POST JSON data securely
         * @param {string} url - Request URL
         * @param {Object} data - Data to send
         * @returns {Promise<Object>} Response data
         */
        async postJSON(url, data) {
            const response = await this.secureFetch(url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(data)
            });
            return this.parseJSON(response);
        }
    };
    
    /**
     * Storage Utilities (localStorage/sessionStorage)
     */
    const StorageUtils = {
        /**
         * Check if storage is available
         * @param {string} type - 'local' or 'session'
         * @returns {boolean} True if available
         */
        isAvailable(type) {
            const storage = type === 'local' ? window.localStorage : window.sessionStorage;
            try {
                const test = '__storage_test__';
                storage.setItem(test, test);
                storage.removeItem(test);
                return true;
            } catch {
                return false;
            }
        },
        
        /**
         * Get item from storage
         * @param {string} key - Storage key
         * @param {string} [type='local'] - 'local' or 'session'
         * @returns {any} Parsed value or null
         */
        get(key, type = 'local') {
            if (!this.isAvailable(type)) return null;
            
            const storage = type === 'local' ? window.localStorage : window.sessionStorage;
            try {
                const item = storage.getItem(key);
                return item ? JSON.parse(item) : null;
            } catch {
                return null;
            }
        },
        
        /**
         * Set item in storage
         * @param {string} key - Storage key
         * @param {any} value - Value to store
         * @param {string} [type='local'] - 'local' or 'session'
         * @returns {boolean} True if successful
         */
        set(key, value, type = 'local') {
            if (!this.isAvailable(type)) return false;
            
            const storage = type === 'local' ? window.localStorage : window.sessionStorage;
            try {
                storage.setItem(key, JSON.stringify(value));
                return true;
            } catch {
                return false;
            }
        },
        
        /**
         * Remove item from storage
         * @param {string} key - Storage key
         * @param {string} [type='local'] - 'local' or 'session'
         */
        remove(key, type = 'local') {
            if (!this.isAvailable(type)) return;
            
            const storage = type === 'local' ? window.localStorage : window.sessionStorage;
            storage.removeItem(key);
        }
    };
    
    /**
     * Format Utilities
     */
    const FormatUtils = {
        /**
         * Format date to readable string
         * @param {Date|string} date - Date to format
         * @returns {string} Formatted date
         */
        formatDate(date) {
            const d = new Date(date);
            if (isNaN(d.getTime())) return 'Invalid Date';
            
            return d.toLocaleDateString('en-US', {
                year: 'numeric',
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit'
            });
        },
        
        /**
         * Format number with thousand separators
         * @param {number} num - Number to format
         * @returns {string} Formatted number
         */
        formatNumber(num) {
            return new Intl.NumberFormat('en-US').format(num);
        },
        
        /**
         * Truncate text to specified length
         * @param {string} text - Text to truncate
         * @param {number} length - Max length
         * @param {string} [suffix='...'] - Suffix to add
         * @returns {string} Truncated text
         */
        truncate(text, length, suffix = '...') {
            if (!text || text.length <= length) return text;
            return text.substring(0, length) + suffix;
        },
        
        /**
         * Get severity color class
         * @param {string} severity - Severity level
         * @returns {string} CSS class name
         */
        getSeverityClass(severity) {
            const validated = SecurityUtils.validateSeverity(severity);
            return `badge-${validated}`;
        }
    };
    
    /**
     * Theme Management
     */
    const ThemeManager = {
        /**
         * Get current theme
         * @returns {string} 'light' or 'dark'
         */
        getTheme() {
            return document.documentElement.getAttribute('data-theme') || 'light';
        },
        
        /**
         * Set theme
         * @param {string} theme - 'light' or 'dark'
         */
        setTheme(theme) {
            const validTheme = theme === 'dark' ? 'dark' : 'light';
            document.documentElement.setAttribute('data-theme', validTheme);
            StorageUtils.set('theme', validTheme);
        },
        
        /**
         * Toggle theme
         */
        toggleTheme() {
            const currentTheme = this.getTheme();
            this.setTheme(currentTheme === 'dark' ? 'light' : 'dark');
        },
        
        /**
         * Initialize theme from storage
         */
        initTheme() {
            const savedTheme = StorageUtils.get('theme');
            if (savedTheme) {
                this.setTheme(savedTheme);
            } else {
                // Check system preference
                const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
                this.setTheme(prefersDark ? 'dark' : 'light');
            }
        }
    };
    
    // Initialize theme on load
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
            ThemeManager.initTheme();
        });
    } else {
        ThemeManager.initTheme();
    }
    
    // Expose public API
    window.MegidoUtils = {
        Security: SecurityUtils,
        DOM: DOMUtils,
        Search: SearchUtils,
        HTTP: HTTPUtils,
        Storage: StorageUtils,
        Format: FormatUtils,
        Theme: ThemeManager
    };
    
    // Log initialization
    console.log('✅ Megido Utilities initialized');
    
})(window);
