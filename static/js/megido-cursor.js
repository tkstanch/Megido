/**
 * Megido Advanced Cursor Effects v2.3
 * Premium cursor interactions for ultra beauty
 */

(function() {
    'use strict';
    
    class AdvancedCursor {
        constructor(options = {}) {
            this.enabled = !window.matchMedia('(prefers-reduced-motion: reduce)').matches;
            if (!this.enabled) return;
            
            this.options = {
                cursorSize: options.cursorSize || 10,
                glowSize: options.glowSize || 40,
                trailLength: options.trailLength || 10,
                ...options
            };
            
            this.cursor = null;
            this.cursorGlow = null;
            this.trail = [];
            this.mouseX = 0;
            this.mouseY = 0;
            this.targetX = 0;
            this.targetY = 0;
            
            this.init();
        }
        
        init() {
            this.createCursor();
            this.bindEvents();
            this.animate();
        }
        
        createCursor() {
            // Main cursor dot
            this.cursor = document.createElement('div');
            this.cursor.className = 'megido-cursor';
            this.cursor.style.cssText = `
                position: fixed;
                width: ${this.options.cursorSize}px;
                height: ${this.options.cursorSize}px;
                border-radius: 50%;
                background: linear-gradient(135deg, #667eea, #764ba2);
                pointer-events: none;
                z-index: 10000;
                transform: translate(-50%, -50%);
                transition: width 0.2s, height 0.2s;
                box-shadow: 0 0 20px rgba(102, 126, 234, 0.8);
            `;
            
            // Glow circle
            this.cursorGlow = document.createElement('div');
            this.cursorGlow.className = 'megido-cursor-glow';
            this.cursorGlow.style.cssText = `
                position: fixed;
                width: ${this.options.glowSize}px;
                height: ${this.options.glowSize}px;
                border-radius: 50%;
                border: 2px solid rgba(102, 126, 234, 0.3);
                pointer-events: none;
                z-index: 9999;
                transform: translate(-50%, -50%);
                transition: width 0.3s, height 0.3s, border-color 0.3s;
            `;
            
            document.body.appendChild(this.cursor);
            document.body.appendChild(this.cursorGlow);
            
            // Hide default cursor on body
            document.body.style.cursor = 'none';
        }
        
        bindEvents() {
            document.addEventListener('mousemove', (e) => {
                this.mouseX = e.clientX;
                this.mouseY = e.clientY;
            });
            
            // Expand on interactive elements
            document.addEventListener('mouseover', (e) => {
                if (e.target.matches('a, button, input, [role="button"], .card-3d, .hover-premium')) {
                    this.cursor.style.width = `${this.options.cursorSize * 2}px`;
                    this.cursor.style.height = `${this.options.cursorSize * 2}px`;
                    this.cursorGlow.style.width = `${this.options.glowSize * 1.5}px`;
                    this.cursorGlow.style.height = `${this.options.glowSize * 1.5}px`;
                    this.cursorGlow.style.borderColor = 'rgba(102, 126, 234, 0.6)';
                }
            });
            
            document.addEventListener('mouseout', (e) => {
                if (e.target.matches('a, button, input, [role="button"], .card-3d, .hover-premium')) {
                    this.cursor.style.width = `${this.options.cursorSize}px`;
                    this.cursor.style.height = `${this.options.cursorSize}px`;
                    this.cursorGlow.style.width = `${this.options.glowSize}px`;
                    this.cursorGlow.style.height = `${this.options.glowSize}px`;
                    this.cursorGlow.style.borderColor = 'rgba(102, 126, 234, 0.3)';
                }
            });
            
            // Shrink on click
            document.addEventListener('mousedown', () => {
                this.cursor.style.transform = 'translate(-50%, -50%) scale(0.8)';
            });
            
            document.addEventListener('mouseup', () => {
                this.cursor.style.transform = 'translate(-50%, -50%) scale(1)';
            });
        }
        
        animate() {
            // Smooth cursor following with easing
            this.targetX += (this.mouseX - this.targetX) * 0.2;
            this.targetY += (this.mouseY - this.targetY) * 0.2;
            
            this.cursor.style.left = `${this.mouseX}px`;
            this.cursor.style.top = `${this.mouseY}px`;
            
            this.cursorGlow.style.left = `${this.targetX}px`;
            this.cursorGlow.style.top = `${this.targetY}px`;
            
            requestAnimationFrame(() => this.animate());
        }
        
        destroy() {
            if (this.cursor) this.cursor.remove();
            if (this.cursorGlow) this.cursorGlow.remove();
            document.body.style.cursor = 'auto';
        }
    }
    
    // Spotlight effect
    class SpotlightEffect {
        constructor() {
            this.enabled = !window.matchMedia('(prefers-reduced-motion: reduce)').matches;
            if (!this.enabled) return;
            
            this.spotlight = null;
            this.mouseX = 0;
            this.mouseY = 0;
            this.init();
        }
        
        init() {
            this.spotlight = document.createElement('div');
            this.spotlight.className = 'megido-spotlight';
            this.spotlight.style.cssText = `
                position: fixed;
                width: 600px;
                height: 600px;
                border-radius: 50%;
                background: radial-gradient(circle, rgba(102, 126, 234, 0.08) 0%, transparent 70%);
                pointer-events: none;
                z-index: 1;
                transform: translate(-50%, -50%);
                transition: opacity 0.3s;
                opacity: 0;
            `;
            document.body.appendChild(this.spotlight);
            
            document.addEventListener('mousemove', (e) => {
                this.mouseX = e.clientX;
                this.mouseY = e.clientY;
                this.spotlight.style.left = `${this.mouseX}px`;
                this.spotlight.style.top = `${this.mouseY}px`;
                this.spotlight.style.opacity = '1';
            });
            
            document.addEventListener('mouseleave', () => {
                this.spotlight.style.opacity = '0';
            });
        }
        
        destroy() {
            if (this.spotlight) this.spotlight.remove();
        }
    }
    
    // Initialize based on device
    let cursorInstance = null;
    let spotlightInstance = null;
    
    function initCursor() {
        // Only on desktop devices
        if (window.innerWidth > 1024 && !('ontouchstart' in window)) {
            if (document.body.classList.contains('custom-cursor-enabled')) {
                cursorInstance = new AdvancedCursor();
            }
            
            if (document.body.classList.contains('spotlight-enabled')) {
                spotlightInstance = new SpotlightEffect();
            }
        }
    }
    
    // Auto-initialize
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initCursor);
    } else {
        initCursor();
    }
    
    // Export to global
    window.MegidoCursor = {
        AdvancedCursor,
        SpotlightEffect,
        init: initCursor
    };
    
    console.log('🎯 Advanced Cursor Effects v2.3 loaded');
    
})();
