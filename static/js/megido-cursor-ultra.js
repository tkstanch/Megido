/**
 * Megido Ultra Cursor System v2.3+
 * Enhanced cursor with prism trails and advanced interactions
 */

(function() {
    'use strict';
    
    class UltraCursor {
        constructor(options = {}) {
            this.enabled = !window.matchMedia('(prefers-reduced-motion: reduce)').matches;
            this.isTouchDevice = 'ontouchstart' in window || navigator.maxTouchPoints > 0;
            
            if (!this.enabled || this.isTouchDevice) return;
            
            this.options = {
                cursorSize: options.cursorSize || 12,
                glowSize: options.glowSize || 50,
                trailCount: options.trailCount || 15,
                prismTrail: options.prismTrail !== false,
                spotlight: options.spotlight !== false,
                ...options
            };
            
            this.cursor = null;
            this.cursorGlow = null;
            this.spotlight = null;
            this.trails = [];
            this.mouseX = 0;
            this.mouseY = 0;
            this.targetX = 0;
            this.targetY = 0;
            this.lastTrailTime = 0;
            
            this.init();
        }
        
        init() {
            this.createCursor();
            this.bindEvents();
            this.animate();
        }
        
        createCursor() {
            // Main cursor dot with enhanced gradient
            this.cursor = document.createElement('div');
            this.cursor.className = 'megido-ultra-cursor';
            this.cursor.style.cssText = `
                position: fixed;
                width: ${this.options.cursorSize}px;
                height: ${this.options.cursorSize}px;
                border-radius: 50%;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 50%, #f093fb 100%);
                pointer-events: none;
                z-index: 10001;
                transform: translate(-50%, -50%);
                transition: width 0.2s ease, height 0.2s ease;
                box-shadow: 
                    0 0 15px rgba(102, 126, 234, 0.8),
                    0 0 30px rgba(118, 75, 162, 0.6),
                    0 0 45px rgba(240, 147, 251, 0.4);
                animation: cursor-pulse 2s ease-in-out infinite;
            `;
            
            // Enhanced glow circle with gradient border
            this.cursorGlow = document.createElement('div');
            this.cursorGlow.className = 'megido-ultra-cursor-glow';
            this.cursorGlow.style.cssText = `
                position: fixed;
                width: ${this.options.glowSize}px;
                height: ${this.options.glowSize}px;
                border-radius: 50%;
                border: 2px solid transparent;
                background: 
                    linear-gradient(white, white) padding-box,
                    linear-gradient(135deg, rgba(102, 126, 234, 0.4), rgba(118, 75, 162, 0.4), rgba(240, 147, 251, 0.4)) border-box;
                pointer-events: none;
                z-index: 10000;
                transform: translate(-50%, -50%);
                transition: width 0.3s ease, height 0.3s ease, opacity 0.3s ease;
                opacity: 0.6;
            `;
            
            // Spotlight effect
            if (this.options.spotlight) {
                this.spotlight = document.createElement('div');
                this.spotlight.className = 'megido-ultra-spotlight';
                this.spotlight.style.cssText = `
                    position: fixed;
                    width: 400px;
                    height: 400px;
                    border-radius: 50%;
                    background: radial-gradient(
                        circle,
                        rgba(102, 126, 234, 0.15) 0%,
                        rgba(118, 75, 162, 0.1) 40%,
                        transparent 70%
                    );
                    pointer-events: none;
                    z-index: 9999;
                    transform: translate(-50%, -50%);
                    mix-blend-mode: screen;
                    opacity: 0.8;
                `;
                document.body.appendChild(this.spotlight);
            }
            
            document.body.appendChild(this.cursor);
            document.body.appendChild(this.cursorGlow);
            
            // Hide default cursor
            document.body.style.cursor = 'none';
            
            // Add cursor pulse animation to document
            if (!document.getElementById('cursor-pulse-keyframes')) {
                const style = document.createElement('style');
                style.id = 'cursor-pulse-keyframes';
                style.textContent = `
                    @keyframes cursor-pulse {
                        0%, 100% { 
                            transform: translate(-50%, -50%) scale(1);
                            filter: hue-rotate(0deg);
                        }
                        50% { 
                            transform: translate(-50%, -50%) scale(1.1);
                            filter: hue-rotate(30deg);
                        }
                    }
                `;
                document.head.appendChild(style);
            }
        }
        
        createPrismTrail(x, y) {
            const trail = document.createElement('div');
            trail.className = 'cursor-prism-trail';
            trail.style.cssText = `
                position: fixed;
                left: ${x}px;
                top: ${y}px;
                width: 8px;
                height: 8px;
                border-radius: 50%;
                background: linear-gradient(135deg, #ff00ff, #00ffff, #ffff00);
                opacity: 0.7;
                pointer-events: none;
                z-index: 9998;
                transform: translate(-50%, -50%);
                animation: cursor-trail-fade 0.8s ease-out forwards;
                box-shadow: 0 0 10px currentColor;
            `;
            document.body.appendChild(trail);
            
            setTimeout(() => {
                if (trail.parentNode) {
                    trail.parentNode.removeChild(trail);
                }
            }, 800);
        }
        
        bindEvents() {
            let lastX = 0;
            let lastY = 0;
            
            document.addEventListener('mousemove', (e) => {
                this.targetX = e.clientX;
                this.targetY = e.clientY;
                
                // Create prism trail based on movement
                if (this.options.prismTrail) {
                    const now = Date.now();
                    const distance = Math.sqrt(
                        Math.pow(e.clientX - lastX, 2) + 
                        Math.pow(e.clientY - lastY, 2)
                    );
                    
                    if (distance > 10 && now - this.lastTrailTime > 50) {
                        this.createPrismTrail(e.clientX, e.clientY);
                        this.lastTrailTime = now;
                    }
                }
                
                lastX = e.clientX;
                lastY = e.clientY;
            });
            
            // Enhanced interactions for different elements
            document.addEventListener('mouseover', (e) => {
                const target = e.target;
                
                // Expand on interactive elements
                if (target.matches('a, button, input, [role="button"], .card-3d, .hover-premium, .btn, [onclick]')) {
                    this.cursor.style.width = `${this.options.cursorSize * 2.5}px`;
                    this.cursor.style.height = `${this.options.cursorSize * 2.5}px`;
                    this.cursorGlow.style.width = `${this.options.glowSize * 1.8}px`;
                    this.cursorGlow.style.height = `${this.options.glowSize * 1.8}px`;
                    this.cursorGlow.style.opacity = '1';
                }
            });
            
            document.addEventListener('mouseout', (e) => {
                const target = e.target;
                
                if (target.matches('a, button, input, [role="button"], .card-3d, .hover-premium, .btn, [onclick]')) {
                    this.cursor.style.width = `${this.options.cursorSize}px`;
                    this.cursor.style.height = `${this.options.cursorSize}px`;
                    this.cursorGlow.style.width = `${this.options.glowSize}px`;
                    this.cursorGlow.style.height = `${this.options.glowSize}px`;
                    this.cursorGlow.style.opacity = '0.6';
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
            const ease = 0.15;
            this.mouseX += (this.targetX - this.mouseX) * ease;
            this.mouseY += (this.targetY - this.mouseY) * ease;
            
            this.cursor.style.left = `${this.mouseX}px`;
            this.cursor.style.top = `${this.mouseY}px`;
            
            // Glow follows with slight delay
            const glowEase = 0.1;
            this.cursorGlow.style.left = `${this.mouseX}px`;
            this.cursorGlow.style.top = `${this.mouseY}px`;
            
            // Spotlight follows with more delay
            if (this.spotlight) {
                const spotEase = 0.08;
                this.spotlight.style.left = `${this.mouseX}px`;
                this.spotlight.style.top = `${this.mouseY}px`;
            }
            
            requestAnimationFrame(() => this.animate());
        }
    }
    
    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
            window.MegidoUltraCursor = new UltraCursor();
        });
    } else {
        window.MegidoUltraCursor = new UltraCursor();
    }
    
})();
