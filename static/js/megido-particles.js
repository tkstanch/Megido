/**
 * Megido Particle System v2.3
 * Ultra premium particle effects for extreme beauty
 */

(function() {
    'use strict';
    
    class ParticleSystem {
        constructor(options = {}) {
            this.canvas = options.canvas || this.createCanvas();
            this.ctx = this.canvas.getContext('2d');
            this.particles = [];
            this.maxParticles = options.maxParticles || 50;
            this.particleColor = options.particleColor || 'rgba(102, 126, 234, 0.6)';
            this.connectionDistance = options.connectionDistance || 150;
            this.speed = options.speed || 0.5;
            this.mouseParticles = [];
            this.enabled = !window.matchMedia('(prefers-reduced-motion: reduce)').matches;
            
            if (this.enabled) {
                this.init();
            }
        }
        
        createCanvas() {
            const canvas = document.createElement('canvas');
            canvas.style.position = 'fixed';
            canvas.style.top = '0';
            canvas.style.left = '0';
            canvas.style.width = '100%';
            canvas.style.height = '100%';
            canvas.style.pointerEvents = 'none';
            canvas.style.zIndex = '1';
            canvas.style.opacity = '0.4';
            document.body.appendChild(canvas);
            return canvas;
        }
        
        init() {
            this.resize();
            this.createParticles();
            this.animate();
            
            window.addEventListener('resize', () => this.resize());
            document.addEventListener('mousemove', (e) => this.handleMouseMove(e));
        }
        
        resize() {
            this.canvas.width = window.innerWidth;
            this.canvas.height = window.innerHeight;
        }
        
        createParticles() {
            for (let i = 0; i < this.maxParticles; i++) {
                this.particles.push({
                    x: Math.random() * this.canvas.width,
                    y: Math.random() * this.canvas.height,
                    vx: (Math.random() - 0.5) * this.speed,
                    vy: (Math.random() - 0.5) * this.speed,
                    size: Math.random() * 2 + 1,
                    opacity: Math.random() * 0.5 + 0.3
                });
            }
        }
        
        handleMouseMove(e) {
            // Create particle trail
            if (this.mouseParticles.length < 20) {
                this.mouseParticles.push({
                    x: e.clientX,
                    y: e.clientY,
                    size: Math.random() * 3 + 2,
                    opacity: 1,
                    vx: (Math.random() - 0.5) * 2,
                    vy: (Math.random() - 0.5) * 2,
                    life: 1
                });
            }
        }
        
        update() {
            // Update main particles
            this.particles.forEach(particle => {
                particle.x += particle.vx;
                particle.y += particle.vy;
                
                // Bounce off edges
                if (particle.x < 0 || particle.x > this.canvas.width) particle.vx *= -1;
                if (particle.y < 0 || particle.y > this.canvas.height) particle.vy *= -1;
                
                // Keep in bounds
                particle.x = Math.max(0, Math.min(this.canvas.width, particle.x));
                particle.y = Math.max(0, Math.min(this.canvas.height, particle.y));
            });
            
            // Update mouse trail particles
            this.mouseParticles = this.mouseParticles.filter(particle => {
                particle.x += particle.vx;
                particle.y += particle.vy;
                particle.life -= 0.02;
                particle.opacity = particle.life;
                return particle.life > 0;
            });
        }
        
        draw() {
            this.ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);
            
            // Draw connections
            this.particles.forEach((p1, i) => {
                this.particles.slice(i + 1).forEach(p2 => {
                    const dx = p1.x - p2.x;
                    const dy = p1.y - p2.y;
                    const distance = Math.sqrt(dx * dx + dy * dy);
                    
                    if (distance < this.connectionDistance) {
                        this.ctx.beginPath();
                        this.ctx.strokeStyle = `rgba(102, 126, 234, ${0.2 * (1 - distance / this.connectionDistance)})`;
                        this.ctx.lineWidth = 1;
                        this.ctx.moveTo(p1.x, p1.y);
                        this.ctx.lineTo(p2.x, p2.y);
                        this.ctx.stroke();
                    }
                });
            });
            
            // Draw main particles
            this.particles.forEach(particle => {
                this.ctx.beginPath();
                this.ctx.arc(particle.x, particle.y, particle.size, 0, Math.PI * 2);
                this.ctx.fillStyle = `rgba(102, 126, 234, ${particle.opacity})`;
                this.ctx.fill();
                
                // Add glow
                const gradient = this.ctx.createRadialGradient(
                    particle.x, particle.y, 0,
                    particle.x, particle.y, particle.size * 3
                );
                gradient.addColorStop(0, `rgba(102, 126, 234, ${particle.opacity * 0.5})`);
                gradient.addColorStop(1, 'rgba(102, 126, 234, 0)');
                this.ctx.fillStyle = gradient;
                this.ctx.fill();
            });
            
            // Draw mouse trail particles
            this.mouseParticles.forEach(particle => {
                this.ctx.beginPath();
                this.ctx.arc(particle.x, particle.y, particle.size, 0, Math.PI * 2);
                const gradient = this.ctx.createRadialGradient(
                    particle.x, particle.y, 0,
                    particle.x, particle.y, particle.size * 2
                );
                gradient.addColorStop(0, `rgba(102, 126, 234, ${particle.opacity})`);
                gradient.addColorStop(1, 'rgba(102, 126, 234, 0)');
                this.ctx.fillStyle = gradient;
                this.ctx.fill();
            });
        }
        
        animate() {
            this.update();
            this.draw();
            requestAnimationFrame(() => this.animate());
        }
        
        destroy() {
            if (this.canvas && this.canvas.parentNode) {
                this.canvas.parentNode.removeChild(this.canvas);
            }
        }
    }
    
    // Celebration particles for success states
    class CelebrationParticles {
        static celebrate(element) {
            if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
            
            const rect = element.getBoundingClientRect();
            const centerX = rect.left + rect.width / 2;
            const centerY = rect.top + rect.height / 2;
            
            const canvas = document.createElement('canvas');
            canvas.style.position = 'fixed';
            canvas.style.top = '0';
            canvas.style.left = '0';
            canvas.style.width = '100%';
            canvas.style.height = '100%';
            canvas.style.pointerEvents = 'none';
            canvas.style.zIndex = '9999';
            canvas.width = window.innerWidth;
            canvas.height = window.innerHeight;
            document.body.appendChild(canvas);
            
            const ctx = canvas.getContext('2d');
            const particles = [];
            const particleCount = 50;
            
            // Create particles
            for (let i = 0; i < particleCount; i++) {
                const angle = (Math.PI * 2 * i) / particleCount;
                const velocity = 3 + Math.random() * 3;
                particles.push({
                    x: centerX,
                    y: centerY,
                    vx: Math.cos(angle) * velocity,
                    vy: Math.sin(angle) * velocity,
                    size: Math.random() * 4 + 2,
                    color: ['#667eea', '#764ba2', '#f093fb', '#10b981', '#f59e0b'][Math.floor(Math.random() * 5)],
                    life: 1,
                    rotation: Math.random() * Math.PI * 2,
                    rotationSpeed: (Math.random() - 0.5) * 0.2
                });
            }
            
            function animate() {
                ctx.clearRect(0, 0, canvas.width, canvas.height);
                
                let allDead = true;
                particles.forEach(particle => {
                    if (particle.life > 0) {
                        allDead = false;
                        
                        particle.x += particle.vx;
                        particle.y += particle.vy;
                        particle.vy += 0.2; // Gravity
                        particle.life -= 0.015;
                        particle.rotation += particle.rotationSpeed;
                        
                        ctx.save();
                        ctx.translate(particle.x, particle.y);
                        ctx.rotate(particle.rotation);
                        ctx.globalAlpha = particle.life;
                        
                        // Draw confetti
                        ctx.fillStyle = particle.color;
                        ctx.fillRect(-particle.size / 2, -particle.size / 2, particle.size, particle.size * 2);
                        
                        ctx.restore();
                    }
                });
                
                if (!allDead) {
                    requestAnimationFrame(animate);
                } else {
                    document.body.removeChild(canvas);
                }
            }
            
            animate();
        }
    }
    
    // Initialize particles on load
    let particleSystem = null;
    
    function initParticles() {
        if (document.body.classList.contains('particles-enabled')) {
            particleSystem = new ParticleSystem({
                maxParticles: 50,
                connectionDistance: 150,
                speed: 0.3
            });
        }
    }
    
    // Auto-initialize if enabled
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initParticles);
    } else {
        initParticles();
    }
    
    // Export to global
    window.MegidoParticles = {
        ParticleSystem,
        CelebrationParticles,
        init: initParticles
    };
    
    console.log('🎨 Particle System v2.3 loaded');
    
})();
