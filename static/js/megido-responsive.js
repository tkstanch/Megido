/**
 * Megido Responsive Utilities
 * Handles responsive behavior, sidebar management, and viewport-aware interactions
 */

(function() {
    'use strict';
    
    // Responsive breakpoints matching Tailwind config
    const BREAKPOINTS = {
        xs: 375,
        sm: 640,
        md: 768,
        lg: 1024,
        xl: 1280,
        '2xl': 1536,
        '3xl': 1920,
        '4xl': 2560,
        ultra: 3840
    };
    
    /**
     * Get current breakpoint
     */
    function getCurrentBreakpoint() {
        const width = window.innerWidth;
        
        if (width >= BREAKPOINTS.ultra) return 'ultra';
        if (width >= BREAKPOINTS['4xl']) return '4xl';
        if (width >= BREAKPOINTS['3xl']) return '3xl';
        if (width >= BREAKPOINTS['2xl']) return '2xl';
        if (width >= BREAKPOINTS.xl) return 'xl';
        if (width >= BREAKPOINTS.lg) return 'lg';
        if (width >= BREAKPOINTS.md) return 'md';
        if (width >= BREAKPOINTS.sm) return 'sm';
        return 'xs';
    }
    
    /**
     * Check if viewport is mobile/tablet (< 1024px)
     */
    function isMobileOrTablet() {
        return window.innerWidth < BREAKPOINTS.lg;
    }
    
    /**
     * Check if viewport is desktop (>= 1024px)
     */
    function isDesktop() {
        return window.innerWidth >= BREAKPOINTS.lg;
    }
    
    /**
     * Enhanced Sidebar Manager
     * Handles responsive behavior: always visible on desktop, slide-in on mobile
     */
    class SidebarManager {
        constructor() {
            this.sidebar = document.getElementById('sidebar');
            this.menuToggle = document.getElementById('menu-toggle');
            this.isOpen = false;
            
            if (this.sidebar && this.menuToggle) {
                this.init();
            }
        }
        
        init() {
            // Set initial state based on viewport
            this.updateSidebarState();
            
            // Toggle button click
            this.menuToggle.addEventListener('click', (e) => {
                e.stopPropagation();
                this.toggleSidebar();
            });
            
            // Close on outside click (mobile only)
            document.addEventListener('click', (e) => {
                if (isMobileOrTablet() && this.isOpen) {
                    const isMenuClick = this.menuToggle.contains(e.target);
                    const isSidebarClick = this.sidebar.contains(e.target);
                    
                    if (!isMenuClick && !isSidebarClick) {
                        this.closeSidebar();
                    }
                }
            });
            
            // Handle window resize
            let resizeTimer;
            window.addEventListener('resize', () => {
                clearTimeout(resizeTimer);
                resizeTimer = setTimeout(() => {
                    this.updateSidebarState();
                }, 250);
            });
            
            // ESC key to close sidebar on mobile
            document.addEventListener('keydown', (e) => {
                if (e.key === 'Escape' && isMobileOrTablet() && this.isOpen) {
                    this.closeSidebar();
                }
            });
        }
        
        updateSidebarState() {
            if (isDesktop()) {
                // Desktop: always visible
                this.sidebar.classList.remove('-translate-x-full');
                this.isOpen = true;
                this.removeBackdrop();
            } else {
                // Mobile/Tablet: closed by default
                this.sidebar.classList.add('-translate-x-full');
                this.isOpen = false;
                this.removeBackdrop();
            }
        }
        
        toggleSidebar() {
            if (this.isOpen) {
                this.closeSidebar();
            } else {
                this.openSidebar();
            }
        }
        
        openSidebar() {
            this.sidebar.classList.remove('-translate-x-full');
            this.isOpen = true;
            
            if (isMobileOrTablet()) {
                this.addBackdrop();
            }
            
            // Announce to screen readers
            this.sidebar.setAttribute('aria-hidden', 'false');
            this.menuToggle.setAttribute('aria-expanded', 'true');
        }
        
        closeSidebar() {
            this.sidebar.classList.add('-translate-x-full');
            this.isOpen = false;
            this.removeBackdrop();
            
            // Announce to screen readers
            this.sidebar.setAttribute('aria-hidden', 'true');
            this.menuToggle.setAttribute('aria-expanded', 'false');
        }
        
        addBackdrop() {
            if (document.getElementById('sidebar-backdrop')) return;
            
            const backdrop = document.createElement('div');
            backdrop.id = 'sidebar-backdrop';
            backdrop.className = 'fixed inset-0 bg-black/50 backdrop-blur-sm z-40 lg:hidden animate-fade-in';
            backdrop.setAttribute('aria-hidden', 'true');
            backdrop.addEventListener('click', () => this.closeSidebar());
            
            document.body.appendChild(backdrop);
        }
        
        removeBackdrop() {
            const backdrop = document.getElementById('sidebar-backdrop');
            if (backdrop) {
                backdrop.classList.add('opacity-0');
                setTimeout(() => backdrop.remove(), 300);
            }
        }
    }
    
    /**
     * Responsive Icon Scaler
     * Dynamically adjusts icon sizes based on viewport
     */
    function initResponsiveIcons() {
        const icons = document.querySelectorAll('.icon-responsive, .icon-responsive-lg, .icon-responsive-xl');
        
        icons.forEach(icon => {
            // Add touch-friendly padding on mobile
            if (isMobileOrTablet()) {
                icon.style.padding = '0.25rem';
            }
        });
    }
    
    /**
     * Responsive Grid Manager
     * Adjusts grid columns based on viewport
     */
    function initResponsiveGrids() {
        const grids = document.querySelectorAll('.grid-responsive, .grid-responsive-lg');
        
        grids.forEach(grid => {
            // Add appropriate classes based on viewport
            const breakpoint = getCurrentBreakpoint();
            
            // Set data attribute for CSS hooks
            grid.setAttribute('data-breakpoint', breakpoint);
        });
    }
    
    /**
     * Touch Target Enhancement
     * Ensures all interactive elements meet minimum 44x44px touch target size
     */
    function enhanceTouchTargets() {
        if (!isMobileOrTablet()) return;
        
        const interactiveElements = document.querySelectorAll('button, a, input[type="checkbox"], input[type="radio"]');
        
        interactiveElements.forEach(el => {
            const rect = el.getBoundingClientRect();
            
            if (rect.width < 44 || rect.height < 44) {
                el.classList.add('touch-target');
            }
        });
    }
    
    /**
     * Viewport Height Fixer
     * Handles mobile viewport height issues (address bar)
     */
    function fixViewportHeight() {
        // Set CSS custom property for real viewport height
        const vh = window.innerHeight * 0.01;
        document.documentElement.style.setProperty('--vh', `${vh}px`);
        
        // Update on resize and orientation change
        window.addEventListener('resize', () => {
            const vh = window.innerHeight * 0.01;
            document.documentElement.style.setProperty('--vh', `${vh}px`);
        });
    }
    
    /**
     * Responsive Table Handler
     * Makes tables scrollable on mobile
     */
    function initResponsiveTables() {
        const tables = document.querySelectorAll('table:not(.table-container table)');
        
        tables.forEach(table => {
            if (!table.parentElement.classList.contains('table-container')) {
                const wrapper = document.createElement('div');
                wrapper.className = 'table-container';
                table.parentNode.insertBefore(wrapper, table);
                wrapper.appendChild(table);
            }
        });
    }
    
    /**
     * Font Size Adjuster
     * Applies fluid typography based on viewport
     */
    function initFluidTypography() {
        const fluidTextElements = document.querySelectorAll('[class*="fluid-"]');
        
        fluidTextElements.forEach(el => {
            // Add smooth transitions
            el.style.transition = 'font-size 0.3s ease';
        });
    }
    
    /**
     * Orientation Change Handler
     */
    function handleOrientationChange() {
        window.addEventListener('orientationchange', () => {
            // Wait for orientation change to complete
            setTimeout(() => {
                fixViewportHeight();
                initResponsiveGrids();
                
                // Trigger custom event
                window.dispatchEvent(new CustomEvent('megido:orientationchange', {
                    detail: { orientation: screen.orientation?.type || 'unknown' }
                }));
            }, 200);
        });
    }
    
    /**
     * Initialize all responsive features
     */
    function init() {
        // Initialize sidebar manager
        new SidebarManager();
        
        // Initialize responsive features
        fixViewportHeight();
        initResponsiveIcons();
        initResponsiveGrids();
        enhanceTouchTargets();
        initResponsiveTables();
        initFluidTypography();
        handleOrientationChange();
        
        // Re-initialize on dynamic content load
        window.addEventListener('megido:contentLoaded', () => {
            initResponsiveIcons();
            initResponsiveGrids();
            enhanceTouchTargets();
            initResponsiveTables();
        });
        
        // Add breakpoint to body for debugging
        document.body.setAttribute('data-breakpoint', getCurrentBreakpoint());
        
        // Update on resize
        let resizeTimer;
        window.addEventListener('resize', () => {
            clearTimeout(resizeTimer);
            resizeTimer = setTimeout(() => {
                document.body.setAttribute('data-breakpoint', getCurrentBreakpoint());
            }, 250);
        });
        
        console.log('✅ Megido Responsive Utilities initialized');
        console.log(`📱 Current breakpoint: ${getCurrentBreakpoint()}`);
    }
    
    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
    
    // Export utilities to window
    window.MegidoResponsive = {
        getCurrentBreakpoint,
        isMobileOrTablet,
        isDesktop,
        BREAKPOINTS
    };
    
})();
