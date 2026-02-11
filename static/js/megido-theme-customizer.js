/**
 * Megido Theme Customizer v2.3+
 * Live theme customization with color pickers and accessibility checks
 */

(function() {
    'use strict';
    
    class ThemeCustomizer {
        constructor() {
            this.themes = {
                light: {
                    name: 'Light',
                    primary: '#667eea',
                    secondary: '#764ba2',
                    accent: '#f093fb',
                    background: '#ffffff',
                    surface: '#f9fafb',
                    text: '#111827'
                },
                dark: {
                    name: 'Dark',
                    primary: '#667eea',
                    secondary: '#764ba2',
                    accent: '#f093fb',
                    background: '#111827',
                    surface: '#1f2937',
                    text: '#f9fafb'
                },
                ultra: {
                    name: 'Ultra',
                    primary: '#00f5ff',
                    secondary: '#ff00f5',
                    accent: '#ffff00',
                    background: '#0a0a0a',
                    surface: '#1a1a1a',
                    text: '#ffffff'
                }
            };
            
            this.currentTheme = 'light';
            this.isCustomizerOpen = false;
            
            this.init();
        }
        
        init() {
            this.createCustomizerUI();
            this.loadSavedTheme();
            this.bindEvents();
        }
        
        createCustomizerUI() {
            const customizer = document.createElement('div');
            customizer.id = 'theme-customizer';
            customizer.className = 'theme-customizer';
            customizer.innerHTML = `
                <button id="customizer-toggle" class="customizer-toggle" aria-label="Open theme customizer">
                    <svg width="24" height="24" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 21a4 4 0 01-4-4V5a2 2 0 012-2h4a2 2 0 012 2v12a4 4 0 01-4 4zm0 0h12a2 2 0 002-2v-4a2 2 0 00-2-2h-2.343M11 7.343l1.657-1.657a2 2 0 012.828 0l2.829 2.829a2 2 0 010 2.828l-8.486 8.485M7 17h.01"></path>
                    </svg>
                </button>
                
                <div id="customizer-panel" class="customizer-panel" style="transform: translateX(100%);">
                    <div class="customizer-header">
                        <h3>Theme Customizer</h3>
                        <button id="customizer-close" aria-label="Close customizer">
                            <svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                            </svg>
                        </button>
                    </div>
                    
                    <div class="customizer-body">
                        <!-- Theme Presets -->
                        <div class="customizer-section">
                            <h4>Theme Presets</h4>
                            <div class="theme-presets">
                                <button class="theme-preset active" data-theme="light">
                                    <div class="preset-preview light-preview"></div>
                                    <span>Light</span>
                                </button>
                                <button class="theme-preset" data-theme="dark">
                                    <div class="preset-preview dark-preview"></div>
                                    <span>Dark</span>
                                </button>
                                <button class="theme-preset" data-theme="ultra">
                                    <div class="preset-preview ultra-preview"></div>
                                    <span>Ultra</span>
                                </button>
                            </div>
                        </div>
                        
                        <!-- Color Customization -->
                        <div class="customizer-section">
                            <h4>Colors</h4>
                            <div class="color-inputs">
                                <div class="color-input-group">
                                    <label for="primary-color">Primary</label>
                                    <div class="color-input-wrapper">
                                        <input type="color" id="primary-color" value="#667eea">
                                        <span id="primary-color-value">#667eea</span>
                                    </div>
                                </div>
                                <div class="color-input-group">
                                    <label for="secondary-color">Secondary</label>
                                    <div class="color-input-wrapper">
                                        <input type="color" id="secondary-color" value="#764ba2">
                                        <span id="secondary-color-value">#764ba2</span>
                                    </div>
                                </div>
                                <div class="color-input-group">
                                    <label for="accent-color">Accent</label>
                                    <div class="color-input-wrapper">
                                        <input type="color" id="accent-color" value="#f093fb">
                                        <span id="accent-color-value">#f093fb</span>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Accessibility Check -->
                        <div class="customizer-section">
                            <h4>Accessibility Check</h4>
                            <div id="accessibility-status" class="accessibility-status">
                                <div class="status-item">
                                    <span>Contrast Ratio:</span>
                                    <span id="contrast-ratio" class="status-value">Calculating...</span>
                                </div>
                                <div class="status-item">
                                    <span>WCAG AA:</span>
                                    <span id="wcag-aa" class="status-value">Checking...</span>
                                </div>
                                <div class="status-item">
                                    <span>WCAG AAA:</span>
                                    <span id="wcag-aaa" class="status-value">Checking...</span>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Effects Toggle -->
                        <div class="customizer-section">
                            <h4>Effects</h4>
                            <div class="effect-toggles">
                                <label class="toggle-wrapper">
                                    <input type="checkbox" id="particles-toggle" checked>
                                    <span>Particles</span>
                                </label>
                                <label class="toggle-wrapper">
                                    <input type="checkbox" id="cursor-toggle" checked>
                                    <span>Custom Cursor</span>
                                </label>
                                <label class="toggle-wrapper">
                                    <input type="checkbox" id="animations-toggle" checked>
                                    <span>Animations</span>
                                </label>
                            </div>
                        </div>
                        
                        <!-- Actions -->
                        <div class="customizer-section">
                            <div class="customizer-actions">
                                <button id="export-theme" class="btn-secondary">Export Theme</button>
                                <button id="reset-theme" class="btn-secondary">Reset to Default</button>
                            </div>
                        </div>
                    </div>
                </div>
            `;
            
            document.body.appendChild(customizer);
            this.addCustomizerStyles();
        }
        
        addCustomizerStyles() {
            if (document.getElementById('customizer-styles')) return;
            
            const style = document.createElement('style');
            style.id = 'customizer-styles';
            style.textContent = `
                .customizer-toggle {
                    position: fixed;
                    right: 20px;
                    bottom: 20px;
                    width: 56px;
                    height: 56px;
                    border-radius: 50%;
                    background: linear-gradient(135deg, #667eea, #764ba2);
                    border: none;
                    color: white;
                    cursor: pointer;
                    box-shadow: 0 10px 30px rgba(102, 126, 234, 0.4);
                    transition: all 0.3s ease;
                    z-index: 9990;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                }
                
                .customizer-toggle:hover {
                    transform: translateY(-3px) scale(1.05);
                    box-shadow: 0 15px 40px rgba(102, 126, 234, 0.5);
                }
                
                .customizer-panel {
                    position: fixed;
                    right: 0;
                    top: 0;
                    width: 360px;
                    height: 100vh;
                    background: white;
                    box-shadow: -10px 0 50px rgba(0, 0, 0, 0.1);
                    z-index: 9995;
                    transition: transform 0.4s cubic-bezier(0.68, -0.55, 0.265, 1.55);
                    overflow-y: auto;
                }
                
                .dark .customizer-panel {
                    background: #1f2937;
                }
                
                .customizer-panel.open {
                    transform: translateX(0) !important;
                }
                
                .customizer-header {
                    display: flex;
                    align-items: center;
                    justify-content: space-between;
                    padding: 20px;
                    border-bottom: 1px solid rgba(0, 0, 0, 0.1);
                    background: linear-gradient(135deg, #667eea, #764ba2);
                    color: white;
                }
                
                .customizer-header h3 {
                    margin: 0;
                    font-size: 18px;
                    font-weight: 600;
                }
                
                .customizer-header button {
                    background: rgba(255, 255, 255, 0.2);
                    border: none;
                    border-radius: 8px;
                    width: 32px;
                    height: 32px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    cursor: pointer;
                    color: white;
                    transition: background 0.2s;
                }
                
                .customizer-header button:hover {
                    background: rgba(255, 255, 255, 0.3);
                }
                
                .customizer-body {
                    padding: 20px;
                }
                
                .customizer-section {
                    margin-bottom: 24px;
                }
                
                .customizer-section h4 {
                    margin: 0 0 12px 0;
                    font-size: 14px;
                    font-weight: 600;
                    text-transform: uppercase;
                    color: #6b7280;
                }
                
                .dark .customizer-section h4 {
                    color: #9ca3af;
                }
                
                .theme-presets {
                    display: grid;
                    grid-template-columns: repeat(3, 1fr);
                    gap: 12px;
                }
                
                .theme-preset {
                    background: #f3f4f6;
                    border: 2px solid transparent;
                    border-radius: 12px;
                    padding: 12px;
                    cursor: pointer;
                    transition: all 0.2s;
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    gap: 8px;
                }
                
                .dark .theme-preset {
                    background: #374151;
                }
                
                .theme-preset:hover {
                    transform: translateY(-2px);
                    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
                }
                
                .theme-preset.active {
                    border-color: #667eea;
                    background: rgba(102, 126, 234, 0.1);
                }
                
                .preset-preview {
                    width: 60px;
                    height: 40px;
                    border-radius: 8px;
                    box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.1);
                }
                
                .light-preview {
                    background: linear-gradient(135deg, #ffffff, #f3f4f6);
                }
                
                .dark-preview {
                    background: linear-gradient(135deg, #111827, #1f2937);
                }
                
                .ultra-preview {
                    background: linear-gradient(135deg, #00f5ff, #ff00f5);
                }
                
                .color-inputs {
                    display: flex;
                    flex-direction: column;
                    gap: 12px;
                }
                
                .color-input-group {
                    display: flex;
                    flex-direction: column;
                    gap: 6px;
                }
                
                .color-input-group label {
                    font-size: 13px;
                    font-weight: 500;
                    color: #6b7280;
                }
                
                .dark .color-input-group label {
                    color: #9ca3af;
                }
                
                .color-input-wrapper {
                    display: flex;
                    align-items: center;
                    gap: 12px;
                }
                
                .color-input-wrapper input[type="color"] {
                    width: 48px;
                    height: 48px;
                    border: none;
                    border-radius: 8px;
                    cursor: pointer;
                }
                
                .color-input-wrapper span {
                    font-family: monospace;
                    font-size: 13px;
                    color: #374151;
                    padding: 8px 12px;
                    background: #f3f4f6;
                    border-radius: 6px;
                    flex: 1;
                }
                
                .dark .color-input-wrapper span {
                    color: #d1d5db;
                    background: #374151;
                }
                
                .accessibility-status {
                    background: #f3f4f6;
                    padding: 12px;
                    border-radius: 8px;
                }
                
                .dark .accessibility-status {
                    background: #374151;
                }
                
                .status-item {
                    display: flex;
                    justify-content: space-between;
                    padding: 6px 0;
                    font-size: 13px;
                }
                
                .status-value {
                    font-weight: 600;
                }
                
                .status-value.pass {
                    color: #10b981;
                }
                
                .status-value.fail {
                    color: #ef4444;
                }
                
                .effect-toggles {
                    display: flex;
                    flex-direction: column;
                    gap: 12px;
                }
                
                .toggle-wrapper {
                    display: flex;
                    align-items: center;
                    gap: 12px;
                    cursor: pointer;
                    font-size: 14px;
                }
                
                .toggle-wrapper input[type="checkbox"] {
                    width: 44px;
                    height: 24px;
                    appearance: none;
                    background: #d1d5db;
                    border-radius: 12px;
                    position: relative;
                    cursor: pointer;
                    transition: background 0.2s;
                }
                
                .toggle-wrapper input[type="checkbox"]::before {
                    content: '';
                    position: absolute;
                    width: 20px;
                    height: 20px;
                    border-radius: 50%;
                    background: white;
                    top: 2px;
                    left: 2px;
                    transition: transform 0.2s;
                }
                
                .toggle-wrapper input[type="checkbox"]:checked {
                    background: #667eea;
                }
                
                .toggle-wrapper input[type="checkbox"]:checked::before {
                    transform: translateX(20px);
                }
                
                .customizer-actions {
                    display: flex;
                    flex-direction: column;
                    gap: 8px;
                }
                
                .customizer-actions button {
                    padding: 12px;
                    border: none;
                    border-radius: 8px;
                    font-size: 14px;
                    font-weight: 500;
                    cursor: pointer;
                    transition: all 0.2s;
                }
                
                .btn-secondary {
                    background: #f3f4f6;
                    color: #374151;
                }
                
                .dark .btn-secondary {
                    background: #374151;
                    color: #d1d5db;
                }
                
                .btn-secondary:hover {
                    background: #e5e7eb;
                    transform: translateY(-1px);
                }
                
                .dark .btn-secondary:hover {
                    background: #4b5563;
                }
                
                @media (max-width: 768px) {
                    .customizer-panel {
                        width: 100%;
                    }
                }
            `;
            document.head.appendChild(style);
        }
        
        bindEvents() {
            const toggle = document.getElementById('customizer-toggle');
            const close = document.getElementById('customizer-close');
            const panel = document.getElementById('customizer-panel');
            
            toggle.addEventListener('click', () => this.toggleCustomizer());
            close.addEventListener('click', () => this.closeCustomizer());
            
            // Theme presets
            document.querySelectorAll('.theme-preset').forEach(btn => {
                btn.addEventListener('click', (e) => {
                    const theme = e.currentTarget.dataset.theme;
                    this.applyThemePreset(theme);
                });
            });
            
            // Color inputs
            ['primary', 'secondary', 'accent'].forEach(color => {
                const input = document.getElementById(`${color}-color`);
                const value = document.getElementById(`${color}-color-value`);
                
                input.addEventListener('input', (e) => {
                    value.textContent = e.target.value;
                    this.updateColor(color, e.target.value);
                });
            });
            
            // Effect toggles
            document.getElementById('particles-toggle').addEventListener('change', (e) => {
                document.body.classList.toggle('particles-enabled', e.target.checked);
            });
            
            document.getElementById('cursor-toggle').addEventListener('change', (e) => {
                if (e.target.checked) {
                    document.body.style.cursor = 'none';
                } else {
                    document.body.style.cursor = 'default';
                }
            });
            
            document.getElementById('animations-toggle').addEventListener('change', (e) => {
                if (!e.target.checked) {
                    document.body.style.setProperty('--animation-disabled', '1');
                } else {
                    document.body.style.removeProperty('--animation-disabled');
                }
            });
            
            // Actions
            document.getElementById('export-theme').addEventListener('click', () => this.exportTheme());
            document.getElementById('reset-theme').addEventListener('click', () => this.resetTheme());
        }
        
        toggleCustomizer() {
            const panel = document.getElementById('customizer-panel');
            panel.classList.toggle('open');
            this.isCustomizerOpen = !this.isCustomizerOpen;
        }
        
        closeCustomizer() {
            const panel = document.getElementById('customizer-panel');
            panel.classList.remove('open');
            this.isCustomizerOpen = false;
        }
        
        applyThemePreset(themeName) {
            const theme = this.themes[themeName];
            if (!theme) return;
            
            this.currentTheme = themeName;
            
            // Update color inputs
            document.getElementById('primary-color').value = theme.primary;
            document.getElementById('secondary-color').value = theme.secondary;
            document.getElementById('accent-color').value = theme.accent;
            
            document.getElementById('primary-color-value').textContent = theme.primary;
            document.getElementById('secondary-color-value').textContent = theme.secondary;
            document.getElementById('accent-color-value').textContent = theme.accent;
            
            // Apply colors
            this.updateColor('primary', theme.primary);
            this.updateColor('secondary', theme.secondary);
            this.updateColor('accent', theme.accent);
            
            // Update active preset
            document.querySelectorAll('.theme-preset').forEach(btn => {
                btn.classList.remove('active');
            });
            document.querySelector(`[data-theme="${themeName}"]`).classList.add('active');
            
            // Apply theme class
            if (themeName === 'dark' || themeName === 'ultra') {
                document.documentElement.classList.add('dark');
            } else {
                document.documentElement.classList.remove('dark');
            }
            
            this.checkAccessibility();
        }
        
        updateColor(type, value) {
            document.documentElement.style.setProperty(`--color-${type}`, value);
            this.checkAccessibility();
        }
        
        checkAccessibility() {
            // Simplified contrast check
            const primaryColor = document.getElementById('primary-color').value;
            const backgroundColor = this.currentTheme === 'dark' ? '#111827' : '#ffffff';
            
            const contrast = this.calculateContrast(primaryColor, backgroundColor);
            const contrastRatio = document.getElementById('contrast-ratio');
            const wcagAA = document.getElementById('wcag-aa');
            const wcagAAA = document.getElementById('wcag-aaa');
            
            contrastRatio.textContent = contrast.toFixed(2) + ':1';
            contrastRatio.className = 'status-value ' + (contrast >= 4.5 ? 'pass' : 'fail');
            
            wcagAA.textContent = contrast >= 4.5 ? 'Pass ✓' : 'Fail ✗';
            wcagAA.className = 'status-value ' + (contrast >= 4.5 ? 'pass' : 'fail');
            
            wcagAAA.textContent = contrast >= 7 ? 'Pass ✓' : 'Fail ✗';
            wcagAAA.className = 'status-value ' + (contrast >= 7 ? 'pass' : 'fail');
        }
        
        calculateContrast(color1, color2) {
            const l1 = this.getLuminance(color1);
            const l2 = this.getLuminance(color2);
            const lighter = Math.max(l1, l2);
            const darker = Math.min(l1, l2);
            return (lighter + 0.05) / (darker + 0.05);
        }
        
        getLuminance(hex) {
            const rgb = this.hexToRgb(hex);
            const [r, g, b] = [rgb.r, rgb.g, rgb.b].map(val => {
                val = val / 255;
                return val <= 0.03928 ? val / 12.92 : Math.pow((val + 0.055) / 1.055, 2.4);
            });
            return 0.2126 * r + 0.7152 * g + 0.0722 * b;
        }
        
        hexToRgb(hex) {
            const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
            return result ? {
                r: parseInt(result[1], 16),
                g: parseInt(result[2], 16),
                b: parseInt(result[3], 16)
            } : null;
        }
        
        exportTheme() {
            const theme = {
                name: 'Custom',
                primary: document.getElementById('primary-color').value,
                secondary: document.getElementById('secondary-color').value,
                accent: document.getElementById('accent-color').value,
                particles: document.getElementById('particles-toggle').checked,
                cursor: document.getElementById('cursor-toggle').checked,
                animations: document.getElementById('animations-toggle').checked
            };
            
            const blob = new Blob([JSON.stringify(theme, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'megido-theme.json';
            a.click();
            URL.revokeObjectURL(url);
        }
        
        resetTheme() {
            this.applyThemePreset('light');
            document.getElementById('particles-toggle').checked = true;
            document.getElementById('cursor-toggle').checked = true;
            document.getElementById('animations-toggle').checked = true;
        }
        
        loadSavedTheme() {
            const saved = localStorage.getItem('megido-theme');
            if (saved) {
                try {
                    const theme = JSON.parse(saved);
                    this.applyThemePreset(theme.preset || 'light');
                } catch (e) {
                    console.error('Failed to load saved theme', e);
                }
            }
        }
    }
    
    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
            window.MegidoThemeCustomizer = new ThemeCustomizer();
        });
    } else {
        window.MegidoThemeCustomizer = new ThemeCustomizer();
    }
    
})();
