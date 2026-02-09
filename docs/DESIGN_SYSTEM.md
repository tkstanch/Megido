# Megido Security - Design System

## Overview

The Megido Security Platform uses a modern, professional design system built with CSS Custom Properties (variables) for easy theming and maintainability.

## 🎨 Color Palette

### Primary Colors
```css
--primary-500: #667eea  /* Main brand color */
--primary-600: #5568d3  /* Hover state */
--primary-700: #4553b8  /* Active state */
```

### Gradients
```css
--gradient-primary: linear-gradient(135deg, #667eea 0%, #764ba2 100%)
--gradient-success: linear-gradient(135deg, #10b981 0%, #059669 100%)
--gradient-danger: linear-gradient(135deg, #ef4444 0%, #dc2626 100%)
--gradient-warning: linear-gradient(135deg, #f59e0b 0%, #d97706 100%)
--gradient-info: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%)
```

### Semantic Colors
```css
--success: #10b981  /* Green for positive actions */
--warning: #f59e0b  /* Orange for warnings */
--danger: #ef4444   /* Red for errors/critical */
--info: #3b82f6     /* Blue for information */
```

### Severity Colors (Security Context)
```css
--severity-critical: #dc2626  /* Critical vulnerabilities */
--severity-high: #ea580c      /* High severity */
--severity-medium: #f59e0b    /* Medium severity */
--severity-low: #10b981       /* Low severity */
```

### Neutral Colors (Light Mode)
```css
--gray-50: #f9fafb   /* Lightest gray */
--gray-100: #f3f4f6  /* Very light gray */
--gray-200: #e5e7eb  /* Light gray */
--gray-300: #d1d5db  /* Medium-light gray */
--gray-500: #6b7280  /* Medium gray */
--gray-700: #374151  /* Dark gray */
--gray-900: #111827  /* Darkest gray */
```

### Background & Surface
```css
--bg-primary: #ffffff     /* Main background */
--bg-secondary: #f9fafb   /* Secondary background */
--surface: #ffffff        /* Card/panel background */
```

### Text Colors
```css
--text-primary: #111827    /* Primary text */
--text-secondary: #6b7280  /* Secondary text */
--text-tertiary: #9ca3af   /* Tertiary/disabled text */
--text-inverse: #ffffff    /* Text on dark backgrounds */
```

## 🌙 Dark Mode

Dark mode automatically switches colors when `data-theme="dark"` is set on the `<html>` element.

### Usage
```javascript
// Toggle dark mode
MegidoUtils.Theme.toggleTheme();

// Set specific theme
MegidoUtils.Theme.setTheme('dark');
MegidoUtils.Theme.setTheme('light');

// Get current theme
const theme = MegidoUtils.Theme.getTheme(); // 'dark' or 'light'
```

### Dark Mode Colors
All color variables adapt automatically in dark mode:
```css
[data-theme="dark"] {
    --bg-primary: #111827;
    --bg-secondary: #1f2937;
    --surface: #1f2937;
    --text-primary: #f9fafb;
    --text-secondary: #d1d5db;
    /* ... */
}
```

## 📐 Layout System

### Sidebar Navigation
```css
--sidebar-width: 260px
```

Fixed sidebar with organized sections:
- Core Tools
- Attack Tools
- Proxy & Analysis
- Advanced Tools
- System

### Topbar Header
```css
--topbar-height: 64px
```

Sticky topbar with:
- Menu toggle (mobile)
- Breadcrumb navigation
- Theme toggle
- User actions

### Content Area
```css
.page-content {
    padding: 2rem;
}
```

### Grid System
```html
<div class="grid grid-cols-4">
    <!-- 4 columns on desktop, responsive on mobile -->
</div>
```

Available classes:
- `.grid-cols-1` - 1 column
- `.grid-cols-2` - 2 columns
- `.grid-cols-3` - 3 columns
- `.grid-cols-4` - 4 columns

## 🧱 Components

### Cards
```html
<div class="card">
    <div class="card-header">
        <h3 class="card-title">Title</h3>
    </div>
    <div class="card-body">
        Content here
    </div>
    <div class="card-footer">
        Footer content
    </div>
</div>
```

**Variants:**
```html
<div class="card card-gradient">
    <!-- Gradient background card -->
</div>
```

### Stat Cards
```html
<div class="stat-card stat-card-primary">
    <div class="stat-card-header">
        <div>
            <div class="stat-card-value">42</div>
            <div class="stat-card-label">Active Scans</div>
        </div>
        <div class="stat-card-icon">🔍</div>
    </div>
</div>
```

**Variants:**
- `.stat-card-primary` - Blue gradient
- `.stat-card-success` - Green gradient
- `.stat-card-danger` - Red gradient
- `.stat-card-warning` - Orange gradient
- `.stat-card-info` - Info blue gradient

### Buttons
```html
<button class="btn btn-primary">Primary Action</button>
<button class="btn btn-secondary">Secondary</button>
<button class="btn btn-success">Success</button>
<button class="btn btn-danger">Danger</button>
<button class="btn btn-warning">Warning</button>
<button class="btn btn-outline">Outline</button>
```

**Sizes:**
```html
<button class="btn btn-primary btn-sm">Small</button>
<button class="btn btn-primary">Normal</button>
<button class="btn btn-primary btn-lg">Large</button>
```

### Badges
```html
<span class="badge badge-primary">Primary</span>
<span class="badge badge-success">Success</span>
<span class="badge badge-danger">Danger</span>
<span class="badge badge-warning">Warning</span>
<span class="badge badge-info">Info</span>
<span class="badge badge-gray">Gray</span>
```

**Severity Badges:**
```html
<span class="badge badge-critical">Critical</span>
<span class="badge badge-high">High</span>
<span class="badge badge-medium">Medium</span>
<span class="badge badge-low">Low</span>
```

### Forms
```html
<div class="form-group">
    <label class="form-label">Field Label</label>
    <input type="text" class="form-input" placeholder="Placeholder">
    <small class="form-help">Helper text</small>
</div>

<div class="form-group">
    <label class="form-label">Select Field</label>
    <select class="form-select">
        <option>Option 1</option>
        <option>Option 2</option>
    </select>
</div>

<div class="form-group">
    <label class="form-label">Textarea</label>
    <textarea class="form-textarea"></textarea>
</div>
```

**Search Input:**
```html
<div class="search-wrapper">
    <span class="search-icon">🔍</span>
    <input type="text" class="form-input search-input" placeholder="Search...">
</div>
```

### Tables
```html
<div class="table-wrapper">
    <table class="table">
        <thead>
            <tr>
                <th>Column 1</th>
                <th>Column 2</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td>Data 1</td>
                <td>Data 2</td>
                <td>
                    <button class="btn btn-sm btn-primary">View</button>
                </td>
            </tr>
        </tbody>
    </table>
</div>
```

## 📏 Spacing System

### Margin Utilities
```html
<div class="mt-1">  <!-- margin-top: 0.25rem -->
<div class="mt-2">  <!-- margin-top: 0.5rem -->
<div class="mt-3">  <!-- margin-top: 1rem -->
<div class="mt-4">  <!-- margin-top: 1.5rem -->
<div class="mt-5">  <!-- margin-top: 2rem -->

<div class="mb-1">  <!-- margin-bottom: 0.25rem -->
<div class="mb-2">  <!-- margin-bottom: 0.5rem -->
<!-- ... -->
```

### Padding Utilities
```html
<div class="p-3">  <!-- padding: 1rem -->
<div class="p-4">  <!-- padding: 1.5rem -->
<div class="p-5">  <!-- padding: 2rem -->
```

## 🔤 Typography

### Font Sizes
```html
<span class="text-xs">    <!-- 0.75rem -->
<span class="text-sm">    <!-- 0.875rem -->
<span class="text-base">  <!-- 1rem -->
<span class="text-lg">    <!-- 1.125rem -->
<span class="text-xl">    <!-- 1.25rem -->
<span class="text-2xl">   <!-- 1.5rem -->
```

### Font Weights
```html
<span class="font-semibold">  <!-- 600 -->
<span class="font-bold">      <!-- 700 -->
```

### Text Alignment
```html
<div class="text-center">  <!-- center -->
<div class="text-right">   <!-- right -->
```

## 📱 Responsive Design

### Breakpoints
- **Mobile:** < 768px
- **Tablet:** 768px - 1024px
- **Desktop:** > 1024px

### Responsive Behavior
- Sidebar collapses to mobile menu below 768px
- Grid columns stack on mobile
- Topbar menu button appears on mobile
- Reduced padding on mobile

### Testing Responsive Design
```javascript
// Resize browser window
window.addEventListener('resize', function() {
    if (window.innerWidth <= 768) {
        // Mobile view
    }
});
```

## 🎭 Animations

### CSS Animations
```css
.fade-in {
    animation: fadeIn 250ms ease-in-out;
}

.slide-in-up {
    animation: slideInUp 250ms ease-in-out;
}
```

### Transitions
```css
--transition-fast: 150ms ease-in-out;
--transition-normal: 250ms ease-in-out;
--transition-slow: 350ms ease-in-out;
```

## 🎨 Usage Examples

### Dashboard Page
```html
{% extends 'base.html' %}

{% block breadcrumb %}
<span class="breadcrumb-item">Megido Security</span>
<span class="breadcrumb-separator">›</span>
<span class="breadcrumb-item active">Dashboard</span>
{% endblock %}

{% block content %}
<!-- Stat Cards -->
<div class="grid grid-cols-4">
    <div class="stat-card stat-card-primary">
        <div class="stat-card-header">
            <div>
                <div class="stat-card-value">17</div>
                <div class="stat-card-label">Security Tools</div>
            </div>
            <div class="stat-card-icon">🔧</div>
        </div>
    </div>
    <!-- More stat cards -->
</div>

<!-- Content Cards -->
<div class="grid grid-cols-3 mt-5">
    <div class="card">
        <div class="card-header">
            <h3 class="card-title">Recent Scans</h3>
        </div>
        <div class="card-body">
            <!-- Content -->
        </div>
    </div>
    <!-- More cards -->
</div>
{% endblock %}
```

### Form Page
```html
{% extends 'base.html' %}

{% block content %}
<div class="card">
    <div class="card-header">
        <h3 class="card-title">Start New Scan</h3>
    </div>
    <div class="card-body">
        <form id="scanForm">
            {% csrf_token %}
            
            <div class="form-group">
                <label class="form-label">Target URL:</label>
                <input type="url" class="form-input" required>
            </div>
            
            <button type="submit" class="btn btn-primary">
                🚀 Start Scan
            </button>
        </form>
    </div>
</div>
{% endblock %}
```

## 🚀 Best Practices

1. **Use Semantic Classes:** Use `btn-primary` not `btn-blue`
2. **Consistent Spacing:** Use spacing utilities instead of custom CSS
3. **Mobile First:** Design for mobile, then enhance for desktop
4. **Accessible Colors:** Ensure sufficient contrast (WCAG AA minimum)
5. **Component Reuse:** Use existing components before creating new ones
6. **Theme Variables:** Use CSS custom properties for colors
7. **Responsive Images:** Use responsive images for all screen sizes
8. **Performance:** Minimize CSS/JS bundle size

## 📚 Resources

- **Design Inspiration:** Material Design, Tailwind CSS
- **Icons:** Unicode emoji (no external dependencies)
- **Fonts:** System font stack (performance)
- **Accessibility:** WCAG 2.1 Level AA compliance

---

**Last Updated:** 2026-02-09  
**Version:** 2.0  
**Maintainer:** Megido Security Team
