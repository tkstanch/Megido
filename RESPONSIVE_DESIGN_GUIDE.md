# Megido UI - Responsive Design Guide

## Overview

Megido's UI is built with a **mobile-first, fully responsive** approach that ensures perfect display across all device types and screen sizes, from the smallest mobile phones to ultra-wide 4K displays.

---

## Table of Contents

1. [Responsive Breakpoints](#responsive-breakpoints)
2. [Fluid Typography](#fluid-typography)
3. [Responsive Icons](#responsive-icons)
4. [Adaptive Layouts](#adaptive-layouts)
5. [Sidebar Behavior](#sidebar-behavior)
6. [Touch Targets](#touch-targets)
7. [Responsive Utilities](#responsive-utilities)
8. [Testing Guidelines](#testing-guidelines)
9. [Best Practices](#best-practices)

---

## Responsive Breakpoints

Megido uses **9 breakpoints** to cover all screen sizes:

```javascript
const BREAKPOINTS = {
  xs: 375,      // Mobile small (iPhone SE)
  sm: 640,      // Mobile large
  md: 768,      // Tablet portrait
  lg: 1024,     // Tablet landscape / Laptop
  xl: 1280,     // Desktop
  '2xl': 1536,  // Large desktop
  '3xl': 1920,  // Full HD
  '4xl': 2560,  // 4K
  ultra: 3840   // Ultra-wide / 4K
};
```

### Usage in Tailwind Classes

```html
<!-- Mobile: 1 column, Tablet: 2 columns, Desktop: 3 columns -->
<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
  <!-- Cards -->
</div>

<!-- Responsive padding -->
<div class="p-4 md:p-6 lg:p-8">
  <!-- Content -->
</div>

<!-- Responsive text size -->
<h1 class="text-2xl sm:text-3xl md:text-4xl lg:text-5xl">
  Heading
</h1>
```

---

## Fluid Typography

Megido uses **CSS clamp()** for fluid typography that scales smoothly between breakpoints:

### Available Fluid Sizes

| Class | Min Size | Scaling | Max Size | Best For |
|-------|----------|---------|----------|----------|
| `fluid-xs` | 0.75rem | 1vw + 0.5rem | 0.875rem | Small labels |
| `fluid-sm` | 0.875rem | 1vw + 0.6rem | 1rem | Body text (small) |
| `fluid-base` | 1rem | 1.2vw + 0.7rem | 1.125rem | Body text |
| `fluid-lg` | 1.125rem | 1.5vw + 0.8rem | 1.25rem | Large text |
| `fluid-xl` | 1.25rem | 2vw + 0.9rem | 1.5rem | Subheadings |
| `fluid-2xl` | 1.5rem | 2.5vw + 1rem | 2rem | Headings |
| `fluid-3xl` | 1.875rem | 3vw + 1.2rem | 2.5rem | Large headings |
| `fluid-4xl` | 2.25rem | 4vw + 1.5rem | 3rem | Hero text |

### Example

```html
<h1 class="fluid-4xl font-bold">
  Scales from 2.25rem to 3rem
</h1>

<p class="fluid-base">
  Scales from 1rem to 1.125rem
</p>
```

### Benefits

- ✅ **Smooth Scaling**: Text grows continuously, not in steps
- ✅ **Viewport Aware**: Adapts to any screen size
- ✅ **Reduced Media Queries**: Less CSS, more flexible
- ✅ **Better UX**: Optimal readability at all sizes

---

## Responsive Icons

Icons scale with viewport using special classes:

### Icon Classes

```html
<!-- Small responsive icon (1rem to 1.5rem) -->
<svg class="icon-responsive">...</svg>

<!-- Large responsive icon (1.5rem to 2.5rem) -->
<svg class="icon-responsive-lg">...</svg>

<!-- Extra large responsive icon (2rem to 3.5rem) -->
<svg class="icon-responsive-xl">...</svg>
```

### CSS Implementation

```css
.icon-responsive {
  width: clamp(1rem, 2vw + 0.5rem, 1.5rem);
  height: clamp(1rem, 2vw + 0.5rem, 1.5rem);
}

.icon-responsive-lg {
  width: clamp(1.5rem, 3vw + 1rem, 2.5rem);
  height: clamp(1.5rem, 3vw + 1rem, 2.5rem);
}

.icon-responsive-xl {
  width: clamp(2rem, 4vw + 1.5rem, 3.5rem);
  height: clamp(2rem, 4vw + 1.5rem, 3.5rem);
}
```

---

## Adaptive Layouts

### Responsive Grid

The `grid-responsive` class creates self-adjusting grids:

```html
<div class="grid-responsive">
  <!-- Cards automatically adjust columns -->
</div>
```

**CSS:**
```css
.grid-responsive {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(min(100%, 250px), 1fr));
  gap: clamp(1rem, 2vw, 2rem);
}
```

**Behavior:**
- Mobile: 1 column
- Tablet: 2 columns
- Desktop: 3-4 columns (auto-adjusts)

### Responsive Padding

```html
<!-- Scales from 1rem to 2rem -->
<div class="padding-responsive">
  Content
</div>

<!-- Small padding (0.5rem to 1rem) -->
<div class="padding-responsive-sm">
  Content
</div>

<!-- Large padding (1.5rem to 3rem) -->
<div class="padding-responsive-lg">
  Content
</div>
```

### Responsive Gap

```html
<div class="flex gap-responsive">
  <!-- Gap scales from 0.5rem to 1.5rem -->
</div>
```

---

## Sidebar Behavior

The sidebar has **intelligent responsive behavior**:

### Desktop (≥1024px)
- ✅ Always visible on the left
- ✅ Fixed position
- ✅ Width: 16rem (256px)
- ✅ No backdrop

### Mobile/Tablet (<1024px)
- ✅ Hidden by default
- ✅ Slides in from left when toggled
- ✅ Semi-transparent backdrop
- ✅ Close on outside click or ESC key

### JavaScript Control

```javascript
// Check if mobile
if (MegidoResponsive.isMobileOrTablet()) {
  // Mobile-specific code
}

// Get current breakpoint
const breakpoint = MegidoResponsive.getCurrentBreakpoint();
console.log(breakpoint); // 'xs', 'sm', 'md', 'lg', etc.
```

---

## Touch Targets

All interactive elements meet **WCAG 2.1 AA** requirements:

### Minimum Size: 44x44px

```html
<!-- Automatically enforced -->
<button class="btn touch-target">
  Button
</button>

<!-- All buttons have minimum 44x44px -->
<button class="btn btn-primary">
  Primary
</button>
```

### Implementation

The `touch-target` class ensures minimum dimensions:

```css
.touch-target {
  min-width: 44px;
  min-height: 44px;
}
```

JavaScript automatically adds this class on mobile devices for elements that don't meet the requirement.

---

## Responsive Utilities

### Container Responsive

Self-centering container with responsive padding:

```html
<div class="container-responsive">
  <!-- Content with adaptive padding and max-width -->
</div>
```

**CSS:**
```css
.container-responsive {
  width: 100%;
  max-width: min(90%, 1400px);
  margin-left: auto;
  margin-right: auto;
  padding-left: clamp(1rem, 2vw, 2rem);
  padding-right: clamp(1rem, 2vw, 2rem);
}
```

### Viewport Height Fix

Handles mobile browser address bars:

```css
.h-screen-safe {
  height: 100vh;
  height: 100dvh; /* Dynamic viewport height */
}
```

### Hide/Show by Breakpoint

```html
<!-- Hide on mobile, show on desktop -->
<div class="hidden lg:block">
  Desktop only
</div>

<!-- Show on mobile, hide on desktop -->
<div class="block lg:hidden">
  Mobile only
</div>
```

---

## Testing Guidelines

### Required Test Devices/Resolutions

| Device | Width | Test Focus |
|--------|-------|------------|
| iPhone SE | 375px | Compact mobile layout |
| iPhone 12 | 390px | Standard mobile |
| iPhone 12 Pro Max | 428px | Large mobile |
| iPad Mini | 768px | Tablet portrait |
| iPad Pro | 1024px | Tablet landscape |
| Laptop | 1366px | Standard desktop |
| Desktop | 1920px | Full HD |
| 4K Display | 3840px | Ultra-high resolution |
| Ultra-wide | 3440px | Wide aspect ratio |

### Testing Checklist

- [ ] **Typography**: Readable at all sizes
- [ ] **Icons**: Scale proportionally
- [ ] **Touch Targets**: Minimum 44x44px on mobile
- [ ] **Sidebar**: Opens/closes correctly on mobile
- [ ] **Grids**: Adjust columns appropriately
- [ ] **Images**: Don't overflow containers
- [ ] **Navigation**: Accessible on all devices
- [ ] **Forms**: Easy to fill on mobile
- [ ] **Tables**: Scroll horizontally if needed
- [ ] **Buttons**: Not too small or too large

### Browser Testing

Test in:
- ✅ Chrome/Edge (Chromium)
- ✅ Firefox
- ✅ Safari (iOS and macOS)
- ✅ Samsung Internet (Android)

### Tools

- **Browser DevTools**: Device emulation
- **Real Devices**: Physical testing
- **Responsive Design Mode**: Firefox/Chrome
- **BrowserStack**: Cross-browser testing

---

## Best Practices

### 1. Mobile-First Approach

Always design for mobile first, then enhance for larger screens:

```html
<!-- ✅ Good: Mobile base, desktop enhancement -->
<div class="text-base lg:text-lg">
  Text
</div>

<!-- ❌ Bad: Desktop base, mobile override -->
<div class="text-lg max-sm:text-base">
  Text
</div>
```

### 2. Use Fluid Typography

Prefer fluid classes over breakpoint-based sizing:

```html
<!-- ✅ Good: Smooth scaling -->
<h1 class="fluid-4xl">Title</h1>

<!-- ❌ Okay but not ideal: Stepped scaling -->
<h1 class="text-2xl sm:text-3xl md:text-4xl lg:text-5xl">Title</h1>
```

### 3. Flexible Layouts

Use flexible units (%, fr, auto) over fixed pixels:

```css
/* ✅ Good */
.grid {
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
}

/* ❌ Bad */
.grid {
  grid-template-columns: 250px 250px 250px 250px;
}
```

### 4. Touch-Friendly Spacing

Add adequate spacing on mobile:

```html
<div class="flex gap-3 lg:gap-4">
  <!-- Smaller gap on mobile -->
</div>
```

### 5. Optimize Images

Use responsive images:

```html
<img 
  src="image-small.jpg"
  srcset="image-small.jpg 400w, image-medium.jpg 800w, image-large.jpg 1200w"
  sizes="(max-width: 640px) 100vw, (max-width: 1024px) 50vw, 33vw"
  alt="Description"
  class="w-full h-auto"
/>
```

### 6. Test on Real Devices

Emulators are helpful but not perfect. Always test on:
- At least one iOS device
- At least one Android device
- Desktop/laptop

### 7. Performance Matters

- ✅ Lazy load images
- ✅ Defer non-critical JS
- ✅ Minimize CSS
- ✅ Use system fonts when possible

### 8. Accessibility First

- ✅ Semantic HTML
- ✅ ARIA labels
- ✅ Keyboard navigation
- ✅ Color contrast
- ✅ Touch targets

---

## JavaScript Utilities

### Check Viewport

```javascript
// Get current breakpoint
const bp = MegidoResponsive.getCurrentBreakpoint();

// Check if mobile/tablet
if (MegidoResponsive.isMobileOrTablet()) {
  // Mobile code
}

// Check if desktop
if (MegidoResponsive.isDesktop()) {
  // Desktop code
}

// Access breakpoint values
const breakpoints = MegidoResponsive.BREAKPOINTS;
console.log(breakpoints.lg); // 1024
```

### Listen for Changes

```javascript
// Custom event fired on content load
window.addEventListener('megido:contentLoaded', () => {
  // Re-initialize responsive features
});

// Orientation change
window.addEventListener('megido:orientationchange', (e) => {
  console.log('New orientation:', e.detail.orientation);
});
```

---

## Common Patterns

### Responsive Hero Section

```html
<div class="relative padding-responsive">
  <h1 class="fluid-4xl font-bold mb-4">
    Hero Title
  </h1>
  <p class="fluid-lg mb-6">
    Subtitle text
  </p>
  <button class="btn btn-primary touch-target">
    Call to Action
  </button>
</div>
```

### Responsive Card Grid

```html
<div class="grid-responsive gap-6">
  <div class="card">
    <div class="card-body">
      <svg class="icon-responsive-lg mb-4">...</svg>
      <h3 class="fluid-xl font-bold mb-2">Card Title</h3>
      <p class="fluid-sm text-gray-600">Description</p>
    </div>
  </div>
  <!-- More cards -->
</div>
```

### Responsive Navigation

```html
<nav class="flex flex-col lg:flex-row gap-2 lg:gap-4">
  <a href="#" class="touch-target px-4 py-2">Link 1</a>
  <a href="#" class="touch-target px-4 py-2">Link 2</a>
  <a href="#" class="touch-target px-4 py-2">Link 3</a>
</nav>
```

---

## Troubleshooting

### Issue: Text Too Small on Mobile

**Solution:** Use fluid typography classes:
```html
<p class="fluid-base">Text</p>
```

### Issue: Icons Too Large on Desktop

**Solution:** Use responsive icon classes:
```html
<svg class="icon-responsive">...</svg>
```

### Issue: Sidebar Won't Close on Mobile

**Solution:** Check that megido-responsive.js is loaded:
```html
<script src="/static/js/megido-responsive.js"></script>
```

### Issue: Touch Targets Too Small

**Solution:** Add touch-target class:
```html
<button class="btn touch-target">Button</button>
```

### Issue: Layout Breaks at Specific Width

**Solution:** Test at that exact width and adjust breakpoints or use fluid sizing.

---

## Resources

- [Tailwind CSS Responsive Design](https://tailwindcss.com/docs/responsive-design)
- [CSS Clamp() Function](https://developer.mozilla.org/en-US/docs/Web/CSS/clamp)
- [WCAG 2.1 Touch Target Size](https://www.w3.org/WAI/WCAG21/Understanding/target-size.html)
- [Responsive Images](https://developer.mozilla.org/en-US/docs/Learn/HTML/Multimedia_and_embedding/Responsive_images)

---

## Support

For issues or questions about responsive design:

1. Check this guide
2. Review UI_DESIGN_SYSTEM.md
3. Test in browser DevTools
4. Open a GitHub issue with device/browser details

---

**Last Updated:** February 2026  
**Version:** 2.3 Ultra-Responsive
