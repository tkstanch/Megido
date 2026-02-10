# Megido Security - UI Design System

## Overview

Megido Security uses **Tailwind CSS** as its primary UI framework, providing a modern, professional, and highly accessible user interface. This document outlines the design system, components, and best practices for maintaining and extending the UI.

## Table of Contents

1. [Design Principles](#design-principles)
2. [Color System](#color-system)
3. [Typography](#typography)
4. [Components](#components)
5. [Dark Mode](#dark-mode)
6. [Responsive Design](#responsive-design)
7. [Accessibility](#accessibility)
8. [Extending the UI](#extending-the-ui)

---

## Design Principles

The Megido UI follows these core principles:

1. **Security-First Aesthetic**: Deep purple/blue gradients inspired by modern security tools
2. **Professional & Clean**: Minimalist design with clear visual hierarchy
3. **Highly Accessible**: WCAG 2.1 AA compliant with proper contrast ratios
4. **Responsive**: Mobile-first design that works on all screen sizes
5. **Dark Mode Support**: First-class dark mode with seamless transitions

---

## Color System

### Primary Colors

```css
primary-50:  #f0f4ff  /* Lightest - backgrounds */
primary-100: #e0e9ff  /* Light - hover states */
primary-500: #667eea  /* Main primary color */
primary-600: #5568d3  /* Active states */
primary-900: #333d76  /* Darkest - text */
```

### Status Colors

```css
success: #10b981  /* Green - success states */
warning: #f59e0b  /* Amber - warnings */
danger:  #ef4444  /* Red - errors/critical */
info:    #3b82f6  /* Blue - informational */
```

### Severity Colors (Security-Specific)

```css
severity-critical: #dc2626  /* Critical vulnerabilities */
severity-high:     #ea580c  /* High severity */
severity-medium:   #f59e0b  /* Medium severity */
severity-low:      #10b981  /* Low severity */
```

### Gradients

Megido uses signature gradients for visual impact:

```html
<!-- Primary Gradient (Purple to Blue) -->
<div class="bg-gradient-primary">...</div>

<!-- Success Gradient -->
<div class="bg-gradient-success">...</div>

<!-- Danger Gradient -->
<div class="bg-gradient-danger">...</div>
```

---

## Typography

### Font Stack

```css
font-sans: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen', 
           'Ubuntu', 'Cantarell', 'Fira Sans', 'Droid Sans', 'Helvetica Neue', sans-serif

font-mono: ui-monospace, SFMono-Regular, Monaco, Consolas, 'Liberation Mono', 
           'Courier New', monospace
```

### Text Sizes

```html
<!-- Headings -->
<h1 class="text-3xl font-bold">Main Heading</h1>
<h2 class="text-2xl font-semibold">Section Heading</h2>
<h3 class="text-xl font-semibold">Subsection Heading</h3>

<!-- Body Text -->
<p class="text-base">Regular text</p>
<p class="text-sm">Small text</p>
<p class="text-xs">Extra small text</p>
```

---

## Components

### Cards

Cards are the primary container component in Megido:

```html
<!-- Basic Card -->
<div class="card">
  <div class="card-header">
    <h3>Card Title</h3>
  </div>
  <div class="card-body">
    Card content goes here
  </div>
  <div class="card-footer">
    Footer content
  </div>
</div>

<!-- Hover Effect Card -->
<div class="card hover:shadow-card-hover transition-all">
  Content
</div>

<!-- Gradient Card -->
<div class="bg-gradient-primary text-white rounded-xl p-8 shadow-lg">
  Hero content
</div>
```

### Buttons

Megido provides multiple button variants:

```html
<!-- Primary Button -->
<button class="btn btn-primary">Primary Action</button>

<!-- Secondary Button -->
<button class="btn btn-secondary">Secondary Action</button>

<!-- Success Button -->
<button class="btn btn-success">Success Action</button>

<!-- Danger Button -->
<button class="btn btn-danger">Danger Action</button>

<!-- Outline Button -->
<button class="btn btn-outline">Outline Button</button>

<!-- Button Sizes -->
<button class="btn btn-primary btn-sm">Small</button>
<button class="btn btn-primary">Regular</button>
<button class="btn btn-primary btn-lg">Large</button>

<!-- Button with Icon -->
<button class="btn btn-primary">
  <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"></path>
  </svg>
  Add Item
</button>
```

### Badges

For status indicators and labels:

```html
<!-- Status Badges -->
<span class="badge badge-success">Active</span>
<span class="badge badge-warning">Pending</span>
<span class="badge badge-danger">Failed</span>
<span class="badge badge-info">Info</span>

<!-- Severity Badges -->
<span class="badge badge-critical">Critical</span>
<span class="badge badge-high">High</span>
<span class="badge badge-medium">Medium</span>
<span class="badge badge-low">Low</span>

<!-- Badge with Icon -->
<span class="badge badge-success">
  <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
  </svg>
  Verified
</span>
```

### Forms

Consistent form styling:

```html
<div class="form-group">
  <label class="form-label" for="input-id">
    Label Text
  </label>
  <input 
    type="text" 
    id="input-id" 
    class="form-input" 
    placeholder="Enter text"
  />
  <span class="form-help">
    Helper text goes here
  </span>
</div>

<!-- Textarea -->
<textarea class="form-input" rows="4"></textarea>

<!-- Select -->
<select class="form-input">
  <option>Option 1</option>
  <option>Option 2</option>
</select>
```

### Tables

Professional table styling:

```html
<div class="overflow-x-auto rounded-lg border border-gray-200 dark:border-gray-700">
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

### Empty States

User-friendly empty states:

```html
<div class="empty-state">
  <div class="empty-state-icon">📊</div>
  <h3 class="empty-state-title">No Data Available</h3>
  <p class="empty-state-description">
    There are no items to display yet.
  </p>
  <button class="btn btn-primary">Create New Item</button>
</div>
```

---

## Dark Mode

### Implementation

Dark mode is implemented using Tailwind's `dark:` variant and class-based toggling:

```html
<!-- Element that changes in dark mode -->
<div class="bg-white dark:bg-gray-800 text-gray-900 dark:text-white">
  Content adapts to dark mode
</div>

<!-- Dark mode specific styling -->
<div class="border-gray-200 dark:border-gray-700">
  Border color changes
</div>
```

### Toggling Dark Mode

The theme toggle is handled in JavaScript:

```javascript
// Get saved theme or default to light
const savedTheme = localStorage.getItem('theme') || 'light';
if (savedTheme === 'dark') {
  document.documentElement.classList.add('dark');
}

// Toggle function
function toggleTheme() {
  document.documentElement.classList.toggle('dark');
  const newTheme = document.documentElement.classList.contains('dark') ? 'dark' : 'light';
  localStorage.setItem('theme', newTheme);
}
```

### Color Palette Adjustments

Dark mode uses inverted neutral colors:

```
Light Mode          Dark Mode
-----------------------------------------
Background: white   Background: gray-900
Surface: gray-50    Surface: gray-800
Text: gray-900      Text: gray-100
Border: gray-200    Border: gray-700
```

---

## Responsive Design

### Breakpoints

Tailwind's default breakpoints are used:

```css
sm:  640px   /* Small devices */
md:  768px   /* Tablets */
lg:  1024px  /* Laptops */
xl:  1280px  /* Desktops */
2xl: 1536px  /* Large screens */
```

### Mobile-First Approach

Always start with mobile layout and enhance for larger screens:

```html
<!-- Mobile: Stack vertically, Tablet+: 2 columns, Desktop: 3 columns -->
<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
  <div class="card">Card 1</div>
  <div class="card">Card 2</div>
  <div class="card">Card 3</div>
</div>

<!-- Mobile: Hide, Desktop: Show -->
<div class="hidden lg:block">
  Desktop only content
</div>

<!-- Mobile: Show, Desktop: Hide -->
<div class="block lg:hidden">
  Mobile only content
</div>
```

### Sidebar Behavior

The sidebar is responsive:

- **Desktop (≥1024px)**: Always visible on the left
- **Tablet/Mobile (<1024px)**: Hidden by default, slides in when toggled

---

## Accessibility

### Principles

1. **Semantic HTML**: Use proper HTML5 elements (`<nav>`, `<main>`, `<aside>`)
2. **ARIA Labels**: Provide descriptive labels for interactive elements
3. **Keyboard Navigation**: All interactive elements are keyboard accessible
4. **Color Contrast**: Minimum 4.5:1 for normal text, 3:1 for large text
5. **Focus Indicators**: Clear focus states on all interactive elements

### Examples

```html
<!-- Proper ARIA labels -->
<button aria-label="Toggle dark mode" class="btn">
  <svg>...</svg>
</button>

<!-- Navigation with ARIA -->
<nav aria-label="Main navigation">
  <a href="/" aria-label="Dashboard">Dashboard</a>
</nav>

<!-- Form accessibility -->
<label for="email" class="form-label">
  Email Address
</label>
<input 
  id="email" 
  type="email" 
  class="form-input"
  aria-describedby="email-help"
  required
/>
<span id="email-help" class="form-help">
  We'll never share your email
</span>

<!-- Loading states -->
<button aria-busy="true" disabled>
  <span class="sr-only">Loading...</span>
  <svg class="animate-spin">...</svg>
</button>
```

### Screen Reader Only Content

Use the `sr-only` class for screen reader only text:

```html
<span class="sr-only">Loading...</span>
```

---

## Extending the UI

### Adding New Components

1. **Define in Tailwind Config**: Add custom utilities in `tailwind.config.js`

```javascript
theme: {
  extend: {
    colors: {
      'custom-color': '#yourcolor',
    }
  }
}
```

2. **Create Component Classes**: Add to `static/css/tailwind.input.css`

```css
@layer components {
  .your-component {
    @apply bg-white dark:bg-gray-800 rounded-lg shadow-md p-4;
  }
}
```

3. **Rebuild CSS**: Run the build command

```bash
npm run build:css
```

### Creating Template Partials

For reusable UI components, create partial templates:

```django
{# templates/components/stat_card.html #}
<div class="card hover:shadow-card-hover transition-all">
  <div class="card-body">
    <div class="flex items-start gap-3">
      <div class="p-3 {{ icon_bg_class }} rounded-lg">
        {{ icon|safe }}
      </div>
      <div class="flex-1">
        <h3 class="font-semibold text-gray-900 dark:text-white">
          {{ title }}
        </h3>
        <p class="text-sm text-gray-600 dark:text-gray-400">
          {{ description }}
        </p>
      </div>
    </div>
  </div>
</div>
```

Usage:

```django
{% include "components/stat_card.html" with title="Active Users" description="24 online now" icon_bg_class="bg-primary-100" %}
```

### Best Practices

1. **Use Tailwind utilities first**: Before creating custom CSS
2. **Follow naming conventions**: Use `btn-*`, `card-*`, `badge-*` prefixes
3. **Test in both modes**: Always verify light and dark mode
4. **Mobile-first**: Start with mobile layout
5. **Maintain consistency**: Reuse existing patterns and components
6. **Document custom classes**: Add comments for complex utilities

---

## Development Workflow

### Setup

```bash
# Install dependencies
npm install

# Build CSS (production)
npm run build:css

# Watch for changes (development)
npm run watch:css
```

### File Structure

```
├── static/
│   └── css/
│       ├── tailwind.input.css   # Source file
│       └── tailwind.output.css  # Generated (gitignored)
├── templates/
│   ├── base.html                # Base template
│   └── components/              # Reusable components
├── tailwind.config.js           # Tailwind configuration
└── postcss.config.js            # PostCSS configuration
```

### Testing Checklist

Before committing UI changes:

- [ ] Test on Chrome, Firefox, Safari
- [ ] Verify mobile responsiveness (320px, 768px, 1024px)
- [ ] Test light and dark modes
- [ ] Check keyboard navigation
- [ ] Validate color contrast
- [ ] Test with screen reader
- [ ] Verify all interactive elements have focus states

---

## Resources

- [Tailwind CSS Documentation](https://tailwindcss.com/docs)
- [Heroicons](https://heroicons.com/) - Icon library
- [WCAG Guidelines](https://www.w3.org/WAI/WCAG21/quickref/)
- [Color Contrast Checker](https://webaim.org/resources/contrastchecker/)

---

## Support

For questions or issues with the UI system:

1. Check this documentation
2. Review existing templates for examples
3. Consult the Tailwind CSS documentation
4. Open an issue on GitHub with the `ui` label
