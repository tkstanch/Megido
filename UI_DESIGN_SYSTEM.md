# Megido Security - UI Design System

## Overview

Megido Security uses **Tailwind CSS** as its primary UI framework, providing a modern, professional, and highly accessible user interface. This document outlines the design system, components, and best practices for maintaining and extending the UI.

## Table of Contents

1. [Design Principles](#design-principles)
2. [Color System](#color-system)
3. [Typography](#typography)
4. [Components](#components)
   - [Cards](#cards)
   - [Glassmorphism Cards](#glassmorphism-cards)
   - [Premium Cards](#premium-cards)
   - [Buttons](#buttons)
   - [Badges](#badges)
   - [Forms](#forms)
   - [Tables](#tables)
   - [Empty States](#empty-states)
   - [Hover Effects](#hover-effects)
   - [Alert Components](#alert-components)
   - [Spinner Component](#spinner-component)
   - [Dividers](#dividers)
5. [Shadows](#shadows)
   - [Standard Shadows](#standard-shadows)
   - [Premium Shadows](#premium-shadows)
   - [Glow Shadows](#glow-shadows)
   - [Inner Shadow](#inner-shadow)
6. [Animations](#animations)
   - [Standard Animations](#standard-animations)
   - [Extended Animations](#extended-animations)
   - [Transition Utilities](#transition-utilities)
7. [Background Patterns](#background-patterns)
   - [Dot Pattern](#dot-pattern)
   - [Grid Pattern](#grid-pattern)
8. [Dark Mode](#dark-mode)
9. [Responsive Design](#responsive-design)
10. [Accessibility](#accessibility)
11. [Extending the UI](#extending-the-ui)

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

Megido features a complete color scale from 50-950 for primary and secondary colors:

```css
/* Primary Color Scale (Purple to Blue) */
primary-50:  #f0f4ff  /* Lightest - backgrounds */
primary-100: #e0e9ff  /* Light - hover states */
primary-200: #c7d7fe
primary-300: #a5b8fc
primary-400: #8194f0
primary-500: #667eea  /* Main primary color */
primary-600: #5568d3  /* Active states */
primary-700: #4453b8
primary-800: #363f8e
primary-900: #333d76  /* Darkest - text */
primary-950: #1e2341

/* Secondary Color Scale (Teal) */
secondary-50:  #f0fdfa
secondary-100: #ccfbf1
secondary-200: #99f6e4
secondary-300: #5eead4
secondary-400: #2dd4bf
secondary-500: #14b8a6  /* Main secondary color */
secondary-600: #0d9488
secondary-700: #0f766e
secondary-800: #115e59
secondary-900: #134e4a
secondary-950: #042f2e
```

### Status Colors

Full color scales for all status colors (50-900):

```css
/* Success Color Scale (Green) */
success-50:  #f0fdf4
success-100: #dcfce7
success-200: #bbf7d0
success-300: #86efac
success-400: #4ade80
success-500: #22c55e
success-600: #16a34a
success-700: #15803d
success-800: #166534
success-900: #14532d

/* Warning Color Scale (Amber) */
warning-50:  #fffbeb
warning-100: #fef3c7
warning-200: #fde68a
warning-300: #fcd34d
warning-400: #fbbf24
warning-500: #f59e0b
warning-600: #d97706
warning-700: #b45309
warning-800: #92400e
warning-900: #78350f

/* Danger Color Scale (Red) */
danger-50:  #fef2f2
danger-100: #fee2e2
danger-200: #fecaca
danger-300: #fca5a5
danger-400: #f87171
danger-500: #ef4444
danger-600: #dc2626
danger-700: #b91c1c
danger-800: #991b1b
danger-900: #7f1d1d

/* Info Color Scale (Blue) */
info-50:  #eff6ff
info-100: #dbeafe
info-200: #bfdbfe
info-300: #93c5fd
info-400: #60a5fa
info-500: #3b82f6
info-600: #2563eb
info-700: #1d4ed8
info-800: #1e40af
info-900: #1e3a8a
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

<!-- Mesh Gradient (Multi-directional) -->
<div class="mesh-gradient">
  Complex multi-color gradient overlay
</div>

<!-- Light Gradient (Subtle top-to-bottom) -->
<div class="gradient-light">
  Subtle white to transparent gradient
</div>

<!-- Radial Gradient (Center outward) -->
<div class="gradient-radial bg-primary-500">
  Radial gradient effect
</div>

<!-- Conic Gradient (Circular sweep) -->
<div class="gradient-conic bg-primary-500">
  Conic gradient effect
</div>
```

---

## Typography

### Font Stack

Megido uses modern, highly-readable fonts with Inter as the preferred sans-serif and JetBrains Mono for code:

```css
font-sans: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen', 
           'Ubuntu', 'Cantarell', 'Fira Sans', 'Droid Sans', 'Helvetica Neue', sans-serif

font-mono: 'JetBrains Mono', ui-monospace, SFMono-Regular, Monaco, Consolas, 
           'Liberation Mono', 'Courier New', monospace
```

**Note**: Inter and JetBrains Mono are loaded from Google Fonts for optimal performance and readability.

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

### Glassmorphism Cards

Modern frosted glass effect cards with backdrop blur:

```html
<!-- Basic Glass Card -->
<div class="glass p-6 rounded-xl">
  <h3 class="text-xl font-semibold mb-2">Glass Effect</h3>
  <p>Frosted glass background with subtle transparency</p>
</div>

<!-- Strong Glass Card -->
<div class="glass-strong p-6 rounded-xl">
  <h3 class="text-xl font-semibold mb-2">Strong Glass</h3>
  <p>More opaque glass effect for better contrast</p>
</div>

<!-- Subtle Glass Card -->
<div class="glass-subtle p-6 rounded-xl">
  <h3 class="text-xl font-semibold mb-2">Subtle Glass</h3>
  <p>Very light glass effect for minimal interference</p>
</div>
```

**Use Cases**:
- Overlay panels and modals (`.glass-strong`)
- Feature cards on gradient backgrounds (`.glass`)
- Subtle information panels (`.glass-subtle`)

### Premium Cards

Enhanced cards with special effects and animations:

```html
<!-- Premium Card with Gradient Border -->
<div class="card-premium p-6">
  <h3 class="text-xl font-bold mb-2">Premium Feature</h3>
  <p class="text-gray-600 dark:text-gray-400">
    Card with animated gradient border and premium shadow
  </p>
</div>

<!-- Hover-Enhanced Card -->
<div class="card-hover p-6 rounded-xl bg-white dark:bg-gray-800">
  <h3 class="text-xl font-bold mb-2">Interactive Card</h3>
  <p class="text-gray-600 dark:text-gray-400">
    Lifts up with glow effect on hover
  </p>
</div>
```

**Features**:
- `.card-premium`: Animated gradient border, premium shadow, smooth transitions
- `.card-hover`: Lift animation, scale effect, and glow on hover

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

<!-- Ghost Button (Minimal styling) -->
<button class="btn btn-ghost">Ghost Button</button>

<!-- Icon Button (Square, icon-only) -->
<button class="btn btn-icon btn-primary">
  <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"></path>
  </svg>
</button>

<!-- Button Sizes -->
<button class="btn btn-primary btn-sm">Small</button>
<button class="btn btn-primary">Regular</button>
<button class="btn btn-primary btn-lg">Large</button>

<!-- Button with Icon and Text -->
<button class="btn btn-primary">
  <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"></path>
  </svg>
  Add Item
</button>
```

**New Button Variants**:
- `.btn-ghost`: Transparent background with hover effect, perfect for secondary actions
- `.btn-icon`: Square button optimized for icon-only display

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

Consistent form styling with validation states:

```html
<!-- Basic Form Group -->
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

<!-- Required Field -->
<div class="form-group">
  <label class="form-label form-label-required" for="required-input">
    Required Field
  </label>
  <input 
    type="text" 
    id="required-input" 
    class="form-input" 
    required
  />
</div>

<!-- Input with Error State -->
<div class="form-group">
  <label class="form-label" for="error-input">
    Email Address
  </label>
  <input 
    type="email" 
    id="error-input" 
    class="form-input form-input-error" 
  />
  <span class="form-error">
    Please enter a valid email address
  </span>
</div>

<!-- Input with Success State -->
<div class="form-group">
  <label class="form-label" for="success-input">
    Username
  </label>
  <input 
    type="text" 
    id="success-input" 
    class="form-input form-input-success" 
    value="john_doe"
  />
  <span class="form-success">
    Username is available
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

**Enhanced Form Classes**:
- `.form-label-required`: Adds asterisk (*) indicator for required fields
- `.form-input-error`: Red border and focus ring for error state
- `.form-input-success`: Green border and focus ring for success state
- `.form-error`: Red error message text
- `.form-success`: Green success message text

### Tables

Professional table styling with responsive container and striped rows:

```html
<!-- Basic Table with Container -->
<div class="table-container">
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

<!-- Striped Table -->
<div class="table-container">
  <table class="table table-striped">
    <thead>
      <tr>
        <th>ID</th>
        <th>Name</th>
        <th>Status</th>
        <th>Actions</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td>1</td>
        <td>Item One</td>
        <td><span class="badge badge-success">Active</span></td>
        <td><button class="btn btn-sm btn-primary">View</button></td>
      </tr>
      <tr>
        <td>2</td>
        <td>Item Two</td>
        <td><span class="badge badge-warning">Pending</span></td>
        <td><button class="btn btn-sm btn-primary">View</button></td>
      </tr>
    </tbody>
  </table>
</div>
```

**Enhanced Table Classes**:
- `.table-container`: Wrapper with overflow handling, rounded corners, and borders
- `.table-striped`: Alternating row background colors for better readability

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

### Hover Effects

Interactive hover effects for enhanced user experience:

```html
<!-- Lift Effect -->
<div class="card hover-lift p-6">
  <h3>Hover to Lift</h3>
  <p>Card rises on hover</p>
</div>

<!-- Scale Effect -->
<div class="card hover-scale p-6">
  <h3>Hover to Scale</h3>
  <p>Card scales up slightly</p>
</div>

<!-- Glow Effects -->
<div class="card hover-glow-primary p-6">
  <h3>Primary Glow</h3>
  <p>Purple glow on hover</p>
</div>

<div class="card hover-glow-success p-6">
  <h3>Success Glow</h3>
  <p>Green glow on hover</p>
</div>

<div class="card hover-glow-danger p-6">
  <h3>Danger Glow</h3>
  <p>Red glow on hover</p>
</div>
```

**Available Hover Effects**:
- `.hover-lift`: Transforms Y position upward
- `.hover-scale`: Scales element to 105%
- `.hover-glow-primary`: Adds primary color glow shadow
- `.hover-glow-success`: Adds success color glow shadow
- `.hover-glow-danger`: Adds danger color glow shadow

### Alert Components

Contextual alert boxes for notifications and messages:

```html
<!-- Success Alert -->
<div class="alert alert-success">
  <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
  </svg>
  <div>
    <strong>Success!</strong> Your operation completed successfully.
  </div>
</div>

<!-- Error Alert -->
<div class="alert alert-danger">
  <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
  </svg>
  <div>
    <strong>Error!</strong> Something went wrong. Please try again.
  </div>
</div>

<!-- Warning Alert -->
<div class="alert alert-warning">
  <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
  </svg>
  <div>
    <strong>Warning!</strong> This action cannot be undone.
  </div>
</div>

<!-- Info Alert -->
<div class="alert alert-info">
  <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
  </svg>
  <div>
    <strong>Info:</strong> This is an informational message.
  </div>
</div>
```

**Alert Features**:
- Color-coded backgrounds and borders
- Icon support for visual emphasis
- Flexible content layout
- Dark mode compatible

### Spinner Component

Loading spinner for async operations:

```html
<!-- Basic Spinner -->
<div class="spinner"></div>

<!-- Spinner with Text -->
<div class="flex items-center gap-3">
  <div class="spinner"></div>
  <span>Loading...</span>
</div>

<!-- Colored Spinners -->
<div class="spinner border-primary-500"></div>
<div class="spinner border-success-500"></div>
<div class="spinner border-danger-500"></div>

<!-- Sizes -->
<div class="spinner w-4 h-4"></div>   <!-- Small -->
<div class="spinner w-8 h-8"></div>   <!-- Medium (default) -->
<div class="spinner w-12 h-12"></div> <!-- Large -->
```

### Dividers

Horizontal and vertical dividers for content separation:

```html
<!-- Horizontal Divider -->
<div class="divider"></div>

<!-- Horizontal Divider with Text -->
<div class="divider">OR</div>

<!-- Vertical Divider (in flex container) -->
<div class="flex items-center gap-4">
  <span>Left Content</span>
  <div class="divider-vertical"></div>
  <span>Right Content</span>
</div>
```

**Divider Features**:
- `.divider`: Horizontal line with optional centered text
- `.divider-vertical`: Vertical line for flex layouts
- Responsive to dark mode
- Subtle gray color for minimal interference

---

## Shadows

Megido provides an extensive shadow system for depth and elevation.

### Standard Shadows

Tailwind's default shadow utilities are available:

```html
<div class="shadow-sm">Small shadow</div>
<div class="shadow">Default shadow</div>
<div class="shadow-md">Medium shadow</div>
<div class="shadow-lg">Large shadow</div>
<div class="shadow-xl">Extra large shadow</div>
<div class="shadow-2xl">2XL shadow</div>
```

### Premium Shadows

Enhanced shadows with multiple layers for depth:

```html
<!-- Premium Shadow -->
<div class="card shadow-premium">
  <p>Card with premium multi-layer shadow</p>
</div>

<!-- Large Premium Shadow -->
<div class="card shadow-premium-lg">
  <p>Card with large premium shadow for prominent elements</p>
</div>
```

**Features**:
- Multiple shadow layers for depth
- Subtle color tinting for visual richness
- Optimized for both light and dark modes

### Glow Shadows

Colored glow effects for interactive elements:

```html
<!-- Primary Glow -->
<button class="btn btn-primary shadow-glow-primary">
  Primary Glow Button
</button>

<!-- Success Glow -->
<button class="btn btn-success shadow-glow-success">
  Success Glow Button
</button>

<!-- Danger Glow -->
<button class="btn btn-danger shadow-glow-danger">
  Danger Glow Button
</button>
```

**Use Cases**:
- Call-to-action buttons
- Important notifications
- Interactive cards
- Featured elements

### Inner Shadow

Inset shadow for recessed elements:

```html
<!-- Inner Premium Shadow -->
<div class="bg-gray-100 dark:bg-gray-800 shadow-inner-premium p-6 rounded-lg">
  <p>Content with subtle inner shadow effect</p>
</div>
```

---

## Animations

### Standard Animations

Tailwind includes standard animations:

```html
<!-- Spin -->
<div class="animate-spin">↻</div>

<!-- Ping -->
<div class="animate-ping">●</div>

<!-- Pulse -->
<div class="animate-pulse">◉</div>

<!-- Bounce -->
<div class="animate-bounce">↓</div>
```

### Extended Animations

Additional custom animations for enhanced UI:

```html
<!-- Fade In (Slow) -->
<div class="fade-in-slow">
  Fades in over 1 second
</div>

<!-- Slide In Down -->
<div class="slide-in-down">
  Slides down from top
</div>

<!-- Slide In Left -->
<div class="slide-in-left">
  Slides in from left
</div>

<!-- Scale In -->
<div class="scale-in">
  Scales up from 95% to 100%
</div>

<!-- Bounce Subtle -->
<div class="bounce-subtle">
  Gentle bounce effect
</div>

<!-- Shimmer -->
<div class="shimmer bg-gradient-to-r from-gray-200 via-gray-300 to-gray-200">
  Loading shimmer effect
</div>

<!-- Pulse Slow -->
<div class="pulse-slow">
  Slow pulsing opacity
</div>

<!-- Spin Slow -->
<div class="spin-slow">
  Slow rotation animation
</div>
```

### Animation Timing

Tailwind's duration utilities control animation speed:

```html
<div class="animate-spin duration-1000">1 second</div>
<div class="animate-bounce duration-500">0.5 seconds</div>
```

### Transition Utilities

Smooth transitions for interactive elements:

```html
<!-- Smooth Transition -->
<button class="transition-smooth bg-primary-500 hover:bg-primary-600">
  Smooth color transition
</button>

<!-- Bounce Transition -->
<button class="transition-bounce transform hover:scale-105">
  Bouncy hover effect
</button>
```

**Transition Classes**:
- `.transition-smooth`: All properties with smooth cubic-bezier easing (300ms)
- `.transition-bounce`: Transform with bounce easing (400ms)

### Animation Examples

```html
<!-- Loading Card -->
<div class="card fade-in-slow">
  <div class="flex items-center gap-3">
    <div class="spinner"></div>
    <span>Loading data...</span>
  </div>
</div>

<!-- Notification Slide -->
<div class="alert alert-success slide-in-down">
  Action completed successfully!
</div>

<!-- Interactive Button -->
<button class="btn btn-primary transition-smooth hover-lift hover-glow-primary">
  Click Me
</button>
```

---

## Background Patterns

Subtle patterns for visual interest without overwhelming content.

### Dot Pattern

Grid of subtle dots for texture:

```html
<!-- Light Mode Dots -->
<div class="bg-pattern-dots bg-gray-50 dark:bg-gray-900 p-8">
  <div class="card">
    Content on dot pattern background
  </div>
</div>
```

**Features**:
- Subtle dot grid (8px spacing)
- 2px dot size
- Uses CSS radial-gradient
- Automatically adjusts opacity for dark mode

### Grid Pattern

Subtle grid lines for structure:

```html
<!-- Light Mode Grid -->
<div class="bg-pattern-grid bg-gray-50 dark:bg-gray-900 p-8">
  <div class="card">
    Content on grid pattern background
  </div>
</div>
```

**Features**:
- Grid lines every 20px
- 1px line width
- Uses CSS linear-gradient
- Automatically adjusts opacity for dark mode

### Usage Guidelines

**When to Use Patterns**:
- Large empty sections that need texture
- Background for dashboard layouts
- Hero sections
- Feature showcase areas

**When to Avoid**:
- Behind text-heavy content
- Small containers (< 300px)
- Already busy interfaces

**Best Practices**:
```html
<!-- Good: Pattern with card overlay -->
<section class="bg-pattern-dots bg-gray-50 dark:bg-gray-900 py-12">
  <div class="container mx-auto">
    <div class="card">
      Content is clearly separated from pattern
    </div>
  </div>
</section>

<!-- Avoid: Pattern behind dense text -->
<div class="bg-pattern-grid p-4">
  <p>Long paragraph text...</p> <!-- Hard to read -->
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
