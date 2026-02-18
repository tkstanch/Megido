# NoSQLAttackerGUI Component - Visual Guide

## Component Overview

The NoSQLAttackerGUI is a comprehensive React component that provides a modern, user-friendly interface for security testing of injection vulnerabilities.

## Component Structure

```
┌─────────────────────────────────────────────────────────────────┐
│  🛡️ Advanced Injection Attack Console              🌙 Theme     │
│  Generate and test injection payloads...                        │
│  ┌───────┬───────┬───────┬───────┐                             │
│  │  SQL  │ NoSQL │ XPath │ LDAP  │  ◄─ Injection Type Tabs    │
│  └───────┴───────┴───────┴───────┘                             │
├─────────────────────────────────────────────────────────────────┤
│ ┌──────────────────┐ ┌──────────────────────────────────────┐ │
│ │ Payload Library  │ │ Payload Editor                       │ │
│ │                  │ │                                      │ │
│ │ Authentication   │ │ 📋 Selected: MongoDB Auth Bypass    │ │
│ │ ▼ Basic OR       │ │ Bypass MongoDB authentication...    │ │
│ │   Union Select   │ │                                      │ │
│ │   Time-Based     │ │ Target URL:                         │ │
│ │                  │ │ [https://target.com/api/...]        │ │
│ │ Data Extraction  │ │                                      │ │
│ │ ▼ Error-Based    │ │ Custom Payload:                     │ │
│ │   Substring      │ │ [{"username": {"$ne": null}}]       │ │
│ │                  │ │                                      │ │
│ │ [32 payloads]    │ │ [Auto-fill] [Clear]                 │ │
│ │                  │ │                                      │ │
│ │                  │ │ [====== Execute Attack ======]      │ │
│ └──────────────────┘ │                                      │ │
│                      │ Response Log                         │ │
│                      │ ┌──────────────────────────────────┐ │ │
│                      │ │ ✓ SUCCESS        12:34:56       │ │ │
│                      │ │ Found 7 matching records        │ │ │
│                      │ │ [View Details ▼]                │ │ │
│                      │ └──────────────────────────────────┘ │ │
│                      └──────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────────┤
│ ⚠️  Security Warning                                           │
│ This tool is for educational and authorized testing only...    │
└─────────────────────────────────────────────────────────────────┘
```

## Color Scheme

### Light Mode
- Background: `bg-gray-50` (Light gray)
- Cards: `bg-white/70` with backdrop blur (Glass effect)
- Primary: `#667eea` (Purple-blue gradient)
- Secondary: `#764ba2` (Deep purple)
- Text: `text-gray-900` (Dark gray)
- Borders: `border-gray-200/50` (Subtle)

### Dark Mode
- Background: `bg-midnight-950` (Deep indigo-black)
- Cards: `bg-gray-900/70` with backdrop blur (Glass effect)
- Primary: `#667eea` (Purple-blue gradient)
- Secondary: `#764ba2` (Deep purple)
- Text: `text-white` (White)
- Borders: `border-gray-700/50` (Subtle)

## Component Features by Section

### 1. Header Section
```
┌─────────────────────────────────────────────┐
│ 🛡️ Advanced Injection Attack Console  🌙    │
│ Generate and test injection payloads...     │
│                                             │
│ [SQL] [NoSQL] [XPath] [LDAP]               │
└─────────────────────────────────────────────┘
```
- **Title**: Large, bold heading with icon
- **Subtitle**: Descriptive text
- **Theme Toggle**: Sun/moon icon for light/dark mode
- **Tabs**: Four injection type selectors with gradient on active

### 2. Payload Library (Left Panel)
```
┌─────────────────────┐
│ Payload Library     │
│ [32 payloads]       │
│                     │
│ AUTHENTICATION...   │
│ ▶ Basic OR Bypass  │
│   Classic auth...   │
│ ▶ MongoDB Auth...  │
│   Bypass using... [📋]│
│                     │
│ DATA EXTRACTION     │
│ ▶ Union Select     │
│   Extract data... [📋]│
└─────────────────────┘
```
- **Categories**: Collapsible payload groups
- **Payload Cards**: Click to select, hover effects
- **Copy Button**: Quick clipboard copy
- **Descriptions**: Tooltip-style descriptions
- **Scrollable**: Max height with custom scrollbar

### 3. Payload Editor (Right Panel - Top)
```
┌──────────────────────────────────┐
│ Payload Editor  [Auto-fill][Clear]│
│                                  │
│ 📋 MongoDB Auth Bypass           │
│ Bypass MongoDB authentication... │
│                                  │
│ Target URL:                      │
│ [https://target.example.com/...] │
│                                  │
│ Custom Payload:                  │
│ ┌──────────────────────────────┐ │
│ │ {"username": {"$ne": null}}  │ │
│ │                              │ │
│ └──────────────────────────────┘ │
│                                  │
│ [====== Execute Attack ======]   │
└──────────────────────────────────┘
```
- **Info Banner**: Shows selected payload details
- **URL Input**: For target specification
- **Payload Textarea**: Monospace font for code
- **Action Buttons**: Auto-fill, Clear, Execute
- **Execute Button**: Large, gradient, with loading state

### 4. Response Log (Right Panel - Bottom)
```
┌──────────────────────────────────┐
│ Response Log      [Clear Log]    │
│                                  │
│ ┌──────────────────────────────┐ │
│ │ ✓ SUCCESS        12:34:56   │ │
│ │ Attack executed successfully │ │
│ │ Found 7 matching records    │ │
│ │ [View Details ▼]            │ │
│ └──────────────────────────────┘ │
│                                  │
│ ┌──────────────────────────────┐ │
│ │ ✗ FAILED         12:33:45   │ │
│ │ Target server returned error │ │
│ │ [View Details ▼]            │ │
│ └──────────────────────────────┘ │
└──────────────────────────────────┘
```
- **Log Entries**: Color-coded by success/failure
- **Timestamps**: Local time format
- **Expandable Details**: JSON data display
- **Scrollable**: Latest entries at top
- **Empty State**: Helpful message when no logs

### 5. Footer Warning
```
┌─────────────────────────────────────┐
│ ⚠️  Security Warning                │
│ This tool is for educational and   │
│ authorized testing purposes only.  │
└─────────────────────────────────────┘
```
- **Warning Icon**: Amber/yellow color
- **Important Notice**: Legal disclaimer
- **Glassmorphism**: Subtle glass effect

## Interaction Flow

### Selecting a Payload
1. User clicks on injection type tab (SQL/NoSQL/XPath/LDAP)
2. Component switches payload library
3. User clicks on a payload from the library
4. Payload is loaded into the editor
5. Info banner shows payload details

### Executing an Attack
1. User enters or selects a payload
2. User enters target URL
3. User clicks "Execute Attack"
4. Button shows loading spinner
5. Request is sent to backend (or mock)
6. Response appears in log area
7. Success/failure indicated with colors and icons

### Using Auto-fill
1. User clicks "Auto-fill Example"
2. First payload from current type is loaded
3. Editor is populated with example
4. User can modify before executing

## Responsive Behavior

### Desktop (1024px+)
- Two-column layout (1:2 ratio)
- Full sidebar always visible
- All features accessible

### Tablet (768px - 1023px)
- Single column layout
- Payload library collapses to dropdown
- Full functionality maintained

### Mobile (< 768px)
- Stacked vertical layout
- Compact controls
- Touch-optimized buttons
- Simplified navigation

## Accessibility Features

- **ARIA Labels**: All interactive elements labeled
- **Keyboard Navigation**: Full keyboard support
- **Focus Indicators**: Visible focus states
- **Color Contrast**: WCAG AA compliant
- **Screen Reader**: Semantic HTML structure

## Animation & Transitions

- **Tab Switching**: 200ms ease transition
- **Card Hover**: Scale and shadow effects
- **Button States**: Smooth color transitions
- **Loading Spinner**: Rotating animation
- **Theme Toggle**: Fade transition

## Technical Highlights

### Performance
- React hooks for efficient re-renders
- Minimal state updates
- Memoization of payload libraries
- Efficient DOM updates

### Code Quality
- TypeScript for type safety
- JSDoc comments throughout
- Consistent naming conventions
- Modular component structure

### Browser Support
- Chrome 90+
- Firefox 88+
- Safari 14+
- Edge 90+

## Extension Points

### Custom Payloads
Add to `PAYLOAD_LIBRARIES` object:
```typescript
NoSQL: [
  {
    name: 'Custom Payload',
    value: '...',
    description: '...',
    category: 'Custom'
  }
]
```

### Custom Styling
Modify Tailwind classes in JSX:
```tsx
className="custom-class bg-primary-500"
```

### Custom API Endpoint
Change fetch URL in `handleExecute`:
```typescript
const apiResponse = await fetch('/custom/endpoint/', {...});
```

### Custom Theme Colors
Update `tailwind.config.js`:
```javascript
colors: {
  primary: {
    500: '#yourcolor',
  }
}
```

## Screenshots Location

When the component is running, take screenshots for:
- Light mode full view
- Dark mode full view
- Each injection type selected
- Response log with multiple entries
- Mobile responsive view

Save screenshots to: `/docs/screenshots/nosql-attacker-gui/`

## Demo Data

The component includes mock mode with simulated responses:
- Success rate: 70%
- Random record counts: 1-10
- Simulated API delay: 1 second
- Realistic error messages

## Future Enhancements

Potential improvements:
- [ ] Syntax highlighting in editor
- [ ] Payload history/favorites
- [ ] Export/import payloads
- [ ] Batch testing mode
- [ ] Advanced filtering
- [ ] Payload effectiveness ratings
- [ ] Integration with other tools
- [ ] Real-time collaboration
