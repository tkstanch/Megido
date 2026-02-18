# NoSQLAttackerGUI Component

A comprehensive, cross-platform GUI component for generating and managing various injection attack payloads including SQL, NoSQL (MongoDB), XPath, and LDAP injection attacks.

## Features

✨ **Key Capabilities:**
- **Multi-Type Injection Support**: SQL, NoSQL (MongoDB), XPath, and LDAP
- **Extensive Payload Library**: Pre-built payloads organized by category (Authentication Bypass, Data Extraction, Blind Injection, Advanced)
- **Interactive Payload Editor**: Custom payload creation and editing with syntax highlighting support
- **Auto-Fill Functionality**: Quick example payloads for each injection type
- **Real-time Execution**: Test payloads against target URLs with response logging
- **Dark/Light Mode**: Automatic theme detection with manual toggle
- **Copy to Clipboard**: Quick payload copying for use in other tools
- **Response Logging**: Track all attack attempts with timestamps and detailed results
- **Tailwind CSS Styling**: Matches Megido's modern UI design system

## Installation

### Prerequisites

```bash
# Ensure you have Node.js and npm installed
node --version  # Should be v16 or higher
npm --version   # Should be v8 or higher
```

### Install Dependencies

```bash
# Install React and TypeScript dependencies
npm install react react-dom
npm install --save-dev @types/react @types/react-dom typescript

# Or using yarn
yarn add react react-dom
yarn add -D @types/react @types/react-dom typescript
```

### TypeScript Configuration

Create or update `tsconfig.json` in your project root:

```json
{
  "compilerOptions": {
    "target": "ES2020",
    "lib": ["ES2020", "DOM", "DOM.Iterable"],
    "jsx": "react-jsx",
    "module": "ESNext",
    "moduleResolution": "node",
    "resolveJsonModule": true,
    "allowJs": true,
    "checkJs": false,
    "outDir": "./dist",
    "esModuleInterop": true,
    "forceConsistentCasingInFileNames": true,
    "strict": true,
    "skipLibCheck": true,
    "allowSyntheticDefaultImports": true
  },
  "include": ["sqli_web/frontend/**/*"],
  "exclude": ["node_modules", "dist"]
}
```

## Usage

### Basic Integration

```tsx
import React from 'react';
import ReactDOM from 'react-dom/client';
import NoSQLAttackerGUI from './sqli_web/frontend/components/NoSQLAttackerGUI';

// Render in your application
const root = ReactDOM.createRoot(document.getElementById('root')!);
root.render(
  <React.StrictMode>
    <NoSQLAttackerGUI />
  </React.StrictMode>
);
```

### Integration with Django Templates

Add to your Django template (e.g., `templates/injection_console.html`):

```html
{% extends 'base.html' %}

{% block content %}
<div id="nosql-attacker-root"></div>

<!-- Load React -->
<script crossorigin src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
<script crossorigin src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>

<!-- Load compiled component -->
<script src="{% static 'js/NoSQLAttackerGUI.bundle.js' %}"></script>
{% endblock %}
```

### Build for Production

```bash
# Using webpack or your preferred bundler
npx webpack --config webpack.config.js

# Or using vite
npx vite build

# Or using create-react-app
npm run build
```

## Backend Integration

### API Endpoint Specification

The component expects a backend API endpoint at `/api/nosqli/attack/` that accepts POST requests:

**Request Format:**
```json
{
  "type": "SQL" | "NoSQL" | "XPath" | "LDAP",
  "payload": "string",
  "target": "string"
}
```

**Response Format:**
```json
{
  "success": boolean,
  "result": "string",
  "data": {
    "type": "string",
    "payload": "string",
    "target": "string",
    "recordsFound": number
  }
}
```

### Example Django View

```python
# In your Django views.py
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
import json

@csrf_exempt
@require_http_methods(["POST"])
def nosqli_attack(request):
    try:
        data = json.loads(request.body)
        injection_type = data.get('type')
        payload = data.get('payload')
        target = data.get('target')
        
        # Your attack logic here
        # WARNING: Implement proper authorization and validation
        
        result = execute_injection_attack(injection_type, payload, target)
        
        return JsonResponse({
            'success': True,
            'result': f'Attack executed successfully. Found {result["count"]} records.',
            'data': {
                'type': injection_type,
                'payload': payload,
                'target': target,
                'recordsFound': result['count']
            }
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'result': f'Error: {str(e)}'
        }, status=500)

# In your urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('api/nosqli/attack/', views.nosqli_attack, name='nosqli_attack'),
]
```

### Mock Mode for Testing

The component includes built-in mock mode for testing without a backend. To enable:

```typescript
// In NoSQLAttackerGUI.tsx, line ~383
const useMockData = true; // Set to false when backend is available
```

## Payload Libraries

The component includes comprehensive payload libraries for each injection type:

### SQL Injection (8 payloads)
- Basic OR Bypass
- Union Select
- Time-Based Blind
- Boolean Blind
- Comment Out
- Stacked Queries
- Error-Based
- Second Order

### NoSQL Injection (8 payloads)
- MongoDB Auth Bypass (`$ne` operator)
- MongoDB OR Injection
- MongoDB Regex Injection
- MongoDB GT Injection
- MongoDB Where Injection
- MongoDB NE Array
- MongoDB Exists
- MongoDB Nin

### XPath Injection (8 payloads)
- Basic OR Bypass
- Parent Node Injection
- Comment Injection
- Node Selection
- Substring Extraction
- String Length
- Count Nodes
- Blind Boolean

### LDAP Injection (8 payloads)
- Basic Wildcard
- OR Injection
- AND Bypass
- Wildcard User
- Empty Password
- NOT Filter
- Attribute Injection
- Group Extraction

## Customization

### Adding New Payloads

Edit the `PAYLOAD_LIBRARIES` constant in `NoSQLAttackerGUI.tsx`:

```typescript
const PAYLOAD_LIBRARIES: Record<InjectionType, Payload[]> = {
  SQL: [
    // Add your custom SQL payloads
    { 
      name: 'Custom Payload', 
      value: "' OR 1=1--", 
      description: 'Your description',
      category: 'Authentication Bypass'
    },
  ],
  // ... other types
};
```

### Styling Customization

The component uses Tailwind CSS classes from Megido's configuration. Key style properties:

- Primary colors: `primary-500`, `primary-600`
- Dark mode: `dark:` prefix for all dark mode styles
- Glass effect: `glass-strong` custom class
- Shadows: `shadow-premium`, `shadow-lg`

### Theme Customization

The component automatically detects the system theme preference and provides a toggle button. The theme state is managed internally but can be controlled externally:

```typescript
// Pass initial theme as prop (requires component modification)
<NoSQLAttackerGUI initialTheme="dark" />
```

## Security Considerations

⚠️ **Important Security Notes:**

1. **Authorization Required**: Always implement proper authorization before allowing injection testing
2. **Rate Limiting**: Implement rate limiting on the backend API endpoint
3. **Logging**: Log all attack attempts for security monitoring
4. **Validation**: Validate and sanitize all inputs on the backend
5. **Scope Limitation**: Restrict testing to authorized targets only
6. **Legal Compliance**: Ensure compliance with applicable laws and regulations

### Recommended Security Measures

```python
# Example Django security middleware
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from ratelimit.decorators import ratelimit

@method_decorator(never_cache, name='dispatch')
@method_decorator(ratelimit(key='ip', rate='10/m'), name='dispatch')
class InjectionAttackView(View):
    def dispatch(self, request, *args, **kwargs):
        # Check if user is authenticated and authorized
        if not request.user.is_authenticated:
            return JsonResponse({'error': 'Unauthorized'}, status=401)
        
        if not request.user.has_perm('security.can_test_injection'):
            return JsonResponse({'error': 'Forbidden'}, status=403)
        
        return super().dispatch(request, *args, **kwargs)
```

## Testing

### Manual Testing

1. Open the component in a browser
2. Select an injection type (SQL, NoSQL, XPath, or LDAP)
3. Choose a payload from the library or enter a custom one
4. Enter a target URL (use a test environment!)
5. Click "Execute Attack"
6. Review the response in the log area

### Automated Testing

Create test files using Jest and React Testing Library:

```typescript
// NoSQLAttackerGUI.test.tsx
import { render, screen, fireEvent } from '@testing-library/react';
import NoSQLAttackerGUI from './NoSQLAttackerGUI';

describe('NoSQLAttackerGUI', () => {
  test('renders component with all tabs', () => {
    render(<NoSQLAttackerGUI />);
    expect(screen.getByText('SQL')).toBeInTheDocument();
    expect(screen.getByText('NoSQL')).toBeInTheDocument();
    expect(screen.getByText('XPath')).toBeInTheDocument();
    expect(screen.getByText('LDAP')).toBeInTheDocument();
  });

  test('switches between injection types', () => {
    render(<NoSQLAttackerGUI />);
    const xpathTab = screen.getByText('XPath');
    fireEvent.click(xpathTab);
    expect(screen.getByText('Basic OR Bypass')).toBeInTheDocument();
  });
});
```

## Troubleshooting

### Common Issues

**Issue**: Component styles not rendering correctly
- **Solution**: Ensure Tailwind CSS is properly configured and the output CSS includes the necessary utility classes

**Issue**: TypeScript compilation errors
- **Solution**: Check that all type definitions are installed: `npm install --save-dev @types/react @types/react-dom`

**Issue**: API calls failing
- **Solution**: Check CORS settings on your backend and ensure the API endpoint is accessible

**Issue**: Dark mode not working
- **Solution**: Verify that Tailwind's dark mode is configured in `tailwind.config.js`:
  ```js
  module.exports = {
    darkMode: 'class',
    // ... rest of config
  }
  ```

## Browser Compatibility

- Chrome/Edge 90+
- Firefox 88+
- Safari 14+
- Opera 76+

## Performance Optimization

The component is optimized for performance:
- Uses React hooks for efficient state management
- Implements lazy loading for payload libraries
- Minimal re-renders with proper dependency arrays
- Efficient DOM updates with React's virtual DOM

## Roadmap

Future enhancements planned:
- [ ] Syntax highlighting for payload editor
- [ ] Export/import payload libraries
- [ ] Batch payload testing
- [ ] Advanced filtering and search in payload library
- [ ] Payload effectiveness scoring
- [ ] Integration with popular security testing tools
- [ ] Real-time collaborative testing features

## Contributing

Contributions are welcome! Please follow these guidelines:
1. Fork the repository
2. Create a feature branch
3. Make your changes with proper documentation
4. Add tests for new functionality
5. Submit a pull request

## License

This component is part of the Megido Security Platform.
For educational and authorized security testing purposes only.

## Support

For issues, questions, or contributions:
- GitHub Issues: https://github.com/tkstanch/Megido/issues
- Documentation: See project README.md

## Changelog

### Version 1.0.0 (Initial Release)
- Tab-based injection type selector (SQL, NoSQL, XPath, LDAP)
- 32 pre-built payloads across all types
- Custom payload editor with copy functionality
- Auto-fill with example payloads
- Response logging with timestamps
- Dark/Light mode support
- Tailwind CSS integration matching Megido UI
- Mock mode for testing without backend
- Comprehensive JSDoc documentation

---

**Remember**: This tool is for authorized security testing only. Always obtain proper authorization before testing any system.
