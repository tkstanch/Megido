# NoSQLAttackerGUI Integration Guide

## Quick Start

This guide provides step-by-step instructions for integrating the NoSQLAttackerGUI component into the Megido web application.

## Prerequisites

Ensure you have the following installed:
- Node.js v16 or higher
- npm v8 or higher
- Python 3.8+ (for Django backend)

## Installation Steps

### 1. Install Node Dependencies

From the Megido root directory:

```bash
npm install
```

This will install all dependencies including:
- React and React-DOM
- TypeScript
- Webpack and loaders
- Type definitions

### 2. Build the Component

#### Option A: Build Only TypeScript Component
```bash
npm run build:tsx
```

#### Option B: Build Everything (CSS + TSX)
```bash
npm run build:all
```

This compiles the TypeScript React component to JavaScript and outputs it to `static/js/dist/NoSQLAttackerGUI.bundle.js`.

### 3. Create Django View

Add a new view in your Django application (e.g., `sqli_web/app.py` or create a new views file):

```python
from flask import render_template

@app.route('/injection-console')
def injection_console():
    return render_template('injection_console.html')
```

### 4. Create Django Template

Create `templates/injection_console.html`:

```html
{% extends 'base.html' %}

{% block title %}Injection Attack Console - Megido{% endblock %}

{% block content %}
<div id="nosql-attacker-root"></div>

<!-- React -->
<script crossorigin src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
<script crossorigin src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>

<!-- Compiled Component -->
<script src="{{ url_for('static', filename='js/dist/NoSQLAttackerGUI.bundle.js') }}"></script>

<!-- Mount Component -->
<script>
  const root = ReactDOM.createRoot(document.getElementById('nosql-attacker-root'));
  root.render(React.createElement(NoSQLAttackerGUI.default));
</script>
{% endblock %}
```

### 5. Add Backend API Endpoint (Optional)

If you want live attack functionality, create an API endpoint:

```python
from flask import request, jsonify

@app.route('/api/nosqli/attack/', methods=['POST'])
def nosqli_attack():
    """
    Execute injection attack
    WARNING: Implement proper authorization and validation!
    """
    if not request.is_json:
        return jsonify({'error': 'Content-Type must be application/json'}), 400
    
    data = request.get_json()
    injection_type = data.get('type')
    payload = data.get('payload')
    target = data.get('target')
    
    # TODO: Implement your attack logic here
    # This is just a mock response
    return jsonify({
        'success': True,
        'result': f'Mock response: {injection_type} injection executed',
        'data': {
            'type': injection_type,
            'payload': payload,
            'target': target,
            'recordsFound': 5
        }
    })
```

### 6. Add Navigation Link

Update your sidebar navigation in `templates/base.html`:

```html
<a href="/injection-console" class="group flex items-center gap-3 px-3 py-3 text-sm font-medium rounded-xl transition-all duration-200 {% if '/injection-console' in request.path %}bg-gradient-to-r from-primary-500 to-primary-600 text-white shadow-lg shadow-primary-500/30{% else %}text-gray-700 dark:text-gray-300 hover:bg-white/60 dark:hover:bg-gray-800/60 hover:shadow-md{% endif %}">
    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4" />
    </svg>
    <span>Injection Console</span>
</a>
```

## Development Workflow

### Watch Mode for CSS

Keep CSS building in watch mode during development:

```bash
npm run watch:css
```

### Rebuild Component After Changes

After modifying the TypeScript component:

```bash
npm run build:tsx
```

### Full Rebuild

To rebuild everything from scratch:

```bash
npm run build:all
```

## Testing

### Manual Testing

1. Start your Flask/Django development server:
   ```bash
   python launch.py
   # or
   python app.py
   ```

2. Navigate to `http://localhost:5000/injection-console` (or your configured port)

3. Test the component:
   - Switch between injection types
   - Select payloads from the library
   - Enter a target URL
   - Execute attacks (will use mock data by default)

### Mock vs. Live Mode

The component includes a mock mode toggle. To switch modes, edit line 383 in `NoSQLAttackerGUI.tsx`:

```typescript
const useMockData = false; // Change to false for live API calls
```

Then rebuild:
```bash
npm run build:tsx
```

## Customization

### Adding Custom Payloads

Edit `sqli_web/frontend/components/NoSQLAttackerGUI.tsx` and modify the `PAYLOAD_LIBRARIES` constant:

```typescript
const PAYLOAD_LIBRARIES: Record<InjectionType, Payload[]> = {
  NoSQL: [
    // Add your custom payload here
    { 
      name: 'My Custom Payload', 
      value: '{"username": {"$custom": "value"}}', 
      description: 'Custom MongoDB injection',
      category: 'Custom Category'
    },
    // ... existing payloads
  ],
  // ... other types
};
```

### Styling Customization

The component uses Tailwind CSS classes. To customize colors or styling:

1. Edit `tailwind.config.js` to add or modify colors
2. Rebuild CSS: `npm run build:css`
3. Modify component classes in `NoSQLAttackerGUI.tsx`
4. Rebuild component: `npm run build:tsx`

## Troubleshooting

### Build Errors

**TypeScript errors:**
```bash
# Check TypeScript configuration
npx tsc --project sqli_web/frontend/tsconfig.json --noEmit
```

**Webpack errors:**
```bash
# Run webpack with verbose output
npx webpack --config webpack.config.js --display-error-details
```

### Runtime Errors

**React not found:**
- Ensure React CDN scripts are loaded before the component bundle
- Check browser console for loading errors

**Component not rendering:**
- Verify the root element exists: `<div id="nosql-attacker-root"></div>`
- Check browser console for JavaScript errors
- Ensure the bundle file is accessible: `/static/js/dist/NoSQLAttackerGUI.bundle.js`

**Styles not applied:**
- Verify Tailwind CSS is built: `npm run build:css`
- Check that `tailwind.output.css` is loaded in your template
- Ensure dark mode is configured if using dark theme

### API Issues

**CORS errors:**
```python
# Add CORS headers to your Flask app
from flask_cors import CORS
CORS(app, resources={r"/api/*": {"origins": "*"}})
```

**404 on API endpoint:**
- Verify the route is registered
- Check the URL path matches the component's fetch call
- Look at server logs for routing issues

## Production Deployment

### Build for Production

```bash
# Build optimized production assets
NODE_ENV=production npm run build:all
```

### Security Considerations

1. **Enable CSRF Protection:**
   ```python
   from flask_wtf.csrf import CSRFProtect
   csrf = CSRFProtect(app)
   ```

2. **Add Rate Limiting:**
   ```python
   from flask_limiter import Limiter
   limiter = Limiter(app, key_func=get_remote_address)
   
   @app.route('/api/nosqli/attack/', methods=['POST'])
   @limiter.limit("10 per minute")
   def nosqli_attack():
       # ...
   ```

3. **Implement Authorization:**
   ```python
   from flask_login import login_required, current_user
   
   @app.route('/api/nosqli/attack/', methods=['POST'])
   @login_required
   def nosqli_attack():
       if not current_user.has_permission('injection_testing'):
           return jsonify({'error': 'Unauthorized'}), 403
       # ...
   ```

4. **Log All Attempts:**
   ```python
   import logging
   logger = logging.getLogger(__name__)
   
   @app.route('/api/nosqli/attack/', methods=['POST'])
   def nosqli_attack():
       logger.info(f"Injection attack initiated by {current_user.username}")
       # ...
   ```

### Performance Optimization

1. **Enable Gzip Compression:**
   ```python
   from flask_compress import Compress
   Compress(app)
   ```

2. **Cache Static Assets:**
   - Configure your web server (nginx/apache) to cache static files
   - Use versioned filenames for cache busting

3. **Minification:**
   - The webpack config already minifies JavaScript
   - Ensure CSS is minified: `npm run build:css` uses `--minify` flag

## Next Steps

- [ ] Customize payloads for your use case
- [ ] Implement backend API endpoint
- [ ] Add authentication and authorization
- [ ] Set up logging and monitoring
- [ ] Configure rate limiting
- [ ] Add unit tests
- [ ] Deploy to production

## Support

For issues or questions:
- Check the main README: `sqli_web/frontend/components/README.md`
- Review component documentation (JSDoc comments in source)
- File an issue on GitHub: https://github.com/tkstanch/Megido/issues

## Additional Resources

- [React Documentation](https://react.dev/)
- [TypeScript Documentation](https://www.typescriptlang.org/)
- [Tailwind CSS Documentation](https://tailwindcss.com/)
- [Webpack Documentation](https://webpack.js.org/)
- [OWASP Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)
