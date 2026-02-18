"""
Flask Web Application for SQL Injection Payload Generation

Web interface for generating SQL injection payloads based on DBMS type,
injection requirement, and context. Provides an interactive UI for selecting
options and displays generated payloads with reference cheat sheets.
"""

from flask import Flask, render_template, request, jsonify
from generate_sql_payloads import SQLPayloadGenerator, generate_payloads, get_cheat_sheet_reference
from sql_syntax_and_errors import SQL_CHEAT_SHEET, get_dbms_list

app = Flask(__name__)

# Configure Flask
app.config['SECRET_KEY'] = 'sql-injection-payload-generator-secret-key'
app.config['TEMPLATES_AUTO_RELOAD'] = True


@app.route('/')
def index():
    """
    Main page - SQL injection payload generator UI
    
    Returns:
        Rendered index.html template with initial data
    """
    dbms_list = get_dbms_list()
    return render_template('index.html', dbms_list=dbms_list)


@app.route('/api/injection-types/<dbms>')
def get_injection_types(dbms):
    """
    API endpoint to get available injection types for a DBMS
    
    Args:
        dbms: Database type (oracle, mysql, mssql)
        
    Returns:
        JSON list of injection types
    """
    try:
        generator = SQLPayloadGenerator(dbms)
        injection_types = generator.get_available_injection_types()
        
        # Format for display
        formatted_types = []
        for inj_type in injection_types:
            dbms_info = SQL_CHEAT_SHEET[dbms]
            type_info = dbms_info.get(inj_type, {})
            formatted_types.append({
                'value': inj_type,
                'label': type_info.get('name', inj_type.replace('_', ' ').title())
            })
        
        return jsonify({
            'success': True,
            'injection_types': formatted_types
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400


@app.route('/api/generate-payload', methods=['POST'])
def generate_payload():
    """
    API endpoint to generate SQL injection payloads
    
    Expected JSON body:
        {
            "dbms": "mysql|oracle|mssql",
            "injection_type": "version_detection|union_injection|...",
            "context": "string|numeric|parenthesis" (optional, generates all if not specified)
        }
        
    Returns:
        JSON with generated payloads and cheat sheet reference
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'error': 'No data provided'
            }), 400
        
        dbms = data.get('dbms')
        injection_type = data.get('injection_type')
        context = data.get('context')
        
        if not dbms or not injection_type:
            return jsonify({
                'success': False,
                'error': 'DBMS and injection_type are required'
            }), 400
        
        # Generate payloads
        payloads = generate_payloads(dbms, injection_type, context)
        
        # Get cheat sheet reference
        cheat_sheet = get_cheat_sheet_reference(dbms, injection_type)
        
        return jsonify({
            'success': True,
            'payloads': payloads if isinstance(payloads, list) else [payloads],
            'cheat_sheet': cheat_sheet,
            'dbms_name': SQL_CHEAT_SHEET[dbms]['name']
        })
        
    except ValueError as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Internal error: {str(e)}'
        }), 500


@app.route('/api/cheat-sheet/<dbms>/<injection_type>')
def get_cheat_sheet(dbms, injection_type):
    """
    API endpoint to get cheat sheet reference for a specific DBMS and injection type
    
    Args:
        dbms: Database type
        injection_type: Injection type
        
    Returns:
        JSON with cheat sheet data
    """
    try:
        cheat_sheet = get_cheat_sheet_reference(dbms, injection_type)
        
        if not cheat_sheet:
            return jsonify({
                'success': False,
                'error': 'Cheat sheet not found'
            }), 404
        
        return jsonify({
            'success': True,
            'cheat_sheet': cheat_sheet,
            'dbms_name': SQL_CHEAT_SHEET[dbms]['name']
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400


@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'SQL Injection Payload Generator'
    })


# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'success': False,
        'error': 'Endpoint not found'
    }), 404


@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        'success': False,
        'error': 'Internal server error'
    }), 500


if __name__ == '__main__':
    print("=" * 60)
    print("SQL Injection Payload Generator - Web UI")
    print("=" * 60)
    print("Starting Flask server...")
    print("Access the web interface at: http://localhost:5000")
    print("=" * 60)
    
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True
    )
