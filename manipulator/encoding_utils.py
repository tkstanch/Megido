"""
Utility functions for payload encoding and obfuscation.
Uses only Python's built-in and standard libraries.
"""
import base64
import urllib.parse
import json
import html
import codecs


def url_encode(payload):
    """
    URL encode the payload.
    Example: <script> -> %3Cscript%3E
    """
    return urllib.parse.quote(payload, safe='')


def url_encode_double(payload):
    """
    Double URL encode the payload (for bypass techniques).
    Example: <script> -> %253Cscript%253E
    """
    return urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe='')


def base64_encode(payload):
    """
    Base64 encode the payload.
    Example: <script> -> PHNjcmlwdD4=
    """
    return base64.b64encode(payload.encode('utf-8')).decode('utf-8')


def base64_decode(encoded_payload):
    """
    Base64 decode the payload.
    """
    try:
        return base64.b64decode(encoded_payload).decode('utf-8')
    except Exception:
        return None


def hex_encode(payload):
    """
    Hex encode the payload.
    Example: <script> -> 3c7363726970743e
    """
    return payload.encode('utf-8').hex()


def hex_encode_with_prefix(payload):
    """
    Hex encode with 0x prefix for each character.
    Example: <script> -> 0x3c0x730x630x720x690x700x740x3e
    """
    return ''.join([f'0x{ord(c):02x}' for c in payload])


def unicode_encode(payload):
    """
    Unicode escape encode the payload.
    Example: <script> -> \u003c\u0073\u0063\u0072\u0069\u0070\u0074\u003e
    """
    return payload.encode('unicode-escape').decode('utf-8')


def html_entity_encode(payload):
    """
    HTML entity encode the payload.
    Example: <script> -> &lt;script&gt;
    """
    return html.escape(payload)


def html_entity_encode_numeric(payload):
    """
    HTML numeric entity encode the payload.
    Example: <script> -> &#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;
    """
    return ''.join([f'&#{ord(c)};' for c in payload])


def html_entity_encode_hex(payload):
    """
    HTML hex entity encode the payload.
    Example: <script> -> &#x3c;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3e;
    """
    return ''.join([f'&#x{ord(c):x};' for c in payload])


def octal_encode(payload):
    """
    Octal encode the payload.
    Example: <script> -> \074\163\143\162\151\160\164\076
    """
    return ''.join([f'\\{ord(c):03o}' for c in payload])


def rot13_encode(payload):
    """
    ROT13 encode the payload (simple Caesar cipher).
    Example: alert -> nyreg
    """
    return codecs.encode(payload, 'rot_13')


def mixed_case(payload):
    """
    Alternate case for bypass (for case-insensitive filters).
    Example: <script> -> <ScRiPt>
    """
    result = []
    for i, char in enumerate(payload):
        if i % 2 == 0:
            result.append(char.upper())
        else:
            result.append(char.lower())
    return ''.join(result)


def reverse_encode(payload):
    """
    Reverse the payload string (useful for some bypass scenarios).
    Example: <script> -> >tpircs<
    """
    return payload[::-1]


def null_byte_injection(payload):
    """
    Add null bytes for bypass techniques.
    Example: <script> -> <scri\x00pt>
    """
    # Insert null byte in middle
    mid = len(payload) // 2
    return payload[:mid] + '\x00' + payload[mid:]


def comment_obfuscation_sql(payload):
    """
    Add SQL comments for obfuscation.
    Example: UNION SELECT -> UN/**/ION/**/SEL/**/ECT
    """
    words = payload.split()
    return '/**/'.join(words)


def space_to_comment_sql(payload):
    """
    Replace spaces with SQL comments.
    Example: UNION SELECT -> UNION/**/SELECT
    """
    return payload.replace(' ', '/**/')


def space_to_plus(payload):
    """
    Replace spaces with plus signs (URL encoding style).
    Example: UNION SELECT -> UNION+SELECT
    """
    return payload.replace(' ', '+')


def space_to_tab(payload):
    """
    Replace spaces with tabs.
    """
    return payload.replace(' ', '\t')


def slash_obfuscation(payload):
    """
    Add slashes for path traversal obfuscation.
    Example: ../etc -> ..%2fetc
    """
    return payload.replace('/', '%2f')


def double_slash_obfuscation(payload):
    """
    Double encode slashes for bypass.
    Example: ../etc -> ..%252fetc
    """
    return payload.replace('/', '%252f')


def backslash_to_forward(payload):
    """
    Convert backslashes to forward slashes.
    Example: ..\etc -> ../etc
    """
    return payload.replace('\\', '/')


def char_code_obfuscation_js(payload):
    """
    Convert to JavaScript String.fromCharCode().
    Example: alert -> String.fromCharCode(97,108,101,114,116)
    """
    char_codes = ','.join([str(ord(c)) for c in payload])
    return f'String.fromCharCode({char_codes})'


def unicode_escape_js(payload):
    """
    Unicode escape for JavaScript.
    Example: <script> -> \u003cscript\u003e
    """
    return ''.join([f'\\u{ord(c):04x}' for c in payload])


def apply_encoding(payload, encoding_name):
    """
    Apply a specific encoding to a payload by name.
    Returns tuple: (encoded_payload, success, error_message)
    """
    encoding_functions = {
        'url': url_encode,
        'url_double': url_encode_double,
        'base64': base64_encode,
        'hex': hex_encode,
        'hex_prefix': hex_encode_with_prefix,
        'unicode': unicode_encode,
        'html_entity': html_entity_encode,
        'html_numeric': html_entity_encode_numeric,
        'html_hex': html_entity_encode_hex,
        'octal': octal_encode,
        'rot13': rot13_encode,
        'mixed_case': mixed_case,
        'reverse': reverse_encode,
        'null_byte': null_byte_injection,
        'sql_comment': comment_obfuscation_sql,
        'sql_space_comment': space_to_comment_sql,
        'space_to_plus': space_to_plus,
        'space_to_tab': space_to_tab,
        'slash_obfuscate': slash_obfuscation,
        'slash_double': double_slash_obfuscation,
        'backslash_forward': backslash_to_forward,
        'js_charcode': char_code_obfuscation_js,
        'js_unicode': unicode_escape_js,
    }
    
    func = encoding_functions.get(encoding_name)
    if func:
        try:
            encoded = func(payload)
            return encoded, True, None
        except Exception as e:
            return payload, False, str(e)
    else:
        return payload, False, f"Unknown encoding: {encoding_name}"


def apply_multiple_encodings(payload, encoding_list):
    """
    Apply multiple encodings in sequence.
    Returns tuple: (final_encoded, success, errors)
    """
    result = payload
    errors = []
    
    for encoding in encoding_list:
        result, success, error = apply_encoding(result, encoding)
        if not success:
            errors.append(f"{encoding}: {error}")
    
    return result, len(errors) == 0, errors


def get_available_encodings():
    """
    Get list of all available encoding techniques with descriptions.
    """
    return {
        'url': 'URL Encoding',
        'url_double': 'Double URL Encoding',
        'base64': 'Base64 Encoding',
        'hex': 'Hexadecimal Encoding',
        'hex_prefix': 'Hex with 0x Prefix',
        'unicode': 'Unicode Escape',
        'html_entity': 'HTML Entity Encoding',
        'html_numeric': 'HTML Numeric Entity',
        'html_hex': 'HTML Hex Entity',
        'octal': 'Octal Encoding',
        'rot13': 'ROT13 Encoding',
        'mixed_case': 'Mixed Case',
        'reverse': 'Reverse String',
        'null_byte': 'Null Byte Injection',
        'sql_comment': 'SQL Comment Obfuscation',
        'sql_space_comment': 'SQL Space to Comment',
        'space_to_plus': 'Space to Plus Sign',
        'space_to_tab': 'Space to Tab',
        'slash_obfuscate': 'Slash Obfuscation',
        'slash_double': 'Double Slash Obfuscation',
        'backslash_forward': 'Backslash to Forward',
        'js_charcode': 'JavaScript CharCode',
        'js_unicode': 'JavaScript Unicode Escape',
    }
