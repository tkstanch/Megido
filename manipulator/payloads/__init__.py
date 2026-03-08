from .xss_payloads import XSS_PAYLOADS
from .sqli_payloads import SQLI_PAYLOADS
from .lfi_payloads import LFI_PAYLOADS
from .rfi_payloads import RFI_PAYLOADS
from .rce_payloads import RCE_PAYLOADS
from .csrf_payloads import CSRF_PAYLOADS
from .xxe_payloads import XXE_PAYLOADS
from .ssrf_payloads import SSRF_PAYLOADS
from .path_traversal_payloads import PATH_TRAVERSAL_PAYLOADS
from .command_injection_payloads import COMMAND_INJECTION_PAYLOADS

PAYLOADS = {
    'XSS': XSS_PAYLOADS,
    'SQLi': SQLI_PAYLOADS,
    'LFI': LFI_PAYLOADS,
    'RFI': RFI_PAYLOADS,
    'RCE': RCE_PAYLOADS,
    'CSRF': CSRF_PAYLOADS,
    'XXE': XXE_PAYLOADS,
    'SSRF': SSRF_PAYLOADS,
    'Path Traversal': PATH_TRAVERSAL_PAYLOADS,
    'Command Injection': COMMAND_INJECTION_PAYLOADS,
}
